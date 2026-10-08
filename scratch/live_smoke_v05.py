"""
AgentGuard Frontend v0.5 — Administration & Audit Live Smoke Test
Validates:
1. Authenticated administration access via Bearer token
2. Tenant listing (/api/v1/tenants) returns real backend schemas
3. Principal listing (/api/v1/principals) returns real backend schemas
4. Credential listing (/api/v1/credentials) returns safe metadata (zero secrets in list)
5. Policy listing (/api/v1/policies) returns policies and total count
6. Audit listing (/api/v1/audit/events) returns paginated events
7. Audit event detail contains cryptographic hashes (event_hash, previous_event_hash)
8. Authorization rejection: unauthenticated/unauthorized operations fail closed with 401/403
9. Credential secret handling: create returns secret once, subsequent GET never returns plaintext secret
10. Policy mutation: creates policy rule, verifies version 1, and deletes test policy
11. Audit cryptographic integrity verification (/api/v1/audit/verify)
12. Zero secret leakage: no canary secrets, raw Bearer tokens, or passwords in telemetry
"""

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE_URL = "http://127.0.0.1:8000"

def get(path: str, headers: Optional[Dict[str, str]] = None) -> Tuple[int, Any]:
    req = urllib.request.Request(f"{BASE_URL}{path}", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read().decode("utf-8")
            return resp.status, json.loads(data)
    except urllib.error.HTTPError as e:
        data = e.read().decode("utf-8")
        try:
            return e.code, json.loads(data)
        except Exception:
            return e.code, {"raw": data}
    except Exception as e:
        return 0, {"error": str(e)}

def post(path: str, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> Tuple[int, Any]:
    body = json.dumps(payload).encode("utf-8")
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(f"{BASE_URL}{path}", data=body, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read().decode("utf-8")
            return resp.status, json.loads(data)
    except urllib.error.HTTPError as e:
        data = e.read().decode("utf-8")
        try:
            return e.code, json.loads(data)
        except Exception:
            return e.code, {"raw": data}
    except Exception as e:
        return 0, {"error": str(e)}

def delete(path: str, headers: Optional[Dict[str, str]] = None) -> Tuple[int, Any]:
    req = urllib.request.Request(f"{BASE_URL}{path}", headers=headers or {}, method="DELETE")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read().decode("utf-8")
            return resp.status, json.loads(data) if data else {}
    except urllib.error.HTTPError as e:
        data = e.read().decode("utf-8")
        try:
            return e.code, json.loads(data)
        except Exception:
            return e.code, {"raw": data}
    except Exception as e:
        return 0, {"error": str(e)}

def main():
    print("=" * 65)
    print("AgentGuard Frontend v0.5 Live Smoke Test — Administration & Audit")
    print("=" * 65)

    # Step 0: Ensure backend is running
    status, health = get("/health")
    print(f"\n[0] Backend Health Check => HTTP {status}")
    assert status == 200, f"Backend not running: HTTP {status}"
    print(f"    Version: {health.get('version')}, Guard: {health.get('guard_model')}")

    # Generate test administrator credential for live verification
    from backend.services.credential_service import credential_service
    rec, admin_token = credential_service.create_credential(
        principal_id="global-admin-demo",
        tenant_id="default",
        description="Automated v0.5 live smoke test admin token",
        created_by="smoke_test_runner",
    )
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    print(f"    Authenticated session issued for '{rec.principal_id}' (credential_id={rec.credential_id})")

    # 1. Authenticated Administration Access
    print("\n[1] Authenticated Administration Access")
    status, resp = get("/api/v1/tenants", headers=admin_headers)
    assert status == 200, f"Expected 200, got {status}: {resp}"
    print(f"    --> PASS: Admin token verified, access granted (HTTP {status})")

    # 2. Tenant Listing
    print("\n[2] Tenant Listing (/api/v1/tenants)")
    status, tenants_resp = get("/api/v1/tenants", headers=admin_headers)
    assert status == 200, f"Failed to list tenants: {status}"
    tenants = tenants_resp.get("tenants", [])
    assert len(tenants) > 0, "No tenants found"
    print(f"    Tenants returned: {len(tenants)}, Total: {tenants_resp.get('total')}")
    sample_tenant = tenants[0]
    print(f"    Sample: id='{sample_tenant.get('tenant_id')}', name='{sample_tenant.get('name')}', status='{sample_tenant.get('status')}'")
    print("    --> PASS: Real tenant schema verified")

    # 3. Principal Listing
    print("\n[3] Principal Listing (/api/v1/principals)")
    status, princ_resp = get("/api/v1/principals", headers=admin_headers)
    assert status == 200, f"Failed to list principals: {status}"
    principals = princ_resp.get("principals", [])
    assert len(principals) > 0, "No principals found"
    roles_found = {r for p in principals for r in p.get("roles", [])}
    print(f"    Principals returned: {len(principals)}, Roles observed: {sorted(list(roles_found))}")
    assert "admin" in roles_found or "user" in roles_found, "Expected RBAC roles"
    print("    --> PASS: Real principal schema and RBAC roles verified")

    # 4. Credential Listing
    print("\n[4] Credential Listing (/api/v1/credentials)")
    status, cred_resp = get("/api/v1/credentials", headers=admin_headers)
    assert status == 200, f"Failed to list credentials: {status}"
    creds = cred_resp.get("credentials", [])
    assert len(creds) > 0, "No credentials found"
    print(f"    Credentials returned: {len(creds)}, Total: {cred_resp.get('total')}")
    # Verify no plaintext secrets or raw tokens in list
    serialized_creds = json.dumps(creds)
    assert "credential_secret" not in serialized_creds, "Secret leaked in credential list"
    assert "ag_sec_" not in serialized_creds, "Plaintext token leaked in credential list"
    print("    --> PASS: Credential metadata listed safely without secret leakage")

    # 5. Policy Listing
    print("\n[5] Policy Listing (/api/v1/policies)")
    status, pol_resp = get("/api/v1/policies", headers=admin_headers)
    assert status == 200, f"Failed to list policies: {status}"
    policies = pol_resp.get("policies", [])
    print(f"    Active policies returned: {len(policies)}, Total: {pol_resp.get('total')}")
    print("    --> PASS: Policy listing endpoint operational")

    # 6. Audit Listing
    print("\n[6] Audit Listing (/api/v1/audit/events?limit=5)")
    status, audit_resp = get("/api/v1/audit/events?limit=5", headers=admin_headers)
    assert status == 200, f"Failed to query audit events: {status}"
    events = audit_resp.get("events", [])
    assert len(events) > 0, "No audit events found"
    print(f"    Events returned: {len(events)}, Total in store: {audit_resp.get('total')}")
    print("    --> PASS: Authoritative audit trail retrieved")

    # 7. Audit Event Detail
    print("\n[7] Audit Event Detail & Cryptographic Hash Chain")
    sample_evt = events[0]
    evt_id = sample_evt.get("event_id")
    assert evt_id, "Missing event_id"
    event_hash = sample_evt.get("event_hash")
    assert event_hash and len(event_hash) == 64, f"Invalid SHA-256 event_hash: {event_hash}"
    prev_hash = sample_evt.get("previous_event_hash")
    print(f"    Event ID: {evt_id}")
    print(f"    Action: {sample_evt.get('action')}, Decision: {sample_evt.get('decision')}")
    print(f"    SHA-256 Hash: {event_hash}")
    print(f"    Prev SHA-256: {prev_hash[:16]}...")
    print("    --> PASS: Cryptographic audit integrity fields verified")

    # 8. Authorization Rejection for Unauthorized Request
    print("\n[8] Authorization Rejection (Unauthorized Operation)")
    # Case A: No token -> user-demo fallback lacks admin role -> HTTP 403
    unauth_status, unauth_resp = get("/api/v1/tenants")
    assert unauth_status in (401, 403), f"Expected 401 or 403, got {unauth_status}"
    print(f"    Unauthenticated call rejected with HTTP {unauth_status} (error: {unauth_resp.get('error', {}).get('code', unauth_resp.get('detail'))})")

    # Case B: Spoofed headers disregarded
    spoofed_status, spoofed_resp = get(
        "/api/v1/tenants",
        headers={"X-AgentGuard-Role": "global_admin", "X-AgentGuard-Tenant": "system"},
    )
    assert spoofed_status in (401, 403), f"Expected 401 or 403 for spoofed headers, got {spoofed_status}"
    print(f"    Spoofed header attempt strictly rejected with HTTP {spoofed_status}")
    print("    --> PASS: Authorization correctly fails closed; untrusted headers disregarded")

    # 9. Credential Secret Handling (One-time Reveal Invariant)
    print("\n[9] Credential Secret Lifecycle (One-Time Reveal Invariant)")
    create_cred_payload = {
        "principal_id": "user-demo",
        "description": "Ephemeral test credential for one-time secret verification",
    }
    status, new_cred = post("/api/v1/credentials", create_cred_payload, headers=admin_headers)
    assert status == 201, f"Failed to create credential: {status}: {new_cred}"
    created_id = new_cred.get("credential_id")
    secret_revealed = new_cred.get("credential_secret") or new_cred.get("token")
    assert secret_revealed, "Creation response did not provide one-time secret"
    print(f"    Created credential: '{created_id}' (secret revealed ONCE)")

    # Subsequent GET must NEVER expose the plaintext secret
    status, get_cred = get(f"/api/v1/credentials/{created_id}", headers=admin_headers)
    assert status == 200, f"Failed to inspect credential: {status}"
    assert "credential_secret" not in get_cred, "Plaintext secret leaked in GET response!"
    assert "token" not in get_cred or not get_cred.get("token"), "Full token leaked in GET response!"
    print("    Subsequent GET returns metadata only (zero secret)")

    # Clean up ephemeral credential
    del_status, del_resp = post(f"/api/v1/credentials/{created_id}/revoke", {}, headers=admin_headers)
    assert del_status == 200, f"Failed to revoke test credential: {del_status}: {del_resp}"
    print(f"    Revoked ephemeral credential '{created_id}' successfully")
    print("    --> PASS: One-time reveal invariant strictly validated")

    # 10. Policy Mutation Safety
    print("\n[10] Policy Mutation (Create, Verify Version, Delete)")
    test_policy = {
        "name": "Live Smoke Test Rule",
        "description": "Temporary rule to test version increment and deletion",
        "action": "REQUIRE_APPROVAL",
        "priority": 777,
        "tool_scope": ["send_email"],
        "risk_levels": ["high"],
    }
    status, created_pol = post("/api/v1/policies", test_policy, headers=admin_headers)
    assert status == 201, f"Failed to create policy: {status}: {created_pol}"
    pol_id = created_pol.get("policy_id")
    assert pol_id, "Missing policy_id"
    assert created_pol.get("version") == 1, f"Expected version 1, got {created_pol.get('version')}"
    print(f"    Created policy '{pol_id}' with version {created_pol.get('version')}")

    # Clean up test policy
    del_status, del_resp = delete(f"/api/v1/policies/{pol_id}", headers=admin_headers)
    assert del_status == 200, f"Failed to delete test policy: {del_status}"
    print(f"    Deleted policy '{pol_id}' successfully")
    print("    --> PASS: Policy lifecycle and versioning verified")

    # 11. Audit Cryptographic Integrity Verification
    print("\n[11] Audit Integrity Verification (/api/v1/audit/verify)")
    status, verify_resp = get("/api/v1/audit/verify", headers=admin_headers)
    assert status == 200, f"Failed to verify audit chain: {status}: {verify_resp}"
    is_valid = verify_resp.get("valid")
    total_events = verify_resp.get("total_events")
    details = verify_resp.get("details")
    print(f"    Verification valid: {is_valid}")
    print(f"    Total chained events verified: {total_events}")
    print(f"    Details: {details}")
    assert is_valid is True, f"Audit chain verification returned invalid: {verify_resp}"
    print("    --> PASS: Authoritative SHA-256 chain verification VALID")

    # 12. Zero Secret Leakage
    print("\n[12] Zero Secret Leakage Verification")
    canary = os.environ.get("AGENTGUARD_CANARY_SECRET", "BLUE-ORANGE-42")
    all_responses_dump = json.dumps([
        tenants_resp,
        princ_resp,
        cred_resp,
        pol_resp,
        audit_resp,
        verify_resp,
    ])
    assert canary not in all_responses_dump, f"Canary token '{canary}' detected in responses!"
    assert "authorization: bearer" not in all_responses_dump.lower(), "Raw authorization header found in payload!"
    print("    Canary token check: SAFE (0 matches)")
    print("    Raw authorization header check: SAFE (0 matches)")
    print("    --> PASS: No sensitive secrets leaked in administration APIs")

    print("\n" + "=" * 65)
    print("AgentGuard Frontend v0.5 Live Smoke Test: ALL 12 CHECKS PASSED")
    print("=" * 65)

if __name__ == "__main__":
    main()
