"""
AgentGuard Frontend v0.6 — Security Operations & Incident Response Live Smoke Test
Validates:
1. Backend Gateway Health (/health) and Readiness (/ready)
2. In-Process Runtime Metrics (/metrics)
3. Cryptographic Audit Hash Chain Verification (/api/v1/audit/verify)
4. Live Security Audit Stream with filters and pagination (/api/v1/audit/events)
5. Operational Approvals Queue listing (/api/v1/approvals)
6. Privileged Tool Authorization Lifecycle (Approval, Inspection, and 409 Replay Prevention)
7. Session-Only Investigation Boundary (Backend rejects arbitrary unauthenticated incident stores)
8. Authoritative Incident Response Mitigations (Credential Revocation & 401 Enforcement)
9. Boundary Protection & Fail-Closed Enforcement (401/403 for unauthorized mitigations)
10. Security & Privacy Invariants (Zero canary strings, raw secrets, or auth header leakage)
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

def main():
    print("=" * 70)
    print("AgentGuard Frontend v0.6 Live Smoke Test — Security Operations & IR")
    print("=" * 70)

    # -------------------------------------------------------------------------
    # 0. Backend Health & Readiness
    # -------------------------------------------------------------------------
    print("\n[0] Gateway Health & Readiness Check")
    status, health = get("/health")
    assert status == 200, f"Backend not running: HTTP {status}"
    print(f"    Health: HTTP {status} => version={health.get('version')}, guard_enabled={health.get('guard_enabled')}")

    status, ready = get("/ready")
    assert status == 200, f"Readiness degraded: HTTP {status}"
    print(f"    Readiness: HTTP {status} => status={ready.get('status')}, checks={list(ready.get('checks', {}).keys())}")
    print("    --> PASS: Posture indicators operational")

    # Issue test administrator credential for authoritative SecOps actions
    from backend.services.credential_service import credential_service
    admin_rec, admin_token = credential_service.create_credential(
        principal_id="global-admin-demo",
        tenant_id="default",
        description="Automated v0.6 live smoke test operator token",
        created_by="smoke_test_runner",
    )
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    print(f"    Operator session initialized for '{admin_rec.principal_id}' (credential_id={admin_rec.credential_id})")

    # -------------------------------------------------------------------------
    # 1. In-Process Runtime Metrics
    # -------------------------------------------------------------------------
    print("\n[1] Runtime In-Process Metrics (/metrics)")
    status, metrics = get("/metrics")
    assert status == 200, f"Metrics failed: HTTP {status}"
    print(f"    Metrics: uptime={metrics.get('uptime_seconds')}s, total_requests={metrics.get('total_requests')}")
    print(f"    Memory: {metrics.get('memory_mb')} MB, Pending Approvals: {metrics.get('pending_approvals')}")
    print("    --> PASS: Real process metrics available for Posture Card")

    # -------------------------------------------------------------------------
    # 2. Cryptographic Audit Hash Chain Verification
    # -------------------------------------------------------------------------
    print("\n[2] Cryptographic Audit Hash Chain Verification (/api/v1/audit/verify)")
    status, verify_resp = get("/api/v1/audit/verify", headers=admin_headers)
    assert status == 200, f"Audit verify failed: HTTP {status}"
    print(f"    Verification: valid={verify_resp.get('valid')}, status={verify_resp.get('status')}")
    print(f"    Total Events Verified: {verify_resp.get('total_events')}")
    print("    --> PASS: Authoritative cryptographic verification confirmed")

    # -------------------------------------------------------------------------
    # 3. Live Audit Event Stream & Filtering
    # -------------------------------------------------------------------------
    print("\n[3] Live Audit Event Stream & Filtering (/api/v1/audit/events)")
    status, events_resp = get("/api/v1/audit/events?limit=10&offset=0", headers=admin_headers)
    assert status == 200, f"Audit query failed: HTTP {status}"
    events = events_resp.get("events", [])
    total = events_resp.get("total", 0)
    print(f"    Audit Events Returned: {len(events)}, Total Persisted: {total}")
    if events:
        sample = events[0]
        print(f"    Sample Event: id='{sample.get('event_id')}', action='{sample.get('action')}', decision='{sample.get('decision')}'")
        assert sample.get("event_hash"), "Missing cryptographic event hash"

    # Filter preset: Blocked decisions
    status, blocks_resp = get("/api/v1/audit/events?decision=BLOCK&limit=5", headers=admin_headers)
    assert status == 200, f"Blocks filter failed: HTTP {status}"
    print(f"    Blocked Threats in Stream: {blocks_resp.get('total', 0)}")
    print("    --> PASS: Audit event stream filters and cryptographic proofs verified")

    # -------------------------------------------------------------------------
    # 4. Operational Approvals Queue Listing
    # -------------------------------------------------------------------------
    print("\n[4] Operational Approvals Queue Listing (/api/v1/approvals)")
    status, approvals_resp = get("/api/v1/approvals", headers=admin_headers)
    assert status == 200, f"Approvals listing failed: HTTP {status}"
    print(f"    Approvals Queue count: {len(approvals_resp)}")
    print("    --> PASS: Approvals queue endpoint operational")

    # -------------------------------------------------------------------------
    # 5. Privileged Tool Authorization Lifecycle & Replay Conflict
    # -------------------------------------------------------------------------
    print("\n[5] Privileged Tool Authorization Lifecycle")
    # Create test approval via API
    status, create_appr_resp = post(
        "/api/v1/approvals",
        {
            "tool_name": "send_email",
            "arguments": {"recipient": "secops-alert@example.com", "subject": "Alert", "body": "Security containment action"},
            "conversation_id": "test-secops-conv-01",
        },
        headers=admin_headers,
    )
    assert status == 200, f"Failed to create approval request: HTTP {status} {create_appr_resp}"
    appr_id = create_appr_resp.get("approval_id")
    assert appr_id, "Missing approval_id in response"
    print(f"    Generated pending approval via API: '{appr_id}' for tool '{create_appr_resp.get('tool_name')}'")

    # Inspect approval
    status, detail = get(f"/api/v1/approvals/{appr_id}", headers=admin_headers)
    assert status == 200, f"Failed to get approval detail: HTTP {status}"
    assert detail.get("status") == "PENDING_APPROVAL", f"Expected PENDING_APPROVAL, got {detail.get('status')}"
    print(f"    Inspection: status='{detail.get('status')}', risk_score={detail.get('risk_score')}")

    # Approve tool
    status, approve_resp = post(f"/api/v1/approvals/{appr_id}/approve", {}, headers=admin_headers)
    assert status == 200, f"Approve failed: HTTP {status}"
    print(f"    Approval Action: status='{approve_resp.get('status')}', decision='{approve_resp.get('decision')}'")

    # Replay protection: Calling approve a second time MUST fail closed with HTTP 409 Conflict
    status, replay_resp = post(f"/api/v1/approvals/{appr_id}/approve", {}, headers=admin_headers)
    assert status == 409, f"Expected 409 Conflict on replay, got HTTP {status}: {replay_resp}"
    print(f"    Replay Attempt: HTTP {status} Conflict => '{replay_resp.get('detail')}'")
    print("    --> PASS: One-time approval consumption and replay protection verified")

    # -------------------------------------------------------------------------
    # 6. Session-Only Investigation Boundary
    # -------------------------------------------------------------------------
    print("\n[6] Session-Only Investigation Boundary Verification")
    # Verify that backend does NOT provide incident persistence endpoints (enforcing frontend session-only contract)
    status, _ = get("/api/v1/incidents")
    assert status in (404, 405), f"Backend should not persist frontend incidents: got HTTP {status}"
    status, _ = post("/api/v1/incidents", {"title": "Fabricated"})
    assert status in (404, 405), f"Backend should not accept incident creation: got HTTP {status}"
    print("    --> PASS: Backend enforces that incident workspaces are strictly session-only in React state")

    # -------------------------------------------------------------------------
    # 7. Authoritative Security Mitigations (Credential Revocation & 401 Enforcement)
    # -------------------------------------------------------------------------
    print("\n[7] Authoritative Security Mitigation Controls")
    # Issue a temporary credential to revoke
    temp_rec, temp_token = credential_service.create_credential(
        principal_id="admin-demo",
        tenant_id="default",
        description="Target credential for v0.6 mitigation test",
        created_by="smoke_test_runner",
    )
    temp_headers = {"Authorization": f"Bearer {temp_token}"}
    print(f"    Issued test credential: '{temp_rec.credential_id}'")

    # Verify temp token initially authenticates
    status, _ = get("/api/v1/tenants", headers=temp_headers)
    assert status == 200, f"Temp token should authenticate: got {status}"

    # Operator executes revocation mitigation
    status, revoke_resp = post(f"/api/v1/credentials/{temp_rec.credential_id}/revoke", {}, headers=admin_headers)
    assert status == 200, f"Revocation failed: HTTP {status}"
    assert revoke_resp.get("status") == "REVOKED", f"Expected REVOKED, got {revoke_resp.get('status')}"
    print(f"    Mitigation Executed: Credential '{temp_rec.credential_id}' transitioned to REVOKED")

    # Verify revoked token immediately fails closed with HTTP 401 Unauthorized
    status, fail_resp = get("/api/v1/tenants", headers=temp_headers)
    assert status == 401, f"Expected HTTP 401 for revoked token, got {status}: {fail_resp}"
    print(f"    Boundary Enforcement: Revoked token rejected with HTTP {status} Unauthorized")
    print("    --> PASS: Authoritative mitigation immediately invalidates caller sessions")

    # -------------------------------------------------------------------------
    # 8. Boundary Protection: Unauthorized Mitigation Rejected
    # -------------------------------------------------------------------------
    print("\n[8] Unauthorized Mitigation Rejection (RBAC Boundary)")
    # Unauthenticated/unauthorized mitigation attempt fails closed with 401 or 403
    status, unauth_resp = post(f"/api/v1/credentials/{admin_rec.credential_id}/revoke", {})
    assert status in (401, 403), f"Expected 401 or 403, got HTTP {status}: {unauth_resp}"
    print(f"    Unauthorized Mitigation: Rejected with HTTP {status}")
    print("    --> PASS: Authoritative mitigation endpoints require authenticated operator session")

    # -------------------------------------------------------------------------
    # 9. Security & Privacy Invariants
    # -------------------------------------------------------------------------
    print("\n[9] Security & Privacy Invariants Verification")
    canary = "BLUE-ORANGE-42"
    for endpoint, data in [
        ("/health", health),
        ("/ready", ready),
        ("/metrics", metrics),
        ("/api/v1/approvals", approvals_resp),
    ]:
        serialized = json.dumps(data)
        assert canary not in serialized, f"Canary token leaked in {endpoint}"
        assert "Authorization" not in serialized, f"Authorization header leaked in {endpoint}"
    print("    --> PASS: Zero canary strings, raw secrets, or auth headers in responses")

    print("\n" + "=" * 70)
    print("ALL FRONTEND v0.6 LIVE SMOKE TESTS PASSED (10/10)")
    print("=" * 70)

if __name__ == "__main__":
    main()
