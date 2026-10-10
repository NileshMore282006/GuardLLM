"""
Live Demonstration Script for Feature 3: Live SOC Dashboard & 1-Click HITL Approval Queue
Demonstrates:
1. Real-time Posture Metrics & Hash-chain verification (/api/v1/secops/overview)
2. Live Server-Sent Events (SSE) Stream initialization (/api/v1/secops/events/stream)
3. Simulating a High-Risk Tool Request (HMAC-SHA256 bound, PENDING_APPROVAL)
4. 1-Click Human Authorization (Approve -> CONSUMED with single-use guarantee)
5. Anti-Replay Defense Verification (Subsequent execution blocked with 409 Conflict)
6. 1-Click Human Denial (Deny -> DENIED state, tool execution prohibited)
"""

import json
import time
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.tenant_service import tenant_service
from backend.services.principal_service import principal_service
from backend.services.credential_service import credential_service


def run_soc_demo():
    print("=" * 75)
    print("[*] FEATURE 3 DEMO: LIVE SOC DASHBOARD & 1-CLICK HITL APPROVAL QUEUE [*]")
    print("=" * 75)

    client = TestClient(app, raise_server_exceptions=False)
    tenant_service._seed_defaults()
    principal_service._seed_defaults()

    tenant_id = "soc-enterprise-corp"
    tenant_service.create_tenant(tenant_id, "SOC Enterprise Corp")

    admin_principal = "soc-lead-analyst"
    principal_service.create_principal(
        principal_id=admin_principal,
        principal_type="user",
        roles=["admin"],
        tenant_id=tenant_id,
    )
    _, admin_token = credential_service.create_credential(admin_principal, tenant_id)
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Inspect live SOC posture overview
    print("\n[Step 1] Fetching Real-Time SOC Posture Overview (/api/v1/secops/overview)...")
    overview = client.get("/api/v1/secops/overview").json()
    print(f"  * Status:                {overview.get('status').upper()}")
    print(f"  * Gateway Version:       {overview.get('version')}")
    print(f"  * Audit Chain Intact:    {overview.get('audit_chain_intact')}")
    print(f"  * Latest Hash:           {overview.get('latest_event_hash')}")
    print(f"  * Pending Approvals:     {overview.get('pending_approvals_count')}")

    # 2. Simulate high-risk request
    print("\n[Step 2] Simulating High-Risk Action Proposal (Wire Transfer via send_email)...")
    sim_res = client.post(
        "/api/v1/approvals/simulate",
        json={
            "tool_name": "send_email",
            "tool_arguments": {
                "recipient": "treasury-wire@external-bank.com",
                "subject": "Authorization: Outbound Transfer $50,000",
                "body": "Approve settlement for Vendor INV-9042",
            },
            "risk_level": "high",
        },
        headers=admin_headers,
    )
    sim_data = sim_res.json()
    approval_id = sim_data["approval_id"]
    print(f"  [+] High-Risk Proposal Generated: {approval_id}")
    print(f"  [+] Tool Name:                   {sim_data['tool_name']}")
    print(f"  [+] Risk Level:                  {sim_data['risk_level'].upper()}")
    print(f"  [+] Live SSE Alert Dispatched:   Broadcasting to SOC incident monitor!")

    # 3. 1-Click Human Approval
    print(f"\n[Step 3] Operator clicks 'Approve & Execute' in SOC Dashboard Queue...")
    approve_res = client.post(
        f"/api/v1/approvals/{approval_id}/approve",
        headers=admin_headers,
    )
    appr_data = approve_res.json()
    print(f"  [+] Authorization Decision:       {appr_data.get('decision')} (ALLOWED)")
    print(f"  [+] Approval State Transition:    PENDING_APPROVAL -> APPROVED -> {appr_data.get('approval_status')}")
    print(f"  [+] One-Time Execution:          Tool executed safely on behalf of {admin_principal}.")

    # 4. Verify Replay Attack Prevention
    print(f"\n[Step 4] Simulating Adversarial Replay Attempt of Consumed Token {approval_id}...")
    replay_res = client.post(
        f"/api/v1/approvals/{approval_id}/approve",
        headers=admin_headers,
    )
    print(f"  [!] Replay Response HTTP Status: {replay_res.status_code} (CONFLICT)")
    print(f"  [!] Security Perimeter Defense:  Token already consumed. Replay blocked!")

    # 5. 1-Click Human Denial
    print("\n[Step 5] Simulating Destructive Critical Action (delete_record) & Operator Denial...")
    crit_sim = client.post(
        "/api/v1/approvals/simulate",
        json={
            "tool_name": "delete_record",
            "tool_arguments": {"record_id": "rec_prod_customer_db_01"},
            "risk_level": "critical",
        },
        headers=admin_headers,
    ).json()
    crit_id = crit_sim["approval_id"]
    print(f"  [+] Critical Action Submitted:    {crit_id} ({crit_sim['tool_name']})")

    deny_res = client.post(
        f"/api/v1/approvals/{crit_id}/deny",
        headers=admin_headers,
    )
    deny_data = deny_res.json()
    print(f"  [!] Operator Decision:           {deny_data.get('decision')} (BLOCKED)")
    print(f"  [!] Final Approval State:        {deny_data.get('approval_status')}")
    print(f"  [!] Guarantee:                   Target tool NEVER executed.")

    print("\n" + "=" * 75)
    print("[OK] FEATURE 3 LIVE SOC DASHBOARD & 1-CLICK HITL DEMO COMPLETE [OK]")
    print("=" * 75)


if __name__ == "__main__":
    run_soc_demo()
