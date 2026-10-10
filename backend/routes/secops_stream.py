"""
SecOps Real-Time Event Streaming & Dashboard API Routes
Provides Server-Sent Events (SSE) streaming for the live SOC monitor,
posture summary telemetry, and simulation of high-risk tool approval workflows.
"""

import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from backend.config import VERSION
from backend.services.approval_service import create_approval_request
from backend.services.approval_store import approval_store
from backend.services.audit_service import audit_service
from backend.services.event_stream_service import event_broadcaster
from backend.services.identity_service import resolve_principal
from backend.services.metrics_service import metrics

logger = logging.getLogger("agentguard.secops_stream")

router = APIRouter(tags=["Security Operations (SOC)"])


class SecOpsOverviewResponse(BaseModel):
    """
    Live aggregated security posture summary for the SOC Dashboard.
    """
    status: str
    version: str
    uptime_seconds: float
    total_requests: int
    decisions: Dict[str, int]
    pending_approvals_count: int
    latest_event_hash: str
    audit_chain_intact: bool
    recent_events_count: int


class SimulateApprovalRequest(BaseModel):
    """
    Payload for generating a test high-risk action in the approval queue.
    """
    tool_name: Optional[str] = Field("send_email", description="Name of high-risk tool to simulate.")
    tool_arguments: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: {
            "recipient": "finance-dept@external.com",
            "subject": "Wire Transfer Authorization Request #8492",
            "body": "Authorize $15,000 transfer to vendor account ending in 4109.",
        }
    )
    risk_level: Optional[str] = Field("high", description="Risk level (high or critical).")


@router.get(
    "/api/v1/secops/overview",
    response_model=SecOpsOverviewResponse,
    status_code=status.HTTP_200_OK,
    summary="Get aggregated live SOC posture summary",
)
def get_secops_overview() -> SecOpsOverviewResponse:
    """
    Returns real-time telemetry for the SOC overview dashboard cards.
    """
    m = metrics.get_metrics()
    pending = [a for a in approval_store.list_approvals() if getattr(a, "status", None) == "PENDING_APPROVAL"]

    latest_hash = audit_service.get_latest_event_hash()
    verify_result = audit_service.verify_audit_chain()

    return SecOpsOverviewResponse(
        status="operational",
        version=VERSION,
        uptime_seconds=m.get("uptime_seconds", 0.0),
        total_requests=m.get("total_requests", 0),
        decisions=m.get("decisions", {}),
        pending_approvals_count=len(pending),
        latest_event_hash=latest_hash[:16] + "..." if latest_hash else "genesis",
        audit_chain_intact=verify_result.get("valid", True),
        recent_events_count=len(event_broadcaster.get_recent_events()),
    )


@router.get(
    "/api/v1/secops/events/stream",
    summary="Live SSE Security Event Stream (Server-Sent Events)",
    description="Streams real-time security events, attack interceptions, and approval alerts to the SOC dashboard.",
)
async def stream_security_events(request: Request):
    """
    Server-Sent Events route for the live incident monitor.
    """
    async def sse_generator():
        # First send recent events to populate the stream immediately on connection
        for event in event_broadcaster.get_recent_events(limit=10):
            yield f"data: {json.dumps(event)}\n\n"

        # Subscribe to live incoming events
        async for event in event_broadcaster.subscribe():
            if await request.is_disconnected():
                break
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post(
    "/api/v1/approvals/simulate",
    status_code=status.HTTP_201_CREATED,
    summary="Simulate high-risk tool proposal for 1-click HITL approval testing",
)
def simulate_approval_endpoint(
    request: Request,
    payload: Optional[SimulateApprovalRequest] = None,
) -> Any:
    """
    Generates a realistic high-risk approval request with HMAC argument binding
    and registers it in the pending queue for live operator testing.
    """
    if payload is None:
        payload = SimulateApprovalRequest()

    principal = resolve_principal(request=request)
    request_id = getattr(request.state, "request_id", None) or f"sim-{uuid.uuid4().hex[:8]}"

    tool_name = payload.tool_name or "send_email"
    if tool_name not in ("send_email", "delete_record"):
        tool_name = "send_email"

    if tool_name == "delete_record":
        tool_arguments = (
            payload.tool_arguments
            if (payload.tool_arguments and "record_id" in payload.tool_arguments)
            else {"record_id": "rec_finance_9824"}
        )
    else:
        tool_arguments = (
            payload.tool_arguments
            if (
                payload.tool_arguments
                and "recipient" in payload.tool_arguments
                and "subject" in payload.tool_arguments
                and "body" in payload.tool_arguments
            )
            else {
                "recipient": "finance-dept@external.com",
                "subject": "Wire Transfer Authorization Request #8492",
                "body": "Authorize $15,000 transfer to vendor account ending in 4109.",
            }
        )

    # Create approval request via canonical approval service
    _decision, record, reason = create_approval_request(
        tool_name=tool_name,
        arguments=tool_arguments,
        request_id=request_id,
        principal=principal,
    )

    if record is None:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": {"code": "SIMULATION_FAILED", "message": f"Could not simulate approval: {reason}"}},
        )

    # Broadcast event to live SOC incident feed
    event_data = {
        "event_id": f"evt_sim_{uuid.uuid4().hex[:8]}",
        "action": "approval_required",
        "decision": "REQUIRE_APPROVAL",
        "tool_name": tool_name,
        "approval_id": record.approval_id,
        "risk_level": record.risk_level.value if hasattr(record.risk_level, "value") else str(record.risk_level),
        "timestamp": time.time(),
        "summary": f"High-risk action '{tool_name}' proposed. Awaiting Human-in-the-Loop authorization.",
    }
    event_broadcaster.broadcast(event_data)

    return {
        "status": "created",
        "approval_id": record.approval_id,
        "tool_name": record.tool_name,
        "risk_level": record.risk_level.value if hasattr(record.risk_level, "value") else str(record.risk_level),
        "expires_in_seconds": int(record.expires_at - time.time()),
        "message": f"Approval request '{record.approval_id}' generated and waiting in queue.",
    }
