"""
Mock Tool Executor Layer
Provides controlled, deterministic mock implementations for Backend v0.5.
Guarantees that:
1. NO REAL external systems are ever called (no shell, email, filesystem, database, or network actions).
2. The executor refuses to run unless the tool call was explicitly authorized by the Tool Guard.
3. Every mock action produces predictable, deterministic results for benchmarking and security testing.
"""

import logging
from typing import Any, Dict

from backend.services.metrics_service import metrics

logger = logging.getLogger("agentguard.tool_executor")


class UnauthorizedToolExecutionError(PermissionError):
    """
    Raised when an unauthorized or blocked tool execution attempt reaches the executor.
    """
    pass


def execute_mock_tool(tool_name: str, arguments: Dict[str, Any], is_authorized: bool = False) -> str:
    """
    Executes a registered mock tool if and only if it has passed AgentGuard authorization.

    Args:
        tool_name: Canonical name of the tool.
        arguments: Validated key-value arguments.
        is_authorized: Boolean flag set strictly by the Tool Guard service.

    Returns:
        Deterministic mock string result.

    Raises:
        UnauthorizedToolExecutionError: If is_authorized is False.
        ValueError: If tool_name is unrecognized.
    """
    # Strict Gateway Invariant: Target LLM can never directly trigger mock execution
    if not is_authorized:
        metrics.record_unauthorized_tool_execution()
        logger.error(
            "CRITICAL SECURITY VIOLATION: Unauthorized tool execution blocked! tool=%s",
            tool_name,
        )
        raise UnauthorizedToolExecutionError(
            f"Execution rejected: Tool '{tool_name}' has not received AgentGuard authorization."
        )

    logger.info("Executing mock tool: name=%s", tool_name)

    if tool_name == "get_weather":
        city = arguments.get("city", "Unknown City")
        return f"Weather report for {city}: 27°C, Partly Cloudy, Wind: 12 km/h NE, Humidity: 62%."

    elif tool_name == "search_documents":
        query = arguments.get("query", "")
        return (
            f"Documentation Search Results for '{query}':\n"
            f"1. [DOC-101] AgentGuard Architecture & Security Boundary Specification\n"
            f"2. [DOC-102] Tool Authorization Gate & Policy Guidelines\n"
            f"3. [DOC-103] Output Leak Sanitization Protocol"
        )

    elif tool_name == "send_email":
        recipient = arguments.get("recipient", "")
        subject = arguments.get("subject", "")
        return (
            f"MOCK_SIMULATION: Email queued to {recipient} with subject '{subject}'. "
            f"No real email was sent (Backend v0.5 mock mode active)."
        )

    elif tool_name == "delete_record":
        record_id = arguments.get("record_id", "")
        return (
            f"MOCK_SIMULATION: Record '{record_id}' marked for deletion in mock ledger. "
            f"No real deletion was performed (Backend v0.5 mock mode active)."
        )

    else:
        metrics.record_unauthorized_tool_execution()
        raise ValueError(f"Unrecognized mock tool '{tool_name}'. Cannot execute unregistered action.")
