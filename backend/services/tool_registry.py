"""
Tool Registry Service Layer
Manages the controlled, mock tool registry for Backend v0.5.
Maintains metadata (risk level, schemas, side effects, read-only status).
Rejects duplicate tool registrations and invalid tool metadata.
Invariant: The target LLM can only invoke explicitly registered tools subject to AgentGuard policy.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from backend.config import MAX_TOOL_NAME_LENGTH

logger = logging.getLogger("agentguard.tool_registry")

VALID_RISK_LEVELS = {"low", "medium", "high", "critical"}
TOOL_NAME_REGEX = re.compile(r"^[a-z0-9_]+$")


@dataclass(frozen=True)
class ToolDefinition:
    """
    Immutable tool definition and security metadata.
    """
    tool_name: str
    description: str
    risk_level: str
    read_only: bool
    side_effect: bool
    allowed_arguments: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self):
        # Validate tool_name
        if not isinstance(self.tool_name, str) or not self.tool_name.strip():
            raise ValueError("tool_name must be a non-empty string.")
        if len(self.tool_name) > MAX_TOOL_NAME_LENGTH:
            raise ValueError(f"tool_name exceeds maximum length of {MAX_TOOL_NAME_LENGTH}.")
        if not TOOL_NAME_REGEX.match(self.tool_name):
            raise ValueError(f"tool_name '{self.tool_name}' must be lowercase alphanumeric with underscores only.")

        # Validate description
        if not isinstance(self.description, str) or not self.description.strip():
            raise ValueError("description must be a non-empty string.")

        # Validate risk_level
        if self.risk_level.lower() not in VALID_RISK_LEVELS:
            raise ValueError(f"risk_level '{self.risk_level}' is invalid. Must be one of {VALID_RISK_LEVELS}.")

        # Validate boolean flags
        if not isinstance(self.read_only, bool):
            raise ValueError("read_only must be a boolean.")
        if not isinstance(self.side_effect, bool):
            raise ValueError("side_effect must be a boolean.")

        # Validate allowed_arguments schema
        if not isinstance(self.allowed_arguments, dict):
            raise ValueError("allowed_arguments must be a dictionary.")
        for arg_name, arg_spec in self.allowed_arguments.items():
            if not isinstance(arg_name, str) or not arg_name.strip():
                raise ValueError("Argument name must be a non-empty string.")
            if not isinstance(arg_spec, dict):
                raise ValueError(f"Argument spec for '{arg_name}' must be a dictionary.")


class ToolRegistry:
    """
    In-memory registry of authorized tools.
    """

    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._register_default_tools()

    def _register_default_tools(self):
        """
        Populates default deterministic mock tools.
        """
        # 1. get_weather (Low risk, read-only)
        self.register_tool(
            ToolDefinition(
                tool_name="get_weather",
                description="Retrieves current weather report for a specified city.",
                risk_level="low",
                read_only=True,
                side_effect=False,
                allowed_arguments={
                    "city": {
                        "type": "str",
                        "required": True,
                        "max_length": 100,
                        "description": "The name of the city to look up.",
                    }
                },
            )
        )

        # 2. search_documents (Low risk, read-only)
        self.register_tool(
            ToolDefinition(
                tool_name="search_documents",
                description="Searches internal documentation repository for relevant articles.",
                risk_level="low",
                read_only=True,
                side_effect=False,
                allowed_arguments={
                    "query": {
                        "type": "str",
                        "required": True,
                        "max_length": 500,
                        "description": "Search query terms.",
                    }
                },
            )
        )

        # 3. send_email (High risk, side effect - mock simulation only)
        self.register_tool(
            ToolDefinition(
                tool_name="send_email",
                description="Simulates sending an email notification to a recipient.",
                risk_level="high",
                read_only=False,
                side_effect=True,
                allowed_arguments={
                    "recipient": {
                        "type": "str",
                        "required": True,
                        "max_length": 200,
                        "description": "Recipient email address.",
                    },
                    "subject": {
                        "type": "str",
                        "required": True,
                        "max_length": 200,
                        "description": "Subject of the message.",
                    },
                    "body": {
                        "type": "str",
                        "required": True,
                        "max_length": 2000,
                        "description": "Body content of the email.",
                    },
                },
            )
        )

        # 4. delete_record (Critical risk, destructive side effect - mock simulation only)
        self.register_tool(
            ToolDefinition(
                tool_name="delete_record",
                description="Simulates deleting a database record by identifier.",
                risk_level="critical",
                read_only=False,
                side_effect=True,
                allowed_arguments={
                    "record_id": {
                        "type": "str",
                        "required": True,
                        "max_length": 100,
                        "description": "Primary identifier of record to delete.",
                    }
                },
            )
        )

    def register_tool(self, tool_def: ToolDefinition):
        """
        Registers a new tool. Rejects duplicate registrations or invalid metadata.
        """
        if not isinstance(tool_def, ToolDefinition):
            raise TypeError("tool_def must be an instance of ToolDefinition.")

        name = tool_def.tool_name
        if name in self._tools:
            raise ValueError(f"Tool '{name}' is already registered.")

        self._tools[name] = tool_def
        logger.info("Registered tool: name=%s risk=%s read_only=%s", name, tool_def.risk_level, tool_def.read_only)

    def get_tool(self, tool_name: str) -> Optional[ToolDefinition]:
        """
        Retrieves a registered tool by canonical name.
        Strict matching: requires lowercase alphanumeric + underscore, length <= 64.
        Returns None for unknown, ambiguous, or non-canonical tool names.
        """
        if not isinstance(tool_name, str):
            return None
        # Strict canonical validation (no Unicode homoglyphs, no uppercase, no whitespace)
        if not TOOL_NAME_REGEX.match(tool_name) or len(tool_name) > MAX_TOOL_NAME_LENGTH:
            return None
        return self._tools.get(tool_name)

    def list_tools(self) -> List[ToolDefinition]:
        """
        Returns all registered tools.
        """
        return list(self._tools.values())

    def reset_to_defaults(self):
        """
        Resets registry to the 4 default mock tools.
        """
        self._tools.clear()
        self._register_default_tools()


# Global tool registry singleton
tool_registry = ToolRegistry()
