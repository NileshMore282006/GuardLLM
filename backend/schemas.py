"""
Pydantic Schemas for AgentGuard API v0.4
Includes validation for single-prompt evaluations, guarded executions, multi-turn chat conversations,
readiness checks, metrics, and structured operational error responses.
Preserves exact public JSON schema contracts for GuardResponse, ExecuteResponse, and ChatResponse.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
from backend.config import (
    MAX_CHAT_MESSAGES,
    MAX_PROMPT_LENGTH,
    MAX_TOTAL_CONVERSATION_LENGTH,
    MAX_TOOL_ARGUMENT_LENGTH,
    MAX_TOOL_NAME_LENGTH,
)


class HealthResponse(BaseModel):
    """
    Response schema for service health status.
    """
    status: str = Field(..., description="Service operational status.", examples=["ok"])
    version: str = Field(..., description="AgentGuard backend version.", examples=["0.4.0"])
    guard_model: str = Field(..., description="Configured Guard LLM model identifier.", examples=["llama3.2:latest"])
    target_model: str = Field(..., description="Configured Target LLM model identifier.", examples=["llama3.2:latest"])


class ReadyResponse(BaseModel):
    """
    Response schema for service readiness status (Ollama and security dependencies).
    """
    status: str = Field(..., description="Readiness status ('ready' or 'not_ready').", examples=["ready"])
    version: str = Field(..., description="AgentGuard backend version.", examples=["0.9.0"])
    environment: Optional[str] = Field("development", description="Deployment environment profile.")
    ollama: str = Field(..., description="Ollama connection status ('connected' or 'unreachable').", examples=["connected"])
    guard_model: str = Field(..., description="Configured Guard LLM model identifier.", examples=["llama3.2:latest"])
    target_model: str = Field(..., description="Configured Target LLM model identifier.", examples=["llama3.2:latest"])
    identity: Optional[str] = Field("ready", description="Identity store readiness.")
    credential_store: Optional[str] = Field("ready", description="Credential store readiness.")
    policy_store: Optional[str] = Field("ready", description="Policy store readiness.")
    audit_store: Optional[str] = Field("ready", description="Audit store readiness.")
    configuration: Optional[str] = Field("ready", description="Configuration readiness.")
    checks: Optional[Dict[str, str]] = Field(None, description="Detailed safe readiness check statuses.")


class ErrorDetail(BaseModel):
    """
    Structured error code and safe message.
    """
    code: str = Field(..., description="Machine-readable error category.", examples=["RATE_LIMITED", "CONCURRENCY_LIMIT"])
    message: str = Field(..., description="Safe human-readable explanation of error.", examples=["Request rate limit exceeded."])


class ErrorResponse(BaseModel):
    """
    Uniform structured API error response.
    """
    request_id: str = Field(..., description="Correlation tracking identifier.", examples=["550e8400-e29b-41d4-a716-446655440000"])
    error: ErrorDetail = Field(..., description="Structured error payload.")


class GuardRequest(BaseModel):
    """
    Request schema for user prompt security evaluation and execution.
    """
    prompt: str = Field(
        ...,
        min_length=1,
        max_length=MAX_PROMPT_LENGTH,
        description="The user prompt to analyze for security risks and attacks.",
        examples=["What is the capital of France?"],
    )

    @field_validator("prompt")
    @classmethod
    def validate_prompt_not_empty_or_whitespace(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("Prompt must be a string.")
        if not value.strip():
            raise ValueError("Prompt must not be empty or whitespace-only.")
        return value


class ExecuteRequest(GuardRequest):
    """
    Request schema for prompt execution. Identical contract to GuardRequest.
    """
    pass


class GuardResponse(BaseModel):
    """
    Response schema for AgentGuard security evaluation results.
    Strictly preserves the 6 public schema fields for backward compatibility.
    """
    request_id: str = Field(
        ...,
        description="Unique UUID tracking identifier for the request.",
        examples=["550e8400-e29b-41d4-a716-446655440000"],
    )
    decision: str = Field(
        ...,
        description="Security enforcement decision: ALLOW or BLOCK.",
        examples=["ALLOW", "BLOCK"],
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Assessed risk score normalized between 0.0 and 1.0.",
        examples=[0.02, 0.98],
    )
    attack_type: str = Field(
        ...,
        description="Taxonomy classification of identified attack type or 'none'.",
        examples=["none", "instruction_override", "prompt_injection"],
    )
    guard_model: str = Field(
        ...,
        description="Identifier of the Guard model that performed classification.",
        examples=["llama3.2:latest"],
    )
    latency_ms: float = Field(
        ...,
        ge=0.0,
        description="Security evaluation latency in milliseconds.",
        examples=[481.7],
    )


class ExecuteResponse(BaseModel):
    """
    Response schema for guarded execution through AgentGuard v5 and the target LLM.
    Strictly preserves the 8 public schema fields for backward compatibility.
    """
    request_id: str = Field(
        ...,
        description="Unique UUID tracking identifier for the execution request.",
        examples=["550e8400-e29b-41d4-a716-446655440000"],
    )
    decision: str = Field(
        ...,
        description="Execution decision: ALLOW, BLOCK, or ERROR.",
        examples=["ALLOW", "BLOCK", "ERROR"],
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Assessed risk score normalized between 0.0 and 1.0.",
        examples=[0.0, 1.0],
    )
    attack_type: str = Field(
        ...,
        description="Taxonomy classification of identified attack type or 'none'.",
        examples=["none", "instruction_override"],
    )
    guard_model: str = Field(
        ...,
        description="Identifier of the Guard model used.",
        examples=["llama3.2:latest"],
    )
    target_model: str = Field(
        ...,
        description="Identifier of the Target model used.",
        examples=["llama3.2:latest"],
    )
    response: Optional[str] = Field(
        None,
        description="Sanitized target LLM output on ALLOW, or null if BLOCKED or on ERROR.",
        examples=["Paris is the capital of France."],
    )
    latency_ms: float = Field(
        ...,
        ge=0.0,
        description="Total request latency across Guard and Target in milliseconds.",
        examples=[1234.5],
    )


class ChatMessage(BaseModel):
    """
    Individual message turn within a multi-turn conversation.
    Strictly permits only 'user' and 'assistant' roles.
    Privileged client roles ('system', 'developer', 'tool') are strictly rejected.
    """
    role: str = Field(
        ...,
        description="The author role of the message. Strictly 'user' or 'assistant'.",
        examples=["user", "assistant"],
    )
    content: str = Field(
        ...,
        min_length=1,
        max_length=MAX_PROMPT_LENGTH,
        description="Text content of the message.",
        examples=["Can you help me solve a math problem?"],
    )

    @field_validator("role")
    @classmethod
    def validate_role_allowed(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Message role must be a string.")
        normalized = v.strip().lower()
        if normalized not in ("user", "assistant"):
            raise ValueError(
                f"Role '{v}' is not permitted. Only 'user' and 'assistant' roles are allowed in /api/v1/chat."
            )
        return normalized

    @field_validator("content")
    @classmethod
    def validate_content_not_empty(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Message content must be a string.")
        if not v.strip():
            raise ValueError("Message content must not be empty or whitespace-only.")
        return v


class ChatRequest(BaseModel):
    """
    Request schema for multi-turn conversation evaluation and guarded execution.
    """
    conversation_id: Optional[str] = Field(
        None,
        description="Optional correlation identifier for the conversation session.",
        examples=["conv-550e8400-e29b-41d4-a716-446655440000"],
    )
    messages: List[ChatMessage] = Field(
        ...,
        min_length=1,
        description="Sequence of conversation turns ordered chronologically.",
    )

    @field_validator("messages")
    @classmethod
    def validate_conversation_limits(cls, messages: List[ChatMessage]) -> List[ChatMessage]:
        if not messages:
            raise ValueError("Messages list must not be empty.")
        if len(messages) > MAX_CHAT_MESSAGES:
            raise ValueError(
                f"Conversation exceeds maximum allowed turns ({len(messages)} > {MAX_CHAT_MESSAGES})."
            )
        total_len = sum(len(m.content) for m in messages)
        if total_len > MAX_TOTAL_CONVERSATION_LENGTH:
            raise ValueError(
                f"Total conversation length exceeds maximum limit ({total_len} > {MAX_TOTAL_CONVERSATION_LENGTH} characters)."
            )
        return messages


class ChatResponse(BaseModel):
    """
    Response schema for multi-turn conversation execution.
    Strictly preserves the 9 public schema fields for backward compatibility.
    """
    request_id: str = Field(
        ...,
        description="Unique UUID tracking identifier for this chat request.",
        examples=["550e8400-e29b-41d4-a716-446655440000"],
    )
    conversation_id: str = Field(
        ...,
        description="Correlation identifier for the conversation session.",
        examples=["conv-550e8400-e29b-41d4-a716-446655440000"],
    )
    decision: str = Field(
        ...,
        description="Execution decision: ALLOW, BLOCK, or ERROR.",
        examples=["ALLOW", "BLOCK", "ERROR"],
    )
    risk_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Assessed risk score normalized between 0.0 and 1.0, or null on ERROR.",
        examples=[0.05, 0.95],
    )
    attack_type: str = Field(
        ...,
        description="Taxonomy classification of identified attack type, 'none', or 'error'.",
        examples=["none", "instruction_override", "context_manipulation"],
    )
    guard_model: str = Field(
        ...,
        description="Identifier of the Guard model used.",
        examples=["llama3.2:latest"],
    )
    target_model: str = Field(
        ...,
        description="Identifier of the Target model used.",
        examples=["llama3.2:latest"],
    )
    response: Optional[str] = Field(
        None,
        description="Sanitized target LLM output on ALLOW, or null if BLOCKED or on ERROR.",
        examples=["Sure! I can help you solve math problems."],
    )
    latency_ms: float = Field(
        ...,
        ge=0.0,
        description="Total request latency across Guard and Target in milliseconds.",
        examples=[1234.5],
    )


class ToolCallRequest(BaseModel):
    """
    Request schema for tool/function-call execution and authorization.
    """
    tool_name: str = Field(
        ...,
        min_length=1,
        max_length=MAX_TOOL_NAME_LENGTH,
        description="The canonical identifier of the tool to invoke.",
        examples=["get_weather"],
    )
    arguments: Dict[str, Any] = Field(
        default_factory=dict,
        description="Key-value arguments provided to the tool.",
        examples=[{"city": "Mumbai"}],
    )
    approval_id: Optional[str] = Field(
        None,
        description="Optional cryptographic approval ID for high-risk action authorization.",
        examples=["appr_0123456789abcdef0123456789abcdef"],
    )
    conversation_id: Optional[str] = Field(
        None,
        description="Optional conversation context identifier for action binding.",
        examples=["conv-550e8400-e29b-41d4-a716-446655440000"],
    )

    @field_validator("tool_name")
    @classmethod
    def validate_tool_name_basic(cls, v: str) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("tool_name must not be empty or whitespace-only.")
        return v


class ToolCallResponse(BaseModel):
    """
    Response schema for tool execution results and authorization telemetry.
    """
    request_id: str = Field(
        ...,
        description="Unique UUID tracking identifier for the tool call request.",
        examples=["550e8400-e29b-41d4-a716-446655440000"],
    )
    decision: str = Field(
        ...,
        description="Tool authorization decision: ALLOW, BLOCK, ERROR, or PENDING_APPROVAL.",
        examples=["ALLOW", "BLOCK", "ERROR", "PENDING_APPROVAL"],
    )
    tool_name: str = Field(
        ...,
        description="Name of the evaluated tool.",
        examples=["get_weather"],
    )
    result: Optional[str] = Field(
        None,
        description="Sanitized tool execution result if ALLOWED, or null if BLOCKED/ERROR/PENDING.",
        examples=["Weather in Mumbai: 29°C, Sunny."],
    )
    latency_ms: float = Field(
        ...,
        ge=0.0,
        description="Total tool evaluation and execution latency in milliseconds.",
        examples=[12.4],
    )
    risk_level: Optional[str] = Field(
        None,
        description="Assessed risk level of the tool (low, medium, high, critical).",
        examples=["low"],
    )
    attack_type: Optional[str] = Field(
        None,
        description="Identified attack category if blocked, or 'none'.",
        examples=["none", "unknown_tool", "prompt_injection_in_arguments"],
    )
    approval_id: Optional[str] = Field(
        None,
        description="Cryptographic approval ID associated with this action.",
        examples=["appr_0123456789abcdef0123456789abcdef"],
    )
    approval_status: Optional[str] = Field(
        None,
        description="Authorization state: NOT_REQUIRED, PENDING_APPROVAL, APPROVED, DENIED, EXPIRED, CONSUMED.",
        examples=["NOT_REQUIRED", "PENDING_APPROVAL", "CONSUMED"],
    )


class ApprovalCreateRequest(BaseModel):
    """
    Request schema for creating a human approval request.
    """
    tool_name: str = Field(
        ...,
        min_length=1,
        max_length=MAX_TOOL_NAME_LENGTH,
        description="Canonical identifier of the tool requiring approval.",
        examples=["send_email"],
    )
    arguments: Dict[str, Any] = Field(
        default_factory=dict,
        description="Key-value arguments for the proposed action.",
        examples=[{"recipient": "user@example.com", "subject": "Hello"}],
    )
    conversation_id: Optional[str] = Field(
        None,
        description="Optional conversation context identifier for action binding.",
        examples=["conv-550e8400-e29b-41d4-a716-446655440000"],
    )


class ApprovalCreateResponse(BaseModel):
    """
    Response schema when creating an approval request.
    """
    request_id: str = Field(..., description="Unique UUID tracking identifier.")
    approval_id: Optional[str] = Field(None, description="Cryptographic unique approval ID if approval required.")
    decision: str = Field(..., description="Decision: PENDING_APPROVAL, ALLOW, or BLOCK.")
    approval_status: str = Field(..., description="Status: PENDING_APPROVAL, NOT_REQUIRED, or DENIED.")
    tool_name: str = Field(..., description="Tool name proposed.")
    risk_level: Optional[str] = Field(None, description="Risk classification level.")
    arguments_summary: Optional[str] = Field(None, description="Safe summary of arguments (no secrets).")
    reason: Optional[str] = Field(None, description="Explanation of approval requirement or block reason.")
    created_at: Optional[float] = Field(None, description="Creation timestamp.")
    expires_at: Optional[float] = Field(None, description="Expiration timestamp.")
    result: Optional[str] = Field(None, description="Execution result (null while pending approval).")
    latency_ms: Optional[float] = Field(None, description="Evaluation latency in ms.")


class ApprovalDetailResponse(BaseModel):
    """
    Safe inspection schema for approval status (no secrets or raw sensitive parameters).
    """
    approval_id: str = Field(..., description="Unique approval identifier.")
    request_id: str = Field(..., description="Initial tracking request ID.")
    conversation_id: Optional[str] = Field(None, description="Bound conversation ID.")
    tool_name: str = Field(..., description="Canonical tool name.")
    risk_level: str = Field(..., description="Tool risk level.")
    reason: str = Field(..., description="Approval justification.")
    arguments_summary: str = Field(..., description="Safe argument summary.")
    arguments_hash: str = Field(..., description="SHA-256 hash of canonical arguments.")
    status: str = Field(..., description="Approval status.")
    principal_id: Optional[str] = Field("user-demo", description="Principal who requested approval.")
    policy_id: Optional[str] = Field(None, description="Bound policy ID.")
    policy_version: Optional[int] = Field(None, description="Bound policy version.")
    created_at: float = Field(..., description="Creation unix timestamp.")
    expires_at: float = Field(..., description="Expiration unix timestamp.")
    approved_at: Optional[float] = Field(None, description="Timestamp when approved.")
    denied_at: Optional[float] = Field(None, description="Timestamp when denied.")
    expired_at: Optional[float] = Field(None, description="Timestamp when expired.")
    consumed_at: Optional[float] = Field(None, description="Timestamp when consumed for execution.")
    execution_count: int = Field(..., description="Number of times executed (max 1).")


class ApprovalActionResponse(BaseModel):
    """
    Response schema for approve or deny operations.
    """
    request_id: str = Field(..., description="Tracking request ID.")
    approval_id: str = Field(..., description="Unique approval identifier.")
    decision: str = Field(..., description="Action decision: ALLOW, BLOCK, or ERROR.")
    approval_status: str = Field(..., description="Updated approval status: CONSUMED, DENIED, EXPIRED, etc.")
    tool_name: str = Field(..., description="Tool name.")
    result: Optional[str] = Field(None, description="Execution result if ALLOW/CONSUMED, else null.")
    risk_level: Optional[str] = Field(None, description="Tool risk level.")
    latency_ms: Optional[float] = Field(None, description="Execution latency in ms.")
    attack_type: Optional[str] = Field(None, description="Attack classification if blocked.")


# =====================================================================
# Backend v0.7 Schemas: Identity, Policy Administration, and Audit
# =====================================================================

class PrincipalResponse(BaseModel):
    """
    Safe representation of resolved authenticated principal.
    """
    principal_id: str = Field(..., description="Unique principal identifier.")
    principal_type: str = Field(..., description="Principal type: user, service, or admin.")
    roles: List[str] = Field(..., description="Assigned roles: user, operator, admin.")
    tenant_id: str = Field("default", description="Tenant or namespace identifier.")
    active: bool = Field(True, description="Account active status.")


class PolicyCreateRequest(BaseModel):
    """
    Payload schema for creating a security policy rule.
    """
    name: str = Field(..., min_length=1, max_length=100, description="Human-readable policy name.")
    description: Optional[str] = Field("", max_length=500, description="Description of the policy purpose.")
    action: str = Field(..., description="Policy action: ALLOW, DENY, or REQUIRE_APPROVAL.")
    principal_scope: List[str] = Field(default_factory=lambda: ["*"], description="Target principals or ['*'].")
    tool_scope: List[str] = Field(default_factory=lambda: ["*"], description="Target tools or ['*'].")
    risk_levels: List[str] = Field(default_factory=lambda: ["*"], description="Applicable risk levels or ['*'].")
    priority: int = Field(100, ge=0, le=10000, description="Evaluation priority (higher wins within action).")
    enabled: bool = Field(True, description="Policy activation status.")
    tenant_id: Optional[str] = Field(None, description="Optional target tenant for multi-tenancy.")


class PolicyUpdateRequest(BaseModel):
    """
    Payload schema for updating a security policy rule.
    """
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    action: Optional[str] = None
    principal_scope: Optional[List[str]] = None
    tool_scope: Optional[List[str]] = None
    risk_levels: Optional[List[str]] = None
    priority: Optional[int] = Field(None, ge=0, le=10000)
    enabled: Optional[bool] = None


class PolicyResponse(BaseModel):
    """
    Response representation of a security policy rule.
    """
    policy_id: str
    name: str
    description: str
    enabled: bool
    priority: int
    principal_scope: List[str]
    tool_scope: List[str]
    risk_levels: List[str]
    action: str
    version: int
    created_by: str
    updated_by: str
    created_at: float
    updated_at: float
    deleted: bool
    tenant_id: str = "default"


class PolicyListResponse(BaseModel):
    """
    List of security policy rules.
    """
    policies: List[PolicyResponse]
    total: int


class AuditEventResponse(BaseModel):
    """
    Safe audit event representation without secrets or raw user prompts.
    """
    event_id: str
    timestamp: float
    request_id: Optional[str] = None
    principal_id: Optional[str] = None
    principal_type: Optional[str] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    decision: Optional[str] = None
    risk_score: Optional[float] = None
    attack_type: Optional[str] = None
    policy_id: Optional[str] = None
    policy_version: Optional[int] = None
    approval_id: Optional[str] = None
    tool_name: Optional[str] = None
    error_code: Optional[str] = None
    event_hash: str
    previous_event_hash: str
    tenant_id: Optional[str] = "default"


class AuditListResponse(BaseModel):
    """
    Paginated audit log response.
    """
    events: List[AuditEventResponse]
    total: int
    limit: int
    offset: int


class AuditVerifyResponse(BaseModel):
    """
    Audit hash chain cryptographic verification result.
    """
    valid: bool
    first_invalid_event: Optional[str] = None
    total_events: int
    details: str


# =========================================================================
# v0.8 Credential, Principal, and Tenant Schemas
# =========================================================================

class CredentialCreateRequest(BaseModel):
    """
    Payload for creating an API credential.
    Secrets are generated server-side; callers never specify secrets.
    """
    principal_id: str = Field(..., min_length=1, max_length=64, description="Target principal.")
    tenant_id: Optional[str] = Field(None, max_length=64, description="Target tenant.")
    description: Optional[str] = Field(None, max_length=256, description="Credential description.")
    expires_in_seconds: Optional[int] = Field(None, ge=60, le=315360000, description="Expiration TTL in seconds.")


class CredentialResponse(BaseModel):
    """
    Safe credential metadata response (NEVER includes secret or full hash).
    """
    credential_id: str
    principal_id: str
    tenant_id: str
    status: str
    created_at: float
    expires_at: Optional[float] = None
    last_used_at: Optional[float] = None
    revoked_at: Optional[float] = None
    description: Optional[str] = None
    created_by: str


class CredentialCreatedResponse(BaseModel):
    """
    Returned EXACTLY ONCE upon credential creation or rotation.
    Contains the full Bearer token and plaintext secret.
    """
    credential_id: str
    credential_secret: str
    token: str
    principal_id: str
    tenant_id: str
    created_at: float
    expires_at: Optional[float] = None


class CredentialRotateResponse(BaseModel):
    """
    Returned EXACTLY ONCE upon credential rotation.
    """
    old_credential_id: str
    new_credential_id: str
    credential_secret: str
    token: str
    principal_id: str
    tenant_id: str
    created_at: float
    expires_at: Optional[float] = None


class CredentialListResponse(BaseModel):
    credentials: List[CredentialResponse]
    total: int


class PrincipalCreateRequest(BaseModel):
    """
    Payload for creating a security principal.
    """
    principal_id: str = Field(..., min_length=1, max_length=64)
    principal_type: str = Field("user", description="user, service, admin, or global_admin")
    tenant_id: Optional[str] = Field(None, max_length=64)
    roles: List[str] = Field(default_factory=lambda: ["user"])


class PrincipalUpdateRequest(BaseModel):
    """
    Payload for updating principal metadata.
    """
    principal_type: Optional[str] = None
    roles: Optional[List[str]] = None
    status: Optional[str] = None


class PrincipalResponse(BaseModel):
    principal_id: str
    principal_type: str
    tenant_id: str
    roles: List[str]
    status: str
    created_at: float
    updated_at: float


class PrincipalListResponse(BaseModel):
    principals: List[PrincipalResponse]
    total: int


class TenantCreateRequest(BaseModel):
    """
    Payload for creating a new isolated tenant.
    """
    tenant_id: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=128)


class TenantUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    status: Optional[str] = Field(None, description="ACTIVE or DISABLED")


class TenantResponse(BaseModel):
    tenant_id: str
    name: str
    status: str
    created_at: float
    updated_at: float


class TenantListResponse(BaseModel):
    tenants: List[TenantResponse]
    total: int


# ============================================================
# OPENAI COMPATIBILITY SCHEMAS (/v1/chat/completions & /v1/models)
# ============================================================

class OpenAIChatMessage(BaseModel):
    """
    Message structure for OpenAI Chat Completions compatibility.
    Supports system, user, assistant, developer, and tool roles.
    """
    role: str = Field(..., description="Role of the author (system, user, assistant, developer, tool).")
    content: Optional[Any] = Field(default="", description="The contents of the message.")
    name: Optional[str] = Field(default=None, description="An optional name for the participant.")
    tool_call_id: Optional[str] = Field(default=None, description="Tool call that this message is responding to.")
    tool_calls: Optional[List[Dict[str, Any]]] = Field(default=None, description="Tool calls generated by the model.")

    @field_validator("content")
    @classmethod
    def normalize_content(cls, v: Any) -> str:
        if v is None:
            return ""
        if isinstance(v, str):
            return v
        if isinstance(v, list):
            text_parts = []
            for item in v:
                if isinstance(item, dict) and item.get("type") == "text":
                    text_parts.append(str(item.get("text", "")))
                elif isinstance(item, str):
                    text_parts.append(item)
                elif isinstance(item, dict) and "content" in item:
                    text_parts.append(str(item["content"]))
            return " ".join(text_parts)
        return str(v)


class OpenAIChatCompletionRequest(BaseModel):
    """
    Standard request payload for /v1/chat/completions.
    Permits extra arguments to remain fully compatible with all OpenAI SDK parameters.
    """
    model: str = Field(default="llama3.2", description="ID of the model to use.")
    messages: List[OpenAIChatMessage] = Field(..., min_length=1, description="List of messages comprising the conversation.")
    temperature: Optional[float] = Field(default=1.0, ge=0.0, le=2.0)
    top_p: Optional[float] = Field(default=1.0, ge=0.0, le=1.0)
    n: Optional[int] = Field(default=1, ge=1)
    stream: Optional[bool] = Field(default=False)
    stop: Optional[Any] = None
    max_tokens: Optional[int] = None
    presence_penalty: Optional[float] = 0.0
    frequency_penalty: Optional[float] = 0.0
    user: Optional[str] = None

    model_config = {"extra": "allow"}


class OpenAIChatChoiceMessage(BaseModel):
    role: str = "assistant"
    content: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None


class OpenAIChatChoice(BaseModel):
    index: int = 0
    message: OpenAIChatChoiceMessage
    finish_reason: Optional[str] = "stop"


class OpenAIUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class OpenAIGuardMetadata(BaseModel):
    decision: str
    risk_score: float
    attack_type: str
    latency_ms: float


class OpenAIChatCompletionResponse(BaseModel):
    """
    Standard OpenAI response payload for /v1/chat/completions.
    """
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: List[OpenAIChatChoice]
    usage: OpenAIUsage
    system_fingerprint: Optional[str] = "fp_agentguard_v1"
    agentguard: Optional[OpenAIGuardMetadata] = None


class OpenAIModelCard(BaseModel):
    id: str
    object: str = "model"
    created: int
    owned_by: str = "agentguard"
    root: Optional[str] = None
    parent: Optional[str] = None
    permission: Optional[List[Dict[str, Any]]] = Field(default_factory=list)


class OpenAIModelListResponse(BaseModel):
    object: str = "list"
    data: List[OpenAIModelCard]
