/**
 * AgentGuard Frontend Types (v0.1, v0.2 & v0.3)
 * Directly aligned with FastAPI backend schemas.
 */

export type GuardDecision = 'ALLOW' | 'BLOCK' | 'ERROR';

export interface HealthResponse {
  status: string;
  version: string;
  guard_model: string;
  target_model: string;
}

export interface GuardRequest {
  prompt: string;
}

export interface GuardResponse {
  request_id: string;
  decision: GuardDecision;
  risk_score: number;
  attack_type: string;
  guard_model: string;
  latency_ms: number;
}

export interface ExecuteRequest {
  prompt: string;
}

export interface ExecuteResponse {
  request_id: string;
  decision: GuardDecision;
  risk_score: number;
  attack_type: string;
  guard_model: string;
  target_model: string;
  response: string | null;
  latency_ms: number;
}

/* =========================================================================
   Multi-Turn Chat Models (Aligned with backend/schemas.py ChatRequest/Response)
   ========================================================================= */

export type ChatRole = 'user' | 'assistant';

export interface ChatMessage {
  role: ChatRole;
  content: string;
}

export interface ChatRequest {
  conversation_id?: string;
  messages: ChatMessage[];
}

export interface ChatResponse {
  request_id: string;
  conversation_id: string;
  decision: GuardDecision;
  risk_score: number | null;
  attack_type: string;
  guard_model: string;
  target_model: string;
  response: string | null;
  latency_ms: number;
}

export interface TurnSecurityMetadata {
  decision: GuardDecision;
  risk_score: number | null;
  attack_type: string;
  guard_model: string;
  target_model: string;
  request_id: string;
  latency_ms: number;
}

export interface ChatTurn {
  id: string;
  turnNumber: number;
  userMessage: string;
  assistantResponse: string | null;
  security: TurnSecurityMetadata;
  timestamp: string;
  isCancelled?: boolean;
}

export type AppMode = 'secops' | 'admin' | 'dashboard' | 'agent-security' | 'chat' | 'playground';

export interface BackendErrorPayload {
  request_id?: string;
  error?: {
    code: string;
    message: string;
  };
  detail?: string | { code?: string; message?: string };
}

export type SecurityFlowState =
  | 'IDLE'
  | 'ANALYZING'
  | 'ALLOWED'
  | 'BLOCKED'
  | 'EXECUTING'
  | 'COMPLETED'
  | 'ERROR';

export interface HistoryItem {
  id: string;
  timestamp: string;
  prompt: string;
  decision: GuardDecision;
  attack_type: string;
  risk_score: number;
  latency_ms: number;
  guardResult: GuardResponse;
  executeResult?: ExecuteResponse | null;
}

/* =========================================================================
   Agent Security Models (v0.3 - Aligned with Backend Tool & Approval Schemas)
   ========================================================================= */

export type ToolRiskLevel = 'low' | 'medium' | 'high' | 'critical';

export type ToolSecurityDecision = 'ALLOW' | 'BLOCK' | 'ERROR' | 'PENDING_APPROVAL';

export type ApprovalStatus =
  | 'NOT_REQUIRED'
  | 'PENDING_APPROVAL'
  | 'APPROVED'
  | 'DENIED'
  | 'EXPIRED'
  | 'CONSUMED'
  | 'ERROR';

export type ToolSecurityState =
  | 'IDLE'
  | 'ANALYZING'
  | 'ALLOWED'
  | 'BLOCKED'
  | 'PENDING_APPROVAL'
  | 'SUBMITTING_APPROVAL'
  | 'APPROVED'
  | 'DENIED'
  | 'CONSUMED'
  | 'EXPIRED'
  | 'EXECUTING'
  | 'ERROR';

export interface ToolDefinitionInfo {
  tool_name: string;
  description: string;
  risk_level: ToolRiskLevel;
  read_only: boolean;
  side_effect: boolean;
  allowed_arguments: Record<
    string,
    {
      type: string;
      required: boolean;
      max_length?: number;
      description: string;
    }
  >;
  default_arguments: Record<string, any>;
}

export interface ToolCallRequest {
  tool_name: string;
  arguments: Record<string, any>;
  approval_id?: string;
  conversation_id?: string;
}

export interface ToolCallResponse {
  request_id: string;
  decision: ToolSecurityDecision;
  tool_name: string;
  result: string | null;
  latency_ms: number;
  risk_level?: ToolRiskLevel | null;
  attack_type?: string | null;
  approval_id?: string | null;
  approval_status?: ApprovalStatus | null;
}

export interface ApprovalCreateRequest {
  tool_name: string;
  arguments: Record<string, any>;
  conversation_id?: string;
}

export interface ApprovalCreateResponse {
  request_id: string;
  approval_id: string | null;
  decision: ToolSecurityDecision;
  approval_status: ApprovalStatus;
  tool_name: string;
  risk_level: ToolRiskLevel | null;
  arguments_summary: string | null;
  reason: string | null;
  created_at: number | null;
  expires_at: number | null;
  result: string | null;
  latency_ms: number | null;
}

export interface ApprovalDetailResponse {
  approval_id: string;
  request_id: string;
  conversation_id: string | null;
  tool_name: string;
  risk_level: ToolRiskLevel;
  reason: string;
  arguments_summary: string;
  arguments_hash: string;
  status: ApprovalStatus;
  principal_id?: string;
  policy_id?: string | null;
  policy_version?: number | null;
  created_at: number;
  expires_at: number;
  approved_at?: number | null;
  denied_at?: number | null;
  expired_at?: number | null;
  consumed_at?: number | null;
  execution_count: number;
}

export interface ApprovalActionResponse {
  request_id: string;
  approval_id: string;
  decision: ToolSecurityDecision;
  approval_status: ApprovalStatus;
  tool_name: string;
  result: string | null;
  risk_level?: ToolRiskLevel | null;
  latency_ms?: number | null;
  attack_type?: string | null;
}

export interface ToolTimelineEvent {
  id: string;
  stage: string;
  status:
    | 'PENDING'
    | 'ALLOWED'
    | 'BLOCKED'
    | 'PENDING APPROVAL'
    | 'APPROVED'
    | 'DENIED'
    | 'EXPIRED'
    | 'CONSUMED'
    | 'ERROR'
    | 'INFO';
  timestamp: string;
  detail: string;
  isBackendTimestamp?: boolean;
}

export interface ToolSecurityHistoryItem {
  id: string;
  timestamp: string;
  tool_name: string;
  decision: ToolSecurityDecision;
  risk_level: ToolRiskLevel | null;
  approval_status: ApprovalStatus | null;
  result: string | null;
  latency_ms: number;
  attack_type?: string | null;
}

/* =========================================================================
   Security Dashboard & Observability Types (v0.4)
   ========================================================================= */

export interface ReadyResponse {
  status: string; // 'ready' or 'not_ready'
  version: string;
  environment?: string;
  ollama: string; // 'connected' or 'unreachable'
  guard_model: string;
  target_model: string;
  identity?: string;
  credential_store?: string;
  policy_store?: string;
  audit_store?: string;
  configuration?: string;
  checks?: Record<string, string>;
}

export interface RuntimeMetricsResponse {
  uptime_seconds: number;
  total_requests: number;
  requests_by_endpoint: Record<string, number>;
  requests_by_status: Record<string, number>;
  decisions: {
    allow: number;
    block: number;
    error: number;
  };
  rate_limited_count: number;
  concurrency_rejected_count: number;
  guard: {
    invocations: number;
    failures: number;
    timeouts: number;
  };
  target: {
    invocations: number;
    failures: number;
    timeouts: number;
  };
  timeouts: {
    guard_timeouts: number;
    target_timeouts: number;
    total_timeouts: number;
  };
  tools: {
    total_calls: number;
    allowed: number;
    blocked: number;
    error: number;
    unauthorized_executions: number;
    limit_exceeded: number;
  };
  approvals: {
    approval_requests_created: number;
    approval_requests_approved: number;
    approval_requests_denied: number;
    approval_requests_expired: number;
    approval_requests_cancelled: number;
    approval_execution_success: number;
    approval_execution_failure: number;
    approval_replay_attempts: number;
    approval_binding_failures: number;
    unauthorized_high_risk_tool_executions: number;
  };
}

export interface AuditEventItem {
  event_id: string;
  timestamp: number; // epoch seconds
  request_id?: string | null;
  principal_id?: string | null;
  principal_type?: string | null;
  action: string;
  resource_type?: string | null;
  resource_id?: string | null;
  decision?: string | null;
  risk_score?: number | null;
  attack_type?: string | null;
  policy_id?: string | null;
  policy_version?: number | null;
  approval_id?: string | null;
  tool_name?: string | null;
  error_code?: string | null;
  event_hash: string;
  previous_event_hash: string;
  tenant_id?: string | null;
}

export interface AuditListResponse {
  events: AuditEventItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface AuditQueryParams {
  request_id?: string;
  principal_id?: string;
  tenant_id?: string;
  action?: string;
  decision?: string;
  resource_type?: string;
  limit?: number;
  offset?: number;
  start_time?: number;
  end_time?: number;
}

export interface DashboardFilterState {
  decision: 'ALL' | 'ALLOW' | 'BLOCK' | 'ERROR';
  attackType: string;
  actionCategory: string;
  searchQuery: string;
}

export type SecurityFlowStageName =
  | 'REQUEST'
  | 'HTTP_BOUNDARY'
  | 'AUTH_TENANT'
  | 'POLICY'
  | 'GUARD'
  | 'TOOL_APPROVAL'
  | 'TARGET'
  | 'OUTPUT_SANITIZER'
  | 'AUDIT';

export interface SecurityFlowStage {
  id: SecurityFlowStageName;
  label: string;
  description: string;
  status: 'passed' | 'blocked' | 'skipped' | 'active' | 'neutral';
}

/* =========================================================================
   Administration & Audit Types (v0.5)
   ========================================================================= */

export type AdminTab =
  | 'overview'
  | 'tenants'
  | 'principals'
  | 'credentials'
  | 'policies'
  | 'audit';

// -------------------------------------------------------------------------
// Tenants
// -------------------------------------------------------------------------
export interface TenantResponse {
  tenant_id: string;
  name: string;
  status: string; // 'ACTIVE' | 'DISABLED'
  created_at: number;
  updated_at: number;
}

export interface TenantCreateRequest {
  tenant_id: string;
  name: string;
}

export interface TenantUpdateRequest {
  name?: string;
  status?: string;
}

export interface TenantListResponse {
  tenants: TenantResponse[];
  total: number;
}

// -------------------------------------------------------------------------
// Principals / Identities & Roles
// -------------------------------------------------------------------------
export type PrincipalType = 'user' | 'service' | 'admin' | 'global_admin';
export type PrincipalRole = 'user' | 'operator' | 'admin' | 'global_admin';

export interface PrincipalResponse {
  principal_id: string;
  principal_type: string;
  tenant_id: string;
  roles: string[];
  status: string; // 'ACTIVE' | 'DISABLED'
  created_at: number;
  updated_at: number;
}

export interface PrincipalCreateRequest {
  principal_id: string;
  principal_type?: string;
  tenant_id?: string;
  roles: string[];
}

export interface PrincipalUpdateRequest {
  principal_type?: string;
  roles?: string[];
  status?: string;
}

export interface PrincipalListResponse {
  principals: PrincipalResponse[];
  total: number;
}

// -------------------------------------------------------------------------
// API Credentials
// -------------------------------------------------------------------------
export type CredentialStatus = 'ACTIVE' | 'REVOKED' | 'EXPIRED' | 'DISABLED';

export interface CredentialResponse {
  credential_id: string;
  principal_id: string;
  tenant_id: string;
  status: string;
  created_at: number;
  expires_at?: number | null;
  last_used_at?: number | null;
  revoked_at?: number | null;
  description?: string | null;
  created_by: string;
}

export interface CredentialCreateRequest {
  principal_id: string;
  tenant_id?: string;
  description?: string;
  expires_in_seconds?: number;
}

export interface CredentialCreatedResponse {
  credential_id: string;
  credential_secret: string;
  token: string;
  principal_id: string;
  tenant_id: string;
  created_at: number;
  expires_at?: number | null;
}

export interface CredentialRotateResponse {
  old_credential_id: string;
  new_credential_id: string;
  credential_secret: string;
  token: string;
  principal_id: string;
  tenant_id: string;
  created_at: number;
  expires_at?: number | null;
}

export interface CredentialListResponse {
  credentials: CredentialResponse[];
  total: number;
}

// -------------------------------------------------------------------------
// Security Policies
// -------------------------------------------------------------------------
export type PolicyAction = 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL';

export interface PolicyResponse {
  policy_id: string;
  name: string;
  description: string;
  enabled: boolean;
  priority: number;
  principal_scope: string[];
  tool_scope: string[];
  risk_levels: string[];
  action: PolicyAction;
  version: number;
  created_by: string;
  updated_by: string;
  created_at: number;
  updated_at: number;
  deleted: boolean;
  tenant_id: string;
}

export interface PolicyCreateRequest {
  name: string;
  description?: string;
  action: PolicyAction;
  principal_scope?: string[];
  tool_scope?: string[];
  risk_levels?: string[];
  priority?: number;
  enabled?: boolean;
  tenant_id?: string;
}

export interface PolicyUpdateRequest {
  name?: string;
  description?: string;
  action?: PolicyAction;
  principal_scope?: string[];
  tool_scope?: string[];
  risk_levels?: string[];
  priority?: number;
  enabled?: boolean;
}

export interface PolicyListResponse {
  policies: PolicyResponse[];
  total: number;
}

export interface PolicyDeleteResponse {
  policy_id: string;
  status: string;
  version: number;
  deleted: boolean;
  message: string;
}

// -------------------------------------------------------------------------
// Audit Verification & Cryptographic Integrity
// -------------------------------------------------------------------------
export interface AuditVerifyResponse {
  valid: boolean;
  first_invalid_event?: string | null;
  total_events: number;
  details: string;
  status?: string; // 'valid' | 'tampered' | 'key_missing'
}

export type AuditVerificationStatus = 'VALID' | 'TAMPERED' | 'KEY MISSING' | 'INCOMPATIBLE';

// -------------------------------------------------------------------------
// Security Context & Destructive Action Dialog
// -------------------------------------------------------------------------
export interface SecurityContextInfo {
  principalId: string;
  tenantId: string;
  roles: string[];
  isAuthenticated: boolean;
  isGlobalAdmin: boolean;
}

export interface AdminConfirmationState {
  isOpen: boolean;
  operation: string; // e.g. "Revoke credential", "Disable principal", "Delete policy", "Disable tenant"
  targetId: string;
  targetType: 'tenant' | 'principal' | 'credential' | 'policy';
  securityImpact: string;
  onConfirm: () => Promise<void>;
}

// -------------------------------------------------------------------------
// Frontend v0.6: Security Operations & Incident Response Models
// -------------------------------------------------------------------------
export interface IncidentInvestigation {
  id: string;
  title: string;
  createdAt: number;
  selectedEventIds: string[];
  correlatedRequestIds: string[];
  correlatedPrincipals: string[];
  correlatedTenants: string[];
  correlatedTools: string[];
  correlatedApprovals: string[];
  correlatedPolicies: string[];
  notes: string;
  status: 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'DISMISSED';
}

export type SecOpsAlertSeverity = 'CRITICAL' | 'HIGH' | 'INFO';

export interface SecOpsAlert {
  id: string;
  severity: SecOpsAlertSeverity;
  title: string;
  description: string;
  source: string;
  timestamp: number;
  eventId?: string;
  requestId?: string;
  rawAction?: string;
  rawDecision?: string;
}

export type PipelineStageStatus = 'OBSERVED' | 'UNAVAILABLE' | 'BLOCKED';

export interface PipelineStageInfo {
  name: string;
  status: PipelineStageStatus;
  detail: string;
  timestamp?: number;
  observedData?: Record<string, any>;
}

export interface SecOpsConfirmationState {
  isOpen: boolean;
  operation: string;
  targetId: string;
  targetType: 'approval' | 'credential' | 'principal' | 'tenant' | 'policy';
  securityImpact: string;
  onConfirm: () => Promise<void>;
}

// -------------------------------------------------------------------------
// Frontend v0.7: Security Hardening, Session Security & Reliability Models
// -------------------------------------------------------------------------

export type SessionState =
  | 'UNKNOWN'
  | 'AUTHENTICATING'
  | 'AUTHENTICATED'
  | 'UNAUTHENTICATED'
  | 'FORBIDDEN'
  | 'EXPIRED'
  | 'BACKEND_UNAVAILABLE';

export type UserRole = 'user' | 'operator' | 'admin' | 'global_admin';

export type SecurityFreshness = 'LIVE' | 'REFRESHING' | 'STALE' | 'DEGRADED' | 'NOT_AVAILABLE';

export type NormalizedErrorCode =
  | 'AUTHENTICATION_REQUIRED'
  | 'FORBIDDEN'
  | 'RESOURCE_CONFLICT'
  | 'RATE_LIMITED'
  | 'BACKEND_UNAVAILABLE'
  | 'PAYLOAD_TOO_LARGE'
  | 'VALIDATION_ERROR'
  | 'NOT_FOUND'
  | 'INTERNAL_ERROR'
  | 'ABORTED'
  | 'NETWORK_ERROR'
  | 'UNKNOWN_ERROR';

export interface SafeApiError {
  code: NormalizedErrorCode;
  status: number;
  message: string;
  safeDetails?: string;
  timestamp: number;
}

export interface DestructiveActionSpec {
  action: string;
  resourceId: string;
  resourceType: 'approval' | 'credential' | 'principal' | 'tenant' | 'policy';
  currentServerState: string;
  impact: string;
  reversible: boolean;
  requiredRole?: UserRole;
  onExecute: () => Promise<void>;
}

export interface SanitizedInvestigationExport {
  export_schema_version: '1.0';
  export_label: 'Sanitized investigation bundle';
  disclaimer: 'Local investigation — not persisted by AgentGuard';
  exported_at: string;
  investigation_id: string;
  title: string;
  status: string;
  correlation_keys: {
    event_ids: string[];
    request_ids: string[];
    principal_ids: string[];
    tenant_ids: string[];
    tool_names: string[];
    approval_ids: string[];
    policy_ids: string[];
  };
  operator_notes: string;
  events: Array<{
    event_id: string;
    timestamp: number;
    request_id?: string | null;
    action: string;
    decision?: string | null;
    attack_type?: string | null;
    risk_score?: number | null;
    principal_id?: string | null;
    tenant_id?: string | null;
    tool_name?: string | null;
    event_hash: string;
    previous_event_hash: string;
  }>;
}

export interface AuthSessionInfo {
  state: SessionState;
  isAuthenticated: boolean;
  tokenPresent: boolean;
  maskedToken: string;
  principalId?: string;
  tenantId?: string;
  roles: UserRole[];
  lastError?: SafeApiError | null;
}


