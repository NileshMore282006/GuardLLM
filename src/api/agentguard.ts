/**
 * AgentGuard Typed API Client (v0.1, v0.2 & v0.3)
 * Centralizes all communication with the FastAPI backend.
 * Never leaks internal stack traces, tokens, or credentials.
 */

import {
  HealthResponse,
  GuardResponse,
  ExecuteResponse,
  ChatResponse,
  ChatMessage,
  ChatRequest,
  BackendErrorPayload,
  ToolCallRequest,
  ToolCallResponse,
  ApprovalCreateRequest,
  ApprovalCreateResponse,
  ApprovalDetailResponse,
  ApprovalActionResponse,
  ReadyResponse,
  RuntimeMetricsResponse,
  AuditListResponse,
  AuditQueryParams,
  TenantResponse,
  TenantCreateRequest,
  TenantUpdateRequest,
  TenantListResponse,
  PrincipalResponse,
  PrincipalCreateRequest,
  PrincipalUpdateRequest,
  PrincipalListResponse,
  CredentialResponse,
  CredentialCreateRequest,
  CredentialCreatedResponse,
  CredentialRotateResponse,
  CredentialListResponse,
  PolicyResponse,
  PolicyCreateRequest,
  PolicyUpdateRequest,
  PolicyListResponse,
  PolicyDeleteResponse,
  AuditVerifyResponse,
  ConversationSummary,
  ConversationDetail,
} from '../types/agentguard';

export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

export class AgentGuardApiError extends Error {
  public status: number;
  public code: string;

  constructor(message: string, status: number = 0, code: string = 'UNKNOWN_ERROR') {
    super(message);
    this.name = 'AgentGuardApiError';
    this.status = status;
    this.code = code;
  }
}

/**
 * Maps HTTP status codes to user-friendly safe messages without leaking internal info.
 */
function getSafeErrorMessage(status: number, defaultMsg?: string, errorCode?: string): string {
  if (errorCode === 'APPROVAL_ALREADY_CONSUMED') {
    return 'Approval has already been consumed.';
  }
  if (errorCode === 'APPROVAL_EXPIRED') {
    return 'Approval has expired.';
  }
  if (errorCode === 'POLICY_CONFLICT') {
    return defaultMsg || 'Action conflicts with security policy.';
  }

  switch (status) {
    case 400:
      return defaultMsg || 'Bad request. Please verify your payload format.';
    case 401:
      return 'Authentication is required.';
    case 403:
      return defaultMsg || 'Access forbidden: Insufficient privileges.';
    case 404:
      return defaultMsg || 'Requested resource not found.';
    case 409:
      return 'Approval has already been consumed.';
    case 413:
      return 'Your payload exceeds the configured request size limit.';
    case 415:
      return 'Unsupported media type. Expected application/json.';
    case 422:
      return 'Validation error: invalid request schema or parameter types.';
    case 429:
      return 'Too many requests. Rate limit exceeded.';
    case 500:
      return 'An internal server error occurred in AgentGuard.';
    case 503:
      return 'AgentGuard service is currently unavailable.';
    default:
      return (
        defaultMsg ||
        `Request failed with status ${status}. Check backend logs.`
      );
  }
}

async function requestJson<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  const headers = new Headers(options.headers || {});
  headers.set('Content-Type', 'application/json');

  let response: Response;
  try {
    response = await fetch(url, {
      ...options,
      headers,
    });
  } catch (err: unknown) {
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new AgentGuardApiError('Request cancelled locally.', 0, 'ABORTED');
    }
    throw new AgentGuardApiError(
      'AgentGuard backend is currently unreachable. Ensure FastAPI server is running on ' +
        API_BASE_URL,
      0,
      'NETWORK_ERROR'
    );
  }

  if (!response.ok) {
    let errorCode = 'HTTP_ERROR';
    let safeMessage: string = '';

    try {
      const errorJson = (await response.json()) as BackendErrorPayload;
      if (errorJson?.error?.code) {
        errorCode = errorJson.error.code;
      }
      if (errorJson?.error?.message && response.status < 500) {
        safeMessage = errorJson.error.message;
      }
    } catch {
      // JSON parse failed; fall back to safe status message
    }

    if (!safeMessage) {
      safeMessage = getSafeErrorMessage(response.status, undefined, errorCode);
    }

    // Specific mapping for consumed replay as required by specification
    if (response.status === 409 || errorCode === 'APPROVAL_ALREADY_CONSUMED') {
      safeMessage = 'Approval has already been consumed.';
    }

    throw new AgentGuardApiError(safeMessage, response.status, errorCode);
  }

  return response.json() as Promise<T>;
}

export const agentGuardApi = {
  /**
   * Health status check. Lightweight and safe to poll periodically.
   */
  async health(signal?: AbortSignal): Promise<HealthResponse> {
    return requestJson<HealthResponse>('/health', { signal });
  },

  /**
   * Health status check alias for consistency with getReady.
   */
  async getHealth(signal?: AbortSignal): Promise<HealthResponse> {
    return requestJson<HealthResponse>('/health', { signal });
  },

  /**
   * Evaluates prompt security through the complete AgentGuard v5 multi-layer pipeline.
   * Does NOT invoke the target LLM.
   */
  async guardPrompt(prompt: string): Promise<GuardResponse> {
    return requestJson<GuardResponse>('/api/v1/guard', {
      method: 'POST',
      body: JSON.stringify({ prompt }),
    });
  },

  /**
   * Evaluates prompt security and invokes target LLM only if ALLOWED.
   * If BLOCKED, target is never invoked.
   */
  async executePrompt(prompt: string): Promise<ExecuteResponse> {
    return requestJson<ExecuteResponse>('/api/v1/execute', {
      method: 'POST',
      body: JSON.stringify({ prompt }),
    });
  },

  /**
   * Evaluates context-aware multi-turn conversation security and invokes target LLM only if ALLOWED.
   * If BLOCKED or ERROR, halts immediately without invoking the target LLM.
   * Strictly enforces conversation sequence with allowed roles ('user', 'assistant').
   */
  async chat(
    messages: ChatMessage[],
    conversationId?: string,
    signal?: AbortSignal,
    token?: string
  ): Promise<ChatResponse> {
    const payload: ChatRequest = {
      messages,
      ...(conversationId ? { conversation_id: conversationId } : {}),
    };
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }

    return requestJson<ChatResponse>('/api/v1/chat', {
      method: 'POST',
      body: JSON.stringify(payload),
      signal,
      headers,
    });
  },

  /**
   * Retrieves list of persistent conversations stored in SQLite.
   */
  async listConversations(limit: number = 50): Promise<ConversationSummary[]> {
    return requestJson<ConversationSummary[]>(`/api/v1/chat/conversations?limit=${limit}`);
  },

  /**
   * Retrieves a specific conversation with all turns from SQLite.
   */
  async getConversation(conversationId: string): Promise<ConversationDetail> {
    return requestJson<ConversationDetail>(`/api/v1/chat/conversations/${encodeURIComponent(conversationId)}`);
  },

  /**
   * Deletes a conversation and its turns from SQLite.
   */
  async deleteConversation(conversationId: string): Promise<{ success: boolean; conversation_id: string }> {
    return requestJson<{ success: boolean; conversation_id: string }>(
      `/api/v1/chat/conversations/${encodeURIComponent(conversationId)}`,
      { method: 'DELETE' }
    );
  },

  /* =========================================================================
     Agent Security v0.3 APIs (Tools & Approvals)
     ========================================================================= */

  /**
   * Submits a tool call proposal to evaluate risk and create an approval request if required.
   * Low-risk tools return ALLOW (approval_status: NOT_REQUIRED).
   * High-risk/critical tools return PENDING_APPROVAL with cryptographic approval_id.
   * Blocked tools return BLOCK.
   */
  async createApproval(
    payload: ApprovalCreateRequest,
    token?: string,
    signal?: AbortSignal
  ): Promise<ApprovalCreateResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<ApprovalCreateResponse>('/api/v1/approvals', {
      method: 'POST',
      body: JSON.stringify(payload),
      headers,
      signal,
    });
  },

  /**
   * Inspects safe approval status, TTL, and telemetry.
   * Never exposes raw sensitive arguments or protected secrets.
   */
  async getApproval(
    approvalId: string,
    token?: string,
    signal?: AbortSignal
  ): Promise<ApprovalDetailResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<ApprovalDetailResponse>(`/api/v1/approvals/${encodeURIComponent(approvalId)}`, {
      method: 'GET',
      headers,
      signal,
    });
  },

  /**
   * Explicitly approves and executes the action exactly once.
   * Transitions PENDING_APPROVAL -> APPROVED -> CONSUMED.
   * Replay attempts reject with 409 Conflict.
   */
  async approve(
    approvalId: string,
    token?: string,
    signal?: AbortSignal
  ): Promise<ApprovalActionResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<ApprovalActionResponse>(`/api/v1/approvals/${encodeURIComponent(approvalId)}/approve`, {
      method: 'POST',
      headers,
      signal,
    });
  },

  /**
   * Explicitly denies an approval request.
   * Transitions to DENIED. The tool is guaranteed to never execute.
   */
  async deny(
    approvalId: string,
    token?: string,
    signal?: AbortSignal
  ): Promise<ApprovalActionResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<ApprovalActionResponse>(`/api/v1/approvals/${encodeURIComponent(approvalId)}/deny`, {
      method: 'POST',
      headers,
      signal,
    });
  },

  /**
   * Executes a tool via the AgentGuard Tool Authorization Gate.
   * Evaluates arguments for prompt injection and checks policy.
   * If approval_id is supplied, validates action binding and one-time use.
   * If BLOCKED or ERROR, the tool executor is NEVER called and result is null.
   */
  async executeTool(
    payload: ToolCallRequest,
    token?: string,
    signal?: AbortSignal
  ): Promise<ToolCallResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<ToolCallResponse>('/api/v1/tool/execute', {
      method: 'POST',
      body: JSON.stringify(payload),
      headers,
      signal,
    });
  },

  /**
   * Retrieves comprehensive backend readiness status (v0.4).
   * Checks Ollama connection, guard/target models, and security subsystems.
   */
  async getReady(signal?: AbortSignal): Promise<ReadyResponse> {
    return requestJson<ReadyResponse>('/ready', {
      method: 'GET',
      signal,
    });
  },

  /**
   * Retrieves runtime in-process metrics counters (v0.4).
   * Note: Process-level memory counters, not persisted analytics.
   */
  async getMetrics(signal?: AbortSignal): Promise<RuntimeMetricsResponse> {
    return requestJson<RuntimeMetricsResponse>('/metrics', {
      method: 'GET',
      signal,
    });
  },

  /**
   * Queries persisted security audit events (v0.4 & v0.5).
   * Authenticated by caller principal/tenant. Never leaks raw prompts.
   */
  async getAuditEvents(
    params?: AuditQueryParams,
    token?: string,
    signal?: AbortSignal
  ): Promise<AuditListResponse> {
    const searchParams = new URLSearchParams();
    if (params?.request_id) searchParams.set('request_id', params.request_id);
    if (params?.principal_id) searchParams.set('principal_id', params.principal_id);
    if (params?.tenant_id) searchParams.set('tenant_id', params.tenant_id);
    if (params?.action) searchParams.set('action', params.action);
    if (params?.decision) searchParams.set('decision', params.decision);
    if (params?.resource_type) searchParams.set('resource_type', params.resource_type);
    if (params?.limit !== undefined) searchParams.set('limit', String(params.limit));
    if (params?.offset !== undefined) searchParams.set('offset', String(params.offset));
    if (params?.start_time !== undefined) searchParams.set('start_time', String(params.start_time));
    if (params?.end_time !== undefined) searchParams.set('end_time', String(params.end_time));

    const queryString = searchParams.toString();
    const path = `/api/v1/audit/events${queryString ? `?${queryString}` : ''}`;

    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }

    return requestJson<AuditListResponse>(path, {
      method: 'GET',
      headers,
      signal,
    });
  },

  /**
   * Lists stored approval records for inspection (v0.4).
   */
  async listApprovals(
    token?: string,
    signal?: AbortSignal
  ): Promise<ApprovalDetailResponse[]> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<ApprovalDetailResponse[]>('/api/v1/approvals', {
      method: 'GET',
      headers,
      signal,
    });
  },

  /* =========================================================================
     Administration & Audit API Methods (v0.5)
     ========================================================================= */

  // -------------------------------------------------------------------------
  // Tenants Administration
  // -------------------------------------------------------------------------
  async listTenants(
    token?: string,
    signal?: AbortSignal
  ): Promise<TenantListResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<TenantListResponse>('/api/v1/tenants', {
      method: 'GET',
      headers,
      signal,
    });
  },

  async getTenant(
    tenantId: string,
    token?: string,
    signal?: AbortSignal
  ): Promise<TenantResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<TenantResponse>(`/api/v1/tenants/${encodeURIComponent(tenantId)}`, {
      method: 'GET',
      headers,
      signal,
    });
  },

  async createTenant(
    payload: TenantCreateRequest,
    token?: string,
    signal?: AbortSignal
  ): Promise<TenantResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<TenantResponse>('/api/v1/tenants', {
      method: 'POST',
      body: JSON.stringify(payload),
      headers,
      signal,
    });
  },

  async updateTenant(
    tenantId: string,
    payload: TenantUpdateRequest,
    token?: string,
    signal?: AbortSignal
  ): Promise<TenantResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<TenantResponse>(`/api/v1/tenants/${encodeURIComponent(tenantId)}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
      headers,
      signal,
    });
  },

  async disableTenant(
    tenantId: string,
    token?: string,
    signal?: AbortSignal
  ): Promise<TenantResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<TenantResponse>(`/api/v1/tenants/${encodeURIComponent(tenantId)}/disable`, {
      method: 'POST',
      headers,
      signal,
    });
  },

  async enableTenant(
    tenantId: string,
    token?: string,
    signal?: AbortSignal
  ): Promise<TenantResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<TenantResponse>(`/api/v1/tenants/${encodeURIComponent(tenantId)}/enable`, {
      method: 'POST',
      headers,
      signal,
    });
  },

  // -------------------------------------------------------------------------
  // Principals / Identities Administration
  // -------------------------------------------------------------------------
  async listPrincipals(
    tenantId?: string,
    token?: string,
    signal?: AbortSignal
  ): Promise<PrincipalListResponse> {
    const searchParams = new URLSearchParams();
    if (tenantId) searchParams.set('tenant_id', tenantId);
    const queryString = searchParams.toString();
    const path = `/api/v1/principals${queryString ? `?${queryString}` : ''}`;

    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<PrincipalListResponse>(path, {
      method: 'GET',
      headers,
      signal,
    });
  },

  async getPrincipal(
    principalId: string,
    token?: string,
    signal?: AbortSignal
  ): Promise<PrincipalResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<PrincipalResponse>(`/api/v1/principals/${encodeURIComponent(principalId)}`, {
      method: 'GET',
      headers,
      signal,
    });
  },

  async createPrincipal(
    payload: PrincipalCreateRequest,
    token?: string,
    signal?: AbortSignal
  ): Promise<PrincipalResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<PrincipalResponse>('/api/v1/principals', {
      method: 'POST',
      body: JSON.stringify(payload),
      headers,
      signal,
    });
  },

  async updatePrincipal(
    principalId: string,
    payload: PrincipalUpdateRequest,
    token?: string,
    signal?: AbortSignal
  ): Promise<PrincipalResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<PrincipalResponse>(`/api/v1/principals/${encodeURIComponent(principalId)}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
      headers,
      signal,
    });
  },

  async disablePrincipal(
    principalId: string,
    token?: string,
    signal?: AbortSignal
  ): Promise<PrincipalResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<PrincipalResponse>(`/api/v1/principals/${encodeURIComponent(principalId)}/disable`, {
      method: 'POST',
      headers,
      signal,
    });
  },

  async enablePrincipal(
    principalId: string,
    token?: string,
    signal?: AbortSignal
  ): Promise<PrincipalResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<PrincipalResponse>(`/api/v1/principals/${encodeURIComponent(principalId)}/enable`, {
      method: 'POST',
      headers,
      signal,
    });
  },

  // -------------------------------------------------------------------------
  // Credentials Administration
  // -------------------------------------------------------------------------
  async listCredentials(
    principalId?: string,
    token?: string,
    signal?: AbortSignal
  ): Promise<CredentialListResponse> {
    const searchParams = new URLSearchParams();
    if (principalId) searchParams.set('principal_id', principalId);
    const queryString = searchParams.toString();
    const path = `/api/v1/credentials${queryString ? `?${queryString}` : ''}`;

    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<CredentialListResponse>(path, {
      method: 'GET',
      headers,
      signal,
    });
  },

  async getCredential(
    credentialId: string,
    token?: string,
    signal?: AbortSignal
  ): Promise<CredentialResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<CredentialResponse>(`/api/v1/credentials/${encodeURIComponent(credentialId)}`, {
      method: 'GET',
      headers,
      signal,
    });
  },

  async createCredential(
    payload: CredentialCreateRequest,
    token?: string,
    signal?: AbortSignal
  ): Promise<CredentialCreatedResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<CredentialCreatedResponse>('/api/v1/credentials', {
      method: 'POST',
      body: JSON.stringify(payload),
      headers,
      signal,
    });
  },

  async revokeCredential(
    credentialId: string,
    token?: string,
    signal?: AbortSignal
  ): Promise<CredentialResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<CredentialResponse>(`/api/v1/credentials/${encodeURIComponent(credentialId)}/revoke`, {
      method: 'POST',
      headers,
      signal,
    });
  },

  async rotateCredential(
    credentialId: string,
    token?: string,
    signal?: AbortSignal
  ): Promise<CredentialRotateResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<CredentialRotateResponse>(`/api/v1/credentials/${encodeURIComponent(credentialId)}/rotate`, {
      method: 'POST',
      headers,
      signal,
    });
  },

  // -------------------------------------------------------------------------
  // Policies Administration
  // -------------------------------------------------------------------------
  async listPolicies(
    includeDisabled: boolean = true,
    token?: string,
    signal?: AbortSignal
  ): Promise<PolicyListResponse> {
    const path = `/api/v1/policies?include_disabled=${includeDisabled}`;
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<PolicyListResponse>(path, {
      method: 'GET',
      headers,
      signal,
    });
  },

  async getPolicy(
    policyId: string,
    token?: string,
    signal?: AbortSignal
  ): Promise<PolicyResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<PolicyResponse>(`/api/v1/policies/${encodeURIComponent(policyId)}`, {
      method: 'GET',
      headers,
      signal,
    });
  },

  async createPolicy(
    payload: PolicyCreateRequest,
    token?: string,
    signal?: AbortSignal
  ): Promise<PolicyResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<PolicyResponse>('/api/v1/policies', {
      method: 'POST',
      body: JSON.stringify(payload),
      headers,
      signal,
    });
  },

  async updatePolicy(
    policyId: string,
    payload: PolicyUpdateRequest,
    token?: string,
    signal?: AbortSignal
  ): Promise<PolicyResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<PolicyResponse>(`/api/v1/policies/${encodeURIComponent(policyId)}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
      headers,
      signal,
    });
  },

  async deletePolicy(
    policyId: string,
    token?: string,
    signal?: AbortSignal
  ): Promise<PolicyDeleteResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<PolicyDeleteResponse>(`/api/v1/policies/${encodeURIComponent(policyId)}`, {
      method: 'DELETE',
      headers,
      signal,
    });
  },

  // -------------------------------------------------------------------------
  // Cryptographic Audit Verification
  // -------------------------------------------------------------------------
  async verifyAuditChain(
    token?: string,
    signal?: AbortSignal
  ): Promise<AuditVerifyResponse> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<AuditVerifyResponse>('/api/v1/audit/verify', {
      method: 'GET',
      headers,
      signal,
    });
  },

  // -------------------------------------------------------------------------
  // Live SOC Dashboard Telemetry & Simulation
  // -------------------------------------------------------------------------
  async getSecOpsOverview(
    token?: string,
    signal?: AbortSignal
  ): Promise<any> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<any>('/api/v1/secops/overview', {
      method: 'GET',
      headers,
      signal,
    });
  },

  async simulateApproval(
    toolName?: string,
    riskLevel?: string,
    token?: string
  ): Promise<any> {
    const headers: Record<string, string> = {};
    if (token && token.trim()) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }
    return requestJson<any>('/api/v1/approvals/simulate', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        tool_name: toolName || 'send_email',
        risk_level: riskLevel || 'high',
      }),
    });
  },
};

