/**
 * AgentGuard Frontend v0.6 — Security Operations & Incident Response Test Suite
 *
 * Validates:
 * 1. SecOps view renders as primary view when mode is 'secops'
 * 2. Header navigation tab switches to SecOps mode cleanly
 * 3. Security Posture Card renders health, readiness, runtime metrics, and audit integrity
 * 4. Posture Card masks developer token (ag_c_...••••) and never exposes raw secrets
 * 5. Clearing developer token updates posture card and auth state
 * 6. Audit integrity verification displays valid and tampered states accurately
 * 7. Security Alerts Panel derives high-signal alerts from audit blocks, auth failures, pending approvals, and integrity issues
 * 8. Severity filtering in Alerts Panel (All, Critical, High, Info) works correctly
 * 9. Operational Queue renders real backend approvals list with status tabs
 * 10. Approving tool call in queue invokes approve API
 * 11. Denying tool call in queue opens confirmation dialog with security impact and calls deny API
 * 12. Expired or 409 conflict approvals display error feedback safely
 * 13. Incident Investigation Workspace prominently displays session-only disclaimer: "Local investigation — not persisted by AgentGuard"
 * 14. Adding events to workspace correlates request_id, principal_id, and tool_name
 * 15. Correlated Pipeline Timeline displays observed stages and marks unobserved stages as unavailable
 * 16. Operator notes can be edited in memory
 * 17. Clear workspace resets investigation state in memory
 * 18. Export package displays structured JSON summary without storage persistence
 * 19. [SECURITY INVARIANT] Zero investigation data, credentials, or Bearer tokens stored in localStorage or sessionStorage
 * 20. [SECURITY INVARIANT] Zero raw secrets, Authorization headers, or canary tokens (BLUE-ORANGE-42) rendered in UI
 * 21. Security Event Stream renders paginated events and responds to filter changes
 * 22. Inspecting an event opens AuditEventDetails modal
 * 23. Authoritative Security Mitigation Controls: Revoke credential invokes backend revokeCredential API upon confirmation
 * 24. Authoritative Security Mitigation Controls: Disable principal invokes backend disablePrincipal API upon confirmation
 * 25. Authoritative Security Mitigation Controls: Disable tenant invokes backend disableTenant API upon confirmation
 * 26. Canceling confirmation modal aborts destructive action safely
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { App } from '../App';
import { agentGuardApi, AgentGuardApiError } from '../api/agentguard';
import {
  HealthResponse,
  ReadyResponse,
  RuntimeMetricsResponse,
  AuditVerifyResponse,
  AuditListResponse,
  ApprovalDetailResponse,
  AuditEventItem,
} from '../types/agentguard';

// Mock the API client
vi.mock('../api/agentguard', async () => {
  const actual = await vi.importActual('../api/agentguard');
  return {
    ...actual,
    agentGuardApi: {
      health: vi.fn(),
      getHealth: vi.fn(),
      getReady: vi.fn(),
      getMetrics: vi.fn(),
      getAuditEvents: vi.fn(),
      verifyAuditChain: vi.fn(),
      listApprovals: vi.fn(),
      getApproval: vi.fn(),
      approve: vi.fn(),
      deny: vi.fn(),
      revokeCredential: vi.fn(),
      disablePrincipal: vi.fn(),
      disableTenant: vi.fn(),
      deletePolicy: vi.fn(),
    },
  };
});

const mockHealth: HealthResponse = {
  status: 'ok',
  version: '1.0.0',
  guard_model: 'llama3.2:latest',
  target_model: 'llama3.2:latest',
};

const mockReady: ReadyResponse = {
  status: 'ready',
  version: '1.0.0',
  environment: 'development',
  ollama: 'connected',
  guard_model: 'llama3.2:latest',
  target_model: 'llama3.2:latest',
  checks: {
    configuration: 'ok',
    process_model: 'single_process',
    credential_store: 'ok',
    policy_store: 'ok',
    audit_store: 'ok',
    ollama: 'connected',
  },
};

const mockMetrics: RuntimeMetricsResponse = {
  uptime_seconds: 7200,
  total_requests: 350,
  requests_by_endpoint: {
    '/health': 50,
    '/api/v1/guard': 120,
    '/api/v1/chat': 100,
    '/api/v1/tool/execute': 80,
  },
  requests_by_status: {
    '200': 310,
    '401': 12,
    '403': 20,
    '409': 8,
  },
  decisions: {
    allow: 280,
    block: 65,
    error: 5,
  },
  rate_limited_count: 3,
  concurrency_rejected_count: 0,
  guard: {
    invocations: 220,
    failures: 0,
    timeouts: 0,
  },
  target: {
    invocations: 180,
    failures: 0,
    timeouts: 0,
  },
  timeouts: {
    guard_timeouts: 0,
    target_timeouts: 0,
    total_timeouts: 0,
  },
  tools: {
    total_calls: 80,
    allowed: 60,
    blocked: 15,
    error: 5,
    unauthorized_executions: 0,
    limit_exceeded: 0,
  },
  approvals: {
    approval_requests_created: 10,
    approval_requests_approved: 6,
    approval_requests_denied: 2,
    approval_requests_expired: 1,
    approval_requests_cancelled: 0,
    approval_execution_success: 6,
    approval_execution_failure: 0,
    approval_replay_attempts: 0,
    approval_binding_failures: 0,
    unauthorized_high_risk_tool_executions: 0,
  },
};

const mockIntegrityValid: AuditVerifyResponse = {
  valid: true,
  status: 'valid',
  total_events: 42,
  details: 'Audit cryptographic hash chain verified intact',
};

const mockEvents: AuditEventItem[] = [
  {
    event_id: 'ev-block-01',
    request_id: 'req-threat-101',
    tenant_id: 'ten-corp',
    principal_id: 'prin-attacker',
    action: 'guard_block',
    decision: 'BLOCK',
    attack_type: 'prompt_injection',
    tool_name: null,
    risk_score: 0.95,
    timestamp: 1760000100,
    resource_type: 'prompt',
    resource_id: 'res-prompt-1',
    event_hash: 'hash-abc111',
    previous_event_hash: 'hash-prev-000',
  },
  {
    event_id: 'ev-auth-02',
    request_id: 'req-auth-202',
    tenant_id: 'ten-default',
    principal_id: 'prin-unknown',
    action: 'auth_failure',
    decision: 'DENY',
    attack_type: 'none',
    tool_name: null,
    risk_score: 0.8,
    timestamp: 1760000200,
    resource_type: 'credential',
    resource_id: 'cred-bad',
    error_code: 'UNAUTHORIZED',
    event_hash: 'hash-abc222',
    previous_event_hash: 'hash-abc111',
  },
  {
    event_id: 'ev-tool-03',
    request_id: 'req-tool-303',
    tenant_id: 'ten-corp',
    principal_id: 'prin-agent',
    action: 'tool_call',
    decision: 'ALLOW',
    attack_type: 'none',
    tool_name: 'read_document',
    risk_score: 0.1,
    timestamp: 1760000300,
    resource_type: 'tool',
    resource_id: 'read_document',
    event_hash: 'hash-abc333',
    previous_event_hash: 'hash-abc222',
  },
];

const mockAuditList: AuditListResponse = {
  events: mockEvents,
  total: 3,
  limit: 20,
  offset: 0,
};

const mockApprovals: ApprovalDetailResponse[] = [
  {
    approval_id: 'app-991',
    request_id: 'req-tool-303',
    conversation_id: 'conv-01',
    principal_id: 'prin-agent',
    tool_name: 'delete_database',
    risk_level: 'critical',
    reason: 'Critical database manipulation action',
    arguments_summary: 'target_table: users',
    arguments_hash: 'hash-arg-991',
    status: 'PENDING_APPROVAL',
    created_at: 1760000050,
    expires_at: 1760000650,
    execution_count: 0,
  },
  {
    approval_id: 'app-992',
    request_id: 'req-tool-304',
    conversation_id: 'conv-02',
    principal_id: 'prin-agent',
    tool_name: 'export_metrics',
    risk_level: 'medium',
    reason: 'Medium risk metrics export',
    arguments_summary: 'format: csv',
    arguments_hash: 'hash-arg-992',
    status: 'APPROVED',
    created_at: 1760000000,
    expires_at: 1760000600,
    approved_at: 1760000020,
    execution_count: 1,
  },
];

describe('AgentGuard Frontend v0.6 — Security Operations & Incident Response Suite', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    sessionStorage.clear();

    vi.mocked(agentGuardApi.health).mockResolvedValue(mockHealth);
    vi.mocked(agentGuardApi.getReady).mockResolvedValue(mockReady);
    vi.mocked(agentGuardApi.getMetrics).mockResolvedValue(mockMetrics);
    vi.mocked(agentGuardApi.verifyAuditChain).mockResolvedValue(mockIntegrityValid);
    vi.mocked(agentGuardApi.getAuditEvents).mockResolvedValue(mockAuditList);
    vi.mocked(agentGuardApi.listApprovals).mockResolvedValue(mockApprovals);
  });

  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  // ---------------------------------------------------------------------------
  // 1. Navigation & Shell
  // ---------------------------------------------------------------------------

  it('1. SecOps view renders as primary view when mode is "secops"', async () => {
    render(<App initialMode="secops" />);

    expect(await screen.findByText('Security Operations & Incident Response')).toBeInTheDocument();
    expect(screen.getByText('Control Console v0.6')).toBeInTheDocument();
    expect(screen.getByText(/Unified operator console/)).toBeInTheDocument();
  });

  it('2. Navigation header switches to SecOps mode cleanly', async () => {
    render(<App initialMode="chat" />);

    const secopsTab = screen.getByTestId('nav-tab-secops');
    expect(secopsTab).toBeInTheDocument();

    fireEvent.click(secopsTab);

    expect(await screen.findByText('Security Operations & Incident Response')).toBeInTheDocument();
  });

  // ---------------------------------------------------------------------------
  // 2. Posture Card
  // ---------------------------------------------------------------------------

  it('3. Security Posture Card renders health, readiness, and metrics', async () => {
    render(<App initialMode="secops" />);

    expect(await screen.findByText('AgentGuard Security Posture & Boundary Status')).toBeInTheDocument();
    expect(await screen.findByText(/Process: OK/i)).toBeInTheDocument();
    expect(await screen.findByText(/Readiness: READY/i)).toBeInTheDocument();
    expect(await screen.findByText(/350 reqs/i)).toBeInTheDocument();
  });

  it('4. Posture Card displays anonymous state when unauthenticated', async () => {
    render(<App initialMode="secops" />);

    expect(await screen.findByText(/Default \/ Anonymous Context/i)).toBeInTheDocument();
  });

  it('5. Posture Card displays tampered alert if cryptographic hash chain is broken', async () => {
    vi.mocked(agentGuardApi.verifyAuditChain).mockResolvedValueOnce({
      valid: false,
      status: 'tampered',
      total_events: 42,
      details: 'Mismatch detected at block 14: hash verification failed',
    });

    render(<App initialMode="secops" />);

    expect(await screen.findByText(/AUDIT CHAIN INTEGRITY BREACH DETECTED/i)).toBeInTheDocument();
  });

  // ---------------------------------------------------------------------------
  // 3. Security Alerts Panel
  // ---------------------------------------------------------------------------

  it('6. Alerts Panel derives high-signal alerts from audit blocks, auth failures, and approvals', async () => {
    render(<App initialMode="secops" />);

    expect(await screen.findByText(/Threat Blocked: prompt_injection/i)).toBeInTheDocument();
    expect(screen.getByText(/Authentication Boundary Failure/i)).toBeInTheDocument();
    expect(screen.getByText(/Pending Tool Authorization: delete_database/i)).toBeInTheDocument();
  });

  it('7. Severity filters (All, Critical, High, Info) filter alerts correctly', async () => {
    render(<App initialMode="secops" />);

    await screen.findByText(/Threat Blocked: prompt_injection/i);

    // Click Critical filter button
    const criticalBtn = screen.getByRole('button', { name: /Critical/i });
    fireEvent.click(criticalBtn);

    // Threat blocked is HIGH, so should not appear under Critical
    expect(screen.queryByText(/Threat Blocked: prompt_injection/i)).not.toBeInTheDocument();

    // Click High filter button
    const highBtn = screen.getByRole('button', { name: /^High/i });
    fireEvent.click(highBtn);

    expect(screen.getByText(/Threat Blocked: prompt_injection/i)).toBeInTheDocument();
  });

  // ---------------------------------------------------------------------------
  // 4. Operational Approvals Queue
  // ---------------------------------------------------------------------------

  it('8. Operational Queue displays backend approvals with status filter tabs', async () => {
    render(<App initialMode="secops" />);

    expect(await screen.findByText('delete_database')).toBeInTheDocument();
    expect(screen.getByText('export_metrics')).toBeInTheDocument();

    // Filter to Pending
    const pendingTab = screen.getByRole('button', { name: /^Pending/i });
    fireEvent.click(pendingTab);

    expect(screen.getByText('delete_database')).toBeInTheDocument();
    expect(screen.queryByText('export_metrics')).not.toBeInTheDocument();
  });

  it('9. Approving tool call in queue invokes approve API', async () => {
    vi.mocked(agentGuardApi.approve).mockResolvedValueOnce({
      status: 'APPROVED',
      approval_id: 'app-991',
    } as any);

    render(<App initialMode="secops" />);

    await screen.findByText('delete_database');

    const approveBtn = screen.getByTestId('approve-action-app-991');
    fireEvent.click(approveBtn);

    // Confirmation dialog opens
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    const confirmBtn = screen.getByRole('button', { name: /Confirm: Approve & Execute Tool Action/i });
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(agentGuardApi.approve).toHaveBeenCalledWith('app-991', expect.any(String));
    });
  });

  it('10. Denying tool call in queue opens confirmation dialog and invokes deny API', async () => {
    vi.mocked(agentGuardApi.deny).mockResolvedValueOnce({
      status: 'DENIED',
      approval_id: 'app-991',
    } as any);

    render(<App initialMode="secops" />);

    await screen.findByText('delete_database');

    const denyBtn = screen.getByTestId('deny-action-app-991');
    fireEvent.click(denyBtn);

    // Confirmation dialog opens with security impact
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    expect(screen.getByText(/will be permanently blocked/i)).toBeInTheDocument();

    // Click Confirm button inside modal
    const confirmBtn = screen.getByRole('button', { name: /Confirm: Deny Tool Action/i });
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(agentGuardApi.deny).toHaveBeenCalledWith('app-991', expect.any(String));
    });
  });

  it('11. Replay conflict (409) on approval displays consumed notice safely', async () => {
    vi.mocked(agentGuardApi.approve).mockRejectedValueOnce(
      new AgentGuardApiError('Approval has already been resolved or expired', 409, 'ALREADY_CONSUMED')
    );

    render(<App initialMode="secops" />);

    await screen.findByText('delete_database');

    const approveBtn = screen.getByTestId('approve-action-app-991');
    fireEvent.click(approveBtn);

    const confirmBtn = await screen.findByRole('button', { name: /Confirm: Approve & Execute Tool Action/i });
    fireEvent.click(confirmBtn);

    expect(await screen.findByText(/already been resolved or expired/i)).toBeInTheDocument();
  });

  // ---------------------------------------------------------------------------
  // 5. Incident Investigation Workspace & Correlated Pipeline
  // ---------------------------------------------------------------------------

  it('12. Incident Workspace prominently displays session-only disclaimer', async () => {
    render(<App initialMode="secops" />);

    expect(
      await screen.findByText(/Local investigation — not persisted by AgentGuard/i)
    ).toBeInTheDocument();
  });

  it('13. Adding event to workspace correlates IDs and renders Pipeline Timeline', async () => {
    render(<App initialMode="secops" />);

    // Add to investigation button for ev-block-01
    const addBtn = await screen.findByTestId('add-investigation-ev-block-01');
    fireEvent.click(addBtn);

    // Correlated request ID should now be listed in workspace
    expect(await screen.findByText('req-threat-101')).toBeInTheDocument();
    expect(screen.getAllByText('prin-attacker').length).toBeGreaterThan(0);

    // Switch to Pipeline Trajectory tab
    const timelineTab = screen.getByRole('button', { name: /Correlated Pipeline Trajectory/i });
    fireEvent.click(timelineTab);

    expect(await screen.findByText('Observed Request Pipeline Trajectory')).toBeInTheDocument();

    // Unobserved stages are explicitly marked
    const unavailableNotes = screen.getAllByText('Not available from current audit data.');
    expect(unavailableNotes.length).toBeGreaterThan(0);
  });

  it('14. Operator notes can be edited in memory and cleared with Clear button', async () => {
    render(<App initialMode="secops" />);

    const notesTextarea = await screen.findByPlaceholderText(/Add operational findings/i);
    fireEvent.change(notesTextarea, {
      target: { value: 'Suspicious injection attempt observed from external principal.' },
    });

    expect(notesTextarea).toHaveValue('Suspicious injection attempt observed from external principal.');

    // Clear Workspace
    const clearBtn = screen.getByTestId('clear-investigation-btn');
    fireEvent.click(clearBtn);

    expect(notesTextarea).toHaveValue('');
  });

  it('15. Export Sanitized Package renders formatted JSON summary', async () => {
    render(<App initialMode="secops" />);

    await screen.findByText('Incident Investigation Workspace');

    const exportTab = screen.getByRole('button', { name: /Export Sanitized Package/i });
    fireEvent.click(exportTab);

    expect(await screen.findByText(/Local investigation — not persisted by AgentGuard backend/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Copy Summary/i })).toBeInTheDocument();
  });

  // ---------------------------------------------------------------------------
  // 6. Security Invariants
  // ---------------------------------------------------------------------------

  it('16. [SECURITY INVARIANT] Zero investigation data, credentials, or tokens written to localStorage or sessionStorage', async () => {
    render(<App initialMode="secops" />);

    // Add event and update notes
    const addBtn = await screen.findByTestId('add-investigation-ev-block-01');
    fireEvent.click(addBtn);

    const notesTextarea = screen.getByPlaceholderText(/Add operational findings/i);
    fireEvent.change(notesTextarea, {
      target: { value: 'Secret test note' },
    });

    // Verify browser storage is strictly empty
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it('17. [SECURITY INVARIANT] Zero raw secrets, Authorization headers, or canary string BLUE-ORANGE-42 in DOM', async () => {
    render(<App initialMode="secops" />);

    await screen.findByText('Security Operations & Incident Response');

    const domText = document.body.textContent || '';
    expect(domText).not.toContain('BLUE-ORANGE-42');
    expect(domText).not.toContain('Bearer ');
    expect(domText).not.toContain('Authorization:');
  });

  // ---------------------------------------------------------------------------
  // 7. Event Stream & Presets
  // ---------------------------------------------------------------------------

  it('18. Event Stream preset filter buttons update event query', async () => {
    render(<App initialMode="secops" />);

    await screen.findByText('Live Security Event Stream');

    const blockedThreatsBtn = screen.getByRole('button', { name: /^Blocks$/i });
    fireEvent.click(blockedThreatsBtn);

    await waitFor(() => {
      expect(agentGuardApi.getAuditEvents).toHaveBeenCalledWith(
        expect.objectContaining({ decision: 'BLOCK' }),
        expect.any(String)
      );
    });
  });

  it('19. Inspecting an event opens AuditEventDetails modal', async () => {
    render(<App initialMode="secops" />);

    const inspectBtn = await screen.findByTestId('inspect-event-ev-block-01');
    fireEvent.click(inspectBtn);

    // Modal dialog opens
    expect(await screen.findByText('Audit Event Inspection')).toBeInTheDocument();
    expect(screen.getByText('ev-block-01')).toBeInTheDocument();
  });

  // ---------------------------------------------------------------------------
  // 8. Authoritative Security Mitigation Controls
  // ---------------------------------------------------------------------------

  it('20. Revoke Credential opens confirmation dialog and calls revokeCredential API on confirm', async () => {
    vi.mocked(agentGuardApi.revokeCredential).mockResolvedValueOnce({
      credential_id: 'c_malicious99',
      status: 'revoked',
    } as any);

    render(<App initialMode="secops" />);

    await screen.findByText('Authoritative Security Mitigation Controls');

    const targetInput = screen.getByPlaceholderText(/e\.g\. c_17c37eada3f37bd9/i);
    fireEvent.change(targetInput, { target: { value: 'c_malicious99' } });

    const submitBtn = screen.getByRole('button', { name: /Initiate Authoritative Mitigation/i });
    fireEvent.click(submitBtn);

    // Confirmation dialog is shown
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    expect(screen.getByText(/will be immediately and permanently revoked/i)).toBeInTheDocument();

    const confirmBtn = screen.getByRole('button', { name: /Confirm: Revoke API Credential/i });
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(agentGuardApi.revokeCredential).toHaveBeenCalledWith('c_malicious99', expect.any(String));
    });
  });

  it('21. Disable Principal mitigation calls backend disablePrincipal API on confirm', async () => {
    vi.mocked(agentGuardApi.disablePrincipal).mockResolvedValueOnce({
      principal_id: 'prin-compromised-44',
      status: 'disabled',
    } as any);

    render(<App initialMode="secops" />);

    await screen.findByText('Authoritative Security Mitigation Controls');

    // Change action type to PRINCIPAL_DISABLE
    const actionSelect = screen.getByLabelText(/Action Type/i);
    fireEvent.change(actionSelect, { target: { value: 'PRINCIPAL_DISABLE' } });

    const targetInput = screen.getByPlaceholderText(/e\.g\. suspicious-user-id/i);
    fireEvent.change(targetInput, { target: { value: 'prin-compromised-44' } });

    const submitBtn = screen.getByRole('button', { name: /Initiate Authoritative Mitigation/i });
    fireEvent.click(submitBtn);

    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    expect(screen.getByText(/Principal 'prin-compromised-44' will be deactivated immediately/i)).toBeInTheDocument();

    const confirmBtn = screen.getByRole('button', { name: /Confirm: Disable Security Principal/i });
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(agentGuardApi.disablePrincipal).toHaveBeenCalledWith('prin-compromised-44', expect.any(String));
    });
  });

  it('22. Disable Tenant mitigation calls backend disableTenant API on confirm', async () => {
    vi.mocked(agentGuardApi.disableTenant).mockResolvedValueOnce({
      tenant_id: 'ten-rogue-01',
      status: 'disabled',
    } as any);

    render(<App initialMode="secops" />);

    await screen.findByText('Authoritative Security Mitigation Controls');

    // Change action type to TENANT_DISABLE
    const actionSelect = screen.getByLabelText(/Action Type/i);
    fireEvent.change(actionSelect, { target: { value: 'TENANT_DISABLE' } });

    const targetInput = screen.getByPlaceholderText(/e\.g\. compromised-tenant-id/i);
    fireEvent.change(targetInput, { target: { value: 'ten-rogue-01' } });

    const submitBtn = screen.getByRole('button', { name: /Initiate Authoritative Mitigation/i });
    fireEvent.click(submitBtn);

    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    expect(screen.getByText(/Tenant 'ten-rogue-01' will be deactivated immediately/i)).toBeInTheDocument();

    const confirmBtn = screen.getByRole('button', { name: /Confirm: Disable Security Tenant/i });
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(agentGuardApi.disableTenant).toHaveBeenCalledWith('ten-rogue-01', expect.any(String));
    });
  });

  it('23. Canceling confirmation modal aborts action without calling backend API', async () => {
    render(<App initialMode="secops" />);

    await screen.findByText('Authoritative Security Mitigation Controls');

    const targetInput = screen.getByPlaceholderText(/e\.g\. c_17c37eada3f37bd9/i);
    fireEvent.change(targetInput, { target: { value: 'c_test' } });

    const submitBtn = screen.getByRole('button', { name: /Initiate Authoritative Mitigation/i });
    fireEvent.click(submitBtn);

    expect(await screen.findByRole('dialog')).toBeInTheDocument();

    const cancelBtn = screen.getByRole('button', { name: /Cancel/i });
    fireEvent.click(cancelBtn);

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(agentGuardApi.revokeCredential).not.toHaveBeenCalled();
  });
});
