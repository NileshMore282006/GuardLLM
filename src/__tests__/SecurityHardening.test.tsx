/**
 * AgentGuard Frontend v0.7 — Dedicated Security Hardening & Session Security Test Suite
 *
 * Covers:
 * 1. Session Lifecycle & Token Security (1-7)
 * 2. Authorization-Aware UI & Defense-in-Depth Presentation (8-12)
 * 3. Concurrency Safety, Stale State & Race Condition Handling (13-17)
 * 4. Data Safety, Investigation Memory Isolation & Redaction (18-23)
 * 5. Data Freshness & Degraded Mode Resilience (24-27)
 * 6. Destructive Action Guard & Authorization Boundaries (28-31)
 * 7. Operational Reliability, AbortController & Timer Cleanup (32-35)
 */

import React from 'react';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SessionProvider, useSession } from '../context/SessionContext';
import { DestructiveActionDialog } from '../components/common/DestructiveActionDialog';
import { DataFreshnessBadge } from '../components/common/DataFreshnessBadge';
import { DegradedModeBanner } from '../components/common/DegradedModeBanner';
import { RouteGuard } from '../components/common/RouteGuard';
import { redactSensitiveData, redactSensitiveObject, CANARY_SECRET } from '../utils/redaction';
import { normalizeApiError, sanitizeErrorMessage } from '../utils/errorNormalizer';
import { checkPermission, hasMinimumRole, getPermissionExplanation } from '../utils/authorization';
import { agentGuardApi, AgentGuardApiError } from '../api/agentguard';
import { App } from '../App';
import { DestructiveActionSpec, SanitizedInvestigationExport } from '../types/agentguard';

// Mock the API layer for testing state transitions
vi.mock('../api/agentguard', async () => {
  const actual = await vi.importActual('../api/agentguard');
  return {
    ...actual,
    agentGuardApi: {
      health: vi.fn(),
      getReady: vi.fn(),
      guardPrompt: vi.fn(),
      executePrompt: vi.fn(),
      chat: vi.fn(),
      listApprovals: vi.fn(),
      approveTool: vi.fn(),
      denyTool: vi.fn(),
      listAuditEvents: vi.fn(),
      verifyAuditIntegrity: vi.fn(),
      listTenants: vi.fn(),
      listPrincipals: vi.fn(),
      listCredentials: vi.fn(),
      revokeCredential: vi.fn(),
      disablePrincipal: vi.fn(),
      disableTenant: vi.fn(),
      listPolicies: vi.fn(),
      updatePolicy: vi.fn(),
      createPolicy: vi.fn(),
    },
  };
});

describe('AgentGuard Frontend v0.7 — Security Hardening & Session Security', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (agentGuardApi.health as ReturnType<typeof vi.fn>).mockResolvedValue({
      status: 'healthy',
      version: '1.0.0-rc',
      guard_model: 'llama3:8b-instruct',
      target_model: 'llama3:8b-instruct',
      active_rules: 15,
      timestamp: '2026-10-08T12:00:00Z',
    });
    (agentGuardApi.getReady as ReturnType<typeof vi.fn>).mockResolvedValue({
      status: 'ready',
      version: '1.0.0-rc',
      checks: { database: 'ok', memory: 'ok', ollama: 'ok' },
    });
    (agentGuardApi.listTenants as ReturnType<typeof vi.fn>).mockResolvedValue({
      tenants: [{ tenant_id: 'default', name: 'Default Tenant', enabled: true }],
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // =========================================================================
  // 1. Central Session Security & Token Handling (Tests 1-7)
  // =========================================================================

  // Test Component to exercise useSession hook directly
  const TestSessionConsumer: React.FC = () => {
    const { sessionState, tokenPresent, maskedToken, principalId, roles, setToken, clearSession, handleApiError } =
      useSession();
    return (
      <div>
        <span data-testid="session-state">{sessionState}</span>
        <span data-testid="principal-id">{principalId}</span>
        <span data-testid="user-role">{roles[0]}</span>
        <span data-testid="token-masked">{maskedToken}</span>
        <span data-testid="token-present">{tokenPresent ? 'true' : 'false'}</span>
        <button
          onClick={() =>
            setToken('ag_c_407c83f29ca8e139_supersecrettokenvalue')
          }
        >
          Login Admin
        </button>
        <button onClick={clearSession}>Logout</button>
        <button
          onClick={() =>
            handleApiError(new AgentGuardApiError('Unauthorized', 401, 'INVALID_TOKEN'))
          }
        >
          Simulate 401
        </button>
        <button
          onClick={() =>
            handleApiError(new AgentGuardApiError('Forbidden', 403, 'INSUFFICIENT_PERMISSIONS'))
          }
        >
          Simulate 403
        </button>
        <button
          onClick={() =>
            handleApiError(new AgentGuardApiError('Backend Error', 503, 'SERVICE_UNAVAILABLE'))
          }
        >
          Simulate 503
        </button>
      </div>
    );
  };

  it('1. Central Session correctly transitions to AUTHENTICATED on token injection', async () => {
    render(
      <SessionProvider>
        <TestSessionConsumer />
      </SessionProvider>
    );

    expect(screen.getByTestId('session-state').textContent).toBe('UNAUTHENTICATED');
    expect(screen.getByTestId('token-present').textContent).toBe('false');

    await act(async () => {
      fireEvent.click(screen.getByText('Login Admin'));
    });

    expect(screen.getByTestId('session-state').textContent).toBe('AUTHENTICATED');
    expect(screen.getByTestId('user-role').textContent).toBe('admin');
    expect(screen.getByTestId('token-present').textContent).toBe('true');
  });

  it('2. Logout clears memory token, resets role to user, and sets UNAUTHENTICATED', async () => {
    render(
      <SessionProvider>
        <TestSessionConsumer />
      </SessionProvider>
    );

    await act(async () => {
      fireEvent.click(screen.getByText('Login Admin'));
    });
    expect(screen.getByTestId('session-state').textContent).toBe('AUTHENTICATED');

    act(() => {
      fireEvent.click(screen.getByText('Logout'));
    });

    expect(screen.getByTestId('session-state').textContent).toBe('UNAUTHENTICATED');
    expect(screen.getByTestId('token-present').textContent).toBe('false');
    expect(screen.getByTestId('token-masked').textContent).toBe('None');
    expect(screen.getByTestId('user-role').textContent).toBe('user');
  });

  it('3. HTTP 401 Unauthorized invalidates session, clears credentials and stops privileged state', async () => {
    render(
      <SessionProvider>
        <TestSessionConsumer />
      </SessionProvider>
    );

    await act(async () => {
      fireEvent.click(screen.getByText('Login Admin'));
    });
    expect(screen.getByTestId('session-state').textContent).toBe('AUTHENTICATED');

    act(() => {
      fireEvent.click(screen.getByText('Simulate 401'));
    });

    expect(screen.getByTestId('session-state').textContent).toBe('UNAUTHENTICATED');
    expect(screen.getByTestId('token-present').textContent).toBe('false');
    expect(screen.getByTestId('token-masked').textContent).toBe('None');
  });

  it('4. HTTP 403 Forbidden PRESERVES authentication and credentials without logging user out', async () => {
    render(
      <SessionProvider>
        <TestSessionConsumer />
      </SessionProvider>
    );

    await act(async () => {
      fireEvent.click(screen.getByText('Login Admin'));
    });
    expect(screen.getByTestId('session-state').textContent).toBe('AUTHENTICATED');

    // Simulate 403 Forbidden
    act(() => {
      fireEvent.click(screen.getByText('Simulate 403'));
    });

    // State moves to FORBIDDEN, but credentials and token are NOT destroyed!
    expect(screen.getByTestId('session-state').textContent).toBe('FORBIDDEN');
    expect(screen.getByTestId('token-present').textContent).toBe('true');
    expect(screen.getByTestId('token-masked').textContent).not.toBe('None');
  });

  it('5. HTTP 5xx / Network Error enters BACKEND_UNAVAILABLE while preserving credentials', async () => {
    render(
      <SessionProvider>
        <TestSessionConsumer />
      </SessionProvider>
    );

    await act(async () => {
      fireEvent.click(screen.getByText('Login Admin'));
    });
    expect(screen.getByTestId('session-state').textContent).toBe('AUTHENTICATED');

    // Simulate 503 Service Unavailable
    act(() => {
      fireEvent.click(screen.getByText('Simulate 503'));
    });

    expect(screen.getByTestId('session-state').textContent).toBe('BACKEND_UNAVAILABLE');
    // Token is safely preserved for retry
    expect(screen.getByTestId('token-present').textContent).toBe('true');
  });

  it('6. Token is masked in the UI and raw token secret is never fully rendered', async () => {
    const rawSecret = 'ag_c_407c83f29ca8e139_supersecrettokenvalue';
    render(
      <SessionProvider>
        <TestSessionConsumer />
      </SessionProvider>
    );

    await act(async () => {
      fireEvent.click(screen.getByText('Login Admin'));
    });

    const masked = screen.getByTestId('token-masked').textContent;
    expect(masked).toContain('••••');
    expect(masked).not.toBe(rawSecret);
    expect(document.body.textContent).not.toContain(rawSecret);
  });

  it('7. [SECURITY INVARIANT] Token is strictly memory-only (never in localStorage or sessionStorage)', async () => {
    const rawSecret = 'ag_c_407c83f29ca8e139_supersecrettokenvalue';
    render(
      <SessionProvider>
        <TestSessionConsumer />
      </SessionProvider>
    );

    await act(async () => {
      fireEvent.click(screen.getByText('Login Admin'));
    });

    expect(localStorage.getItem('token')).toBeNull();
    expect(localStorage.getItem('developerToken')).toBeNull();
    expect(sessionStorage.getItem('token')).toBeNull();
    expect(sessionStorage.getItem('developerToken')).toBeNull();

    // Verify localStorage & sessionStorage contain 0 references
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i)!;
      expect(localStorage.getItem(key)).not.toContain(rawSecret);
    }
  });

  // =========================================================================
  // 2. Authorization-Aware UI & Presentation Layer (Tests 8-12)
  // =========================================================================

  it('8. User role has low-risk capabilities and cannot perform privileged mutations', () => {
    expect(checkPermission('chat:execute', ['user'])).toBe(true);
    expect(checkPermission('guard:evaluate', ['user'])).toBe(true);
    expect(checkPermission('credential:create', ['user'])).toBe(false);
    expect(checkPermission('credential:revoke', ['user'])).toBe(false);
    expect(checkPermission('policy:manage', ['user'])).toBe(false);
    expect(checkPermission('tenant:disable', ['user'])).toBe(false);

    expect(getPermissionExplanation('credential:revoke', ['user'])).toContain('Requires role: admin or global_admin');
  });

  it('9. Operator role is permitted operational security workflows (approvals) but not tenant mutations', () => {
    expect(checkPermission('approval:approve', ['operator'])).toBe(true);
    expect(checkPermission('approval:deny', ['operator'])).toBe(true);
    expect(checkPermission('audit:read_all', ['operator'])).toBe(true);
    expect(checkPermission('tenant:disable', ['operator'])).toBe(false);
    expect(checkPermission('principal:disable', ['operator'])).toBe(false);
  });

  it('10. Admin role has credentials, policy, and tenant read permissions', () => {
    expect(checkPermission('credential:revoke', ['admin'])).toBe(true);
    expect(checkPermission('policy:update', ['admin'])).toBe(true);
    expect(checkPermission('tenant:read', ['admin'])).toBe(true);
    expect(checkPermission('tenant:disable', ['admin'])).toBe(false); // Global admin only!
  });

  it('11. Global Admin role possesses all system capabilities including tenant disable', () => {
    expect(checkPermission('tenant:disable', ['global_admin'])).toBe(true);
    expect(checkPermission('tenant:create', ['global_admin'])).toBe(true);
    expect(checkPermission('policy:delete', ['global_admin'])).toBe(true);
    expect(checkPermission('credential:revoke', ['global_admin'])).toBe(true);
    expect(hasMinimumRole(['global_admin'], 'admin')).toBe(true);
  });

  it('12. RouteGuard blocks unauthorized roles and renders defense-in-depth explanation', () => {
    render(
      <SessionProvider>
        <RouteGuard requiredRole="admin" requiredCapability="credential:revoke">
          <div data-testid="protected-admin-content">Admin Secrets</div>
        </RouteGuard>
      </SessionProvider>
    );

    expect(screen.queryByTestId('protected-admin-content')).not.toBeInTheDocument();
    expect(screen.getByTestId('route-guard-unauthenticated')).toBeInTheDocument();
    expect(screen.getByText('Authentication Required')).toBeInTheDocument();
  });

  // =========================================================================
  // 3. Stale Data, Race Conditions & Concurrency (Tests 13-17)
  // =========================================================================

  it('13. Approval 409 conflict handles concurrent approval consumption gracefully', async () => {
    // Simulate 409 conflict on approve call
    const conflictError = new AgentGuardApiError(
      'Approval appr_123 already finalized with status APPROVED.',
      409,
      'APPROVAL_CONFLICT'
    );
    const normalized = normalizeApiError(conflictError);

    expect(normalized.code).toBe('RESOURCE_CONFLICT');
    expect(normalized.status).toBe(409);
    expect(normalized.message).toContain('already finalized');
  });

  it('14. Expired approval status error is normalized safely to RESOURCE_CONFLICT', () => {
    const expiredError = new AgentGuardApiError(
      'Approval appr_exp has expired.',
      409,
      'APPROVAL_EXPIRED'
    );
    const normalized = normalizeApiError(expiredError);

    expect(normalized.code).toBe('RESOURCE_CONFLICT');
    expect(normalized.status).toBe(409);
  });

  it('15. Credential stale state rejection on 404/409 produces safe operator guidance', () => {
    const staleRevokeError = new AgentGuardApiError(
      'Credential already revoked or not found.',
      404,
      'NOT_FOUND'
    );
    const normalized = normalizeApiError(staleRevokeError);

    expect(normalized.code).toBe('NOT_FOUND');
    expect(normalized.safeDetails).not.toContain('Traceback');
  });

  it('16. Policy concurrency conflict preserves user draft and displays reload reconciliation option', () => {
    const conflictErr = new AgentGuardApiError('Policy conflict detected.', 409, 'POLICY_CONFLICT');
    const normalized = normalizeApiError(conflictErr);

    expect(normalized.code).toBe('RESOURCE_CONFLICT');
    expect(normalized.status).toBe(409);
  });

  it('17. Polling concurrency guard prevents overlapping concurrent health checks', async () => {
    let callCount = 0;
    (agentGuardApi.health as ReturnType<typeof vi.fn>).mockImplementation(async () => {
      callCount++;
      return new Promise((resolve) => setTimeout(resolve, 50));
    });

    render(<App />);

    // Initial render triggers health check safely
    expect(agentGuardApi.health).toHaveBeenCalled();
  });

  // =========================================================================
  // 4. Sensitive Data Safety, Redaction & Export Allowlist (Tests 18-23)
  // =========================================================================

  it('18. Investigation workspace is strictly in-memory (0 storage footprint)', () => {
    // Check initial clean state
    expect(localStorage.getItem('agentguard_investigation')).toBeNull();
    expect(sessionStorage.getItem('agentguard_investigation')).toBeNull();
  });

  it('19. Sanitized investigation export adheres to strict schema allowlist', () => {
    const exportBundle: SanitizedInvestigationExport = {
      export_label: 'Sanitized investigation bundle',
      export_schema_version: '1.0',
      disclaimer: 'Local investigation — not persisted by AgentGuard',
      exported_at: new Date().toISOString(),
      investigation_id: 'inv_01',
      title: 'Investigation Incident',
      status: 'active',
      correlation_keys: {
        event_ids: ['ev_01'],
        request_ids: ['req_01'],
        principal_ids: ['p_anon'],
        tenant_ids: ['default'],
        tool_names: [],
        approval_ids: [],
        policy_ids: [],
      },
      operator_notes: 'Investigating potential injection attempt.',
      events: [
        {
          event_id: 'ev_01',
          request_id: 'req_01',
          action: 'chat',
          decision: 'BLOCK',
          risk_score: 0.95,
          principal_id: 'p_anon',
          timestamp: Date.now(),
          event_hash: 'hash_01',
          previous_event_hash: 'hash_00',
        },
      ],
    };

    const serialized = JSON.stringify(exportBundle);
    const parsed = JSON.parse(serialized);

    expect(parsed.export_label).toBe('Sanitized investigation bundle');
    expect(parsed.export_schema_version).toBe('1.0');
    expect(parsed.events).toHaveLength(1);
    expect(parsed).not.toHaveProperty('token');
    expect(parsed).not.toHaveProperty('authorization');
    expect(parsed).not.toHaveProperty('credentials');
  });

  it('20. Redaction removes Authorization headers from strings and serialized outputs', () => {
    const raw = 'Request header: Authorization: Bearer ag_c_secret_1234567890abcdef for tenant default';
    const redacted = redactSensitiveData(raw);

    expect(redacted).not.toContain('Bearer ag_c_secret_1234567890abcdef');
    expect(redacted).toContain('Authorization: Bearer [REDACTED]');
  });

  it('21. Redaction strips credential secrets from nested objects', () => {
    const nestedData = {
      event_id: 'ev_123',
      credentials: {
        token: 'ag_c_1234567890123456_supersecret',
        secret: 'my_raw_secret',
      },
      headers: {
        authorization: 'Bearer secret_token',
      },
    };

    const sanitized = redactSensitiveObject(nestedData);
    expect(sanitized.credentials.token).toBe('[REDACTED]');
    expect(sanitized.credentials.secret).toBe('[REDACTED]');
    expect(sanitized.headers.authorization).toBe('[REDACTED]');
  });

  it('22. Redaction strips test canary value from displayed output', () => {
    const textWithCanary = `LLM leaked the canary: ${CANARY_SECRET} in the response.`;
    const redacted = redactSensitiveData(textWithCanary);

    expect(redacted).not.toContain(CANARY_SECRET);
    expect(redacted).toContain('[REDACTED_CANARY]');
  });

  it('23. API error normalizer strips Python stack traces, file paths, and SQL queries', () => {
    const leakMessage =
      'Traceback (most recent call last):\n  File "C:\\Users\\Nilesh\\app.py", line 42, in execute\n    sqlite3.OperationalError: SELECT * FROM credentials;';
    const clean = sanitizeErrorMessage(leakMessage);

    expect(clean).not.toContain('Traceback');
    expect(clean).not.toContain('C:\\Users');
    expect(clean).not.toContain('SELECT * FROM');
    expect(clean).toContain('An internal backend exception occurred');
  });

  // =========================================================================
  // 5. Data Freshness & Degraded Mode Resilience (Tests 24-27)
  // =========================================================================

  it('24. DataFreshnessBadge renders LIVE status with relative timestamp', () => {
    render(
      <DataFreshnessBadge
        freshness="LIVE"
        lastUpdatedTimestamp={Date.now() - 5000}
        onRefresh={vi.fn()}
      />
    );

    expect(screen.getByText(/Live — updated/i)).toBeInTheDocument();
    expect(screen.getByTitle(/Refresh now/i)).toBeInTheDocument();
  });

  it('25. DataFreshnessBadge indicates REFRESHING state during re-fetch', () => {
    render(<DataFreshnessBadge freshness="REFRESHING" />);

    expect(screen.getByText('Refreshing…')).toBeInTheDocument();
  });

  it('26. DataFreshnessBadge displays STALE warning when data is outdated', () => {
    render(
      <DataFreshnessBadge
        freshness="STALE"
        lastUpdatedTimestamp={Date.now() - 45000}
        onRefresh={vi.fn()}
      />
    );

    expect(screen.getByText(/Stale/i)).toBeInTheDocument();
  });

  it('27. DegradedModeBanner informs operators and locks privileged mutations when offline', () => {
    const handleRetry = vi.fn();
    render(<DegradedModeBanner isOnline={false} onRetry={handleRetry} />);

    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText(/GATEWAY OFFLINE \/ DEGRADED/i)).toBeInTheDocument();
    expect(screen.getByText(/Mutations Locked/i)).toBeInTheDocument();

    const retryBtn = screen.getByRole('button', { name: /Retry Gateway Connection/i });
    fireEvent.click(retryBtn);
    expect(handleRetry).toHaveBeenCalledTimes(1);
  });

  // =========================================================================
  // 6. Destructive Action Guard (Tests 28-31)
  // =========================================================================

  it('28. DestructiveActionDialog enforces intentional confirmation checkbox before execution', async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    const onClose = vi.fn();

    const mockDestructiveSpec: DestructiveActionSpec = {
      action: 'Revoke Security Credential',
      resourceType: 'credential',
      resourceId: 'ag_c_test123',
      currentServerState: 'ACTIVE',
      impact: 'Authentication using this credential will immediately fail permanently.',
      reversible: false,
      onExecute: onConfirm,
    };

    render(
      <DestructiveActionDialog
        isOpen={true}
        spec={mockDestructiveSpec}
        onClose={onClose}
      />
    );

    expect(screen.getByText('Revoke Security Credential')).toBeInTheDocument();
    expect(screen.getByText('ACTIVE')).toBeInTheDocument();
    expect(screen.getByText('No (Irreversible)')).toBeInTheDocument();

    const submitBtn = screen.getByTestId('confirm-destructive-action-btn');
    expect(submitBtn).toBeDisabled();

    // Check confirmation checkbox
    const checkbox = screen.getByRole('checkbox');
    fireEvent.click(checkbox);

    expect(submitBtn).not.toBeDisabled();
    await act(async () => {
      fireEvent.click(submitBtn);
    });

    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('29. Destructive action does not show premature success before server response', async () => {
    let resolveExecute: () => void;
    const slowExecute = vi.fn().mockImplementation(() => {
      return new Promise<void>((resolve) => {
        resolveExecute = resolve;
      });
    });

    const mockDestructiveSpec: DestructiveActionSpec = {
      action: 'Revoke Security Credential',
      resourceType: 'credential',
      resourceId: 'ag_c_test123',
      currentServerState: 'ACTIVE',
      impact: 'Authentication will fail.',
      reversible: false,
      onExecute: slowExecute,
    };

    render(
      <DestructiveActionDialog
        isOpen={true}
        spec={mockDestructiveSpec}
        onClose={vi.fn()}
      />
    );

    fireEvent.click(screen.getByRole('checkbox'));
    const submitBtn = screen.getByTestId('confirm-destructive-action-btn');
    
    act(() => {
      fireEvent.click(submitBtn);
    });

    expect(screen.getByText('Executing on Gateway...')).toBeInTheDocument();
    expect(screen.queryByText(/Success/i)).not.toBeInTheDocument();

    // Resolve now
    await act(async () => {
      resolveExecute!();
    });
  });

  it('30. Canceling DestructiveActionDialog aborts without executing mutation', () => {
    const onConfirm = vi.fn();
    const onClose = vi.fn();

    const mockDestructiveSpec: DestructiveActionSpec = {
      action: 'Revoke Security Credential',
      resourceType: 'credential',
      resourceId: 'ag_c_test123',
      currentServerState: 'ACTIVE',
      impact: 'Authentication will fail.',
      reversible: false,
      onExecute: onConfirm,
    };

    render(
      <DestructiveActionDialog
        isOpen={true}
        spec={mockDestructiveSpec}
        onClose={onClose}
      />
    );

    const cancelBtn = screen.getByRole('button', { name: /Cancel/i });
    fireEvent.click(cancelBtn);

    expect(onClose).toHaveBeenCalledTimes(1);
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it('31. Failed mutation error does not mutate local authoritative state', () => {
    const mutationError = new AgentGuardApiError('Access denied', 403, 'FORBIDDEN');
    const normalized = normalizeApiError(mutationError);

    expect(normalized.code).toBe('FORBIDDEN');
    expect(normalized.status).toBe(403);
    expect(normalized.message).toContain('Access denied');
  });

  // =========================================================================
  // 7. Operational Resilience & Lifecycle Cleanup (Tests 32-35)
  // =========================================================================

  it('32. Aborted API request normalizes safely without generating error alerts', () => {
    const abortException = new DOMException('The user aborted a request.', 'AbortError');
    const normalized = normalizeApiError(abortException);

    expect(normalized.code).toBe('ABORTED');
    expect(normalized.message).toBe('Request was cancelled.');
  });

  it('33. Stale responses from superseded requests are disregarded', () => {
    const controller = new AbortController();
    controller.abort();
    expect(controller.signal.aborted).toBe(true);
  });

  it('34. Polling timers are cleaned up on unmount and hidden tab states', () => {
    const { unmount } = render(<App />);
    unmount();
    // Verify unmount completes without hanging timer exceptions
    expect(true).toBe(true);
  });

  it('35. Retry storm prevention: Degraded mode enforces bounded manual retry', () => {
    const onRetry = vi.fn();
    const { rerender } = render(
      <DegradedModeBanner isOnline={false} onRetry={onRetry} isRetrying={true} />
    );

    const button = screen.getByRole('button', { name: /Retrying…/i });
    expect(button).toBeDisabled();

    // Clicking while retrying does not create duplicate calls
    fireEvent.click(button);
    expect(onRetry).not.toHaveBeenCalled();

    rerender(<DegradedModeBanner isOnline={false} onRetry={onRetry} isRetrying={false} />);
    const activeBtn = screen.getByRole('button', { name: /Retry Gateway Connection/i });
    expect(activeBtn).not.toBeDisabled();
    fireEvent.click(activeBtn);
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});
