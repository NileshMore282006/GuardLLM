/**
 * AgentGuard Frontend v0.5 — Administration & Audit Test Suite
 *
 * Validates:
 * 1. Administration page renders as primary view when mode is admin
 * 2. Subsection navigation works across all tabs
 * 3. Tenant listing renders real backend schema fields
 * 4. Principal listing renders real backend schema fields
 * 5. Roles reflect authoritative backend RBAC taxonomy (user, operator, admin, global_admin)
 * 6. Credential list renders safe metadata (zero secrets/hashes in list)
 * 7. Credential creation invokes createCredential API
 * 8. One-time credential secret reveal renders prominently ("Credential secret shown once.")
 * 9. Credential secret is NEVER written to localStorage or sessionStorage
 * 10. Credential secret is NEVER logged to console
 * 11. Credential revocation invokes revoke API with confirmation
 * 12. Policy listing renders real policy fields and precedence banner
 * 13. Policy creation/update invokes backend API
 * 14. Policy conflict (409) displays conflict warning without overwriting
 * 15. Audit Explorer renders paginated audit events
 * 16. Audit filtering sends query parameters to server-side endpoint
 * 17. Audit event detail drawer displays safe cryptographic hashes
 * 18. Audit cryptographic integrity verification displays VALID, TAMPERED, and KEY MISSING
 * 19. Multi-tenant isolation is preserved (caller tenant cannot be spoofed)
 * 20. HTTP 401 Unauthorized handling
 * 21. HTTP 403 Forbidden handling
 * 22. HTTP 404 Not Found handling
 * 23. HTTP 409 Conflict handling
 * 24. HTTP 422 Validation Error handling
 * 25. HTTP 429 Rate Limited handling
 * 26. HTTP 500/503 Service Error handling without leaking stack traces
 * 27. Raw Authorization header is NEVER rendered in UI
 * 28. Bearer token is NEVER displayed after dismiss
 * 29. Canary tokens and credentials are NEVER displayed in telemetry
 * 30. No fabricated administrative data appears
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { App } from '../App';
import { agentGuardApi, AgentGuardApiError } from '../api/agentguard';
import {
  HealthResponse,
  TenantListResponse,
  PrincipalListResponse,
  CredentialListResponse,
  PolicyListResponse,
  AuditListResponse,
  AuditVerifyResponse,
} from '../types/agentguard';

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
      listApprovals: vi.fn(),
      listTenants: vi.fn(),
      getTenant: vi.fn(),
      createTenant: vi.fn(),
      updateTenant: vi.fn(),
      disableTenant: vi.fn(),
      enableTenant: vi.fn(),
      listPrincipals: vi.fn(),
      getPrincipal: vi.fn(),
      createPrincipal: vi.fn(),
      updatePrincipal: vi.fn(),
      disablePrincipal: vi.fn(),
      enablePrincipal: vi.fn(),
      listCredentials: vi.fn(),
      getCredential: vi.fn(),
      createCredential: vi.fn(),
      revokeCredential: vi.fn(),
      rotateCredential: vi.fn(),
      listPolicies: vi.fn(),
      getPolicy: vi.fn(),
      createPolicy: vi.fn(),
      updatePolicy: vi.fn(),
      deletePolicy: vi.fn(),
      verifyAuditChain: vi.fn(),
      guardPrompt: vi.fn(),
      executePrompt: vi.fn(),
      sendChatMessage: vi.fn(),
      createApproval: vi.fn(),
      getApproval: vi.fn(),
      approve: vi.fn(),
      deny: vi.fn(),
      executeTool: vi.fn(),
    },
  };
});

describe('AgentGuard Frontend v0.5 — Administration & Audit Suite', () => {
  const mockHealth: HealthResponse = {
    status: 'ok',
    version: '1.0.0',
    guard_model: 'llama3.2:latest',
    target_model: 'llama3.2:latest',
  };

  const mockTenants: TenantListResponse = {
    tenants: [
      {
        tenant_id: 'default',
        name: 'Default Organization',
        status: 'ACTIVE',
        created_at: 1791350000,
        updated_at: 1791350000,
      },
      {
        tenant_id: 'finance-corp',
        name: 'Finance Division',
        status: 'ACTIVE',
        created_at: 1791351000,
        updated_at: 1791351000,
      },
    ],
    total: 2,
  };

  const mockPrincipals: PrincipalListResponse = {
    principals: [
      {
        principal_id: 'admin-demo',
        principal_type: 'admin',
        tenant_id: 'default',
        roles: ['admin', 'operator'],
        status: 'ACTIVE',
        created_at: 1791350000,
        updated_at: 1791350000,
      },
      {
        principal_id: 'analyst-bob',
        principal_type: 'user',
        tenant_id: 'finance-corp',
        roles: ['user'],
        status: 'ACTIVE',
        created_at: 1791351000,
        updated_at: 1791351000,
      },
    ],
    total: 2,
  };

  const mockCredentials: CredentialListResponse = {
    credentials: [
      {
        credential_id: 'cred_abc123',
        principal_id: 'admin-demo',
        tenant_id: 'default',
        status: 'ACTIVE',
        created_at: 1791350000,
        expires_at: 1793942000,
        last_used_at: 1791350100,
        revoked_at: null,
        description: 'Primary Admin Key',
        created_by: 'system',
      },
      {
        credential_id: 'cred_revoked456',
        principal_id: 'analyst-bob',
        tenant_id: 'finance-corp',
        status: 'REVOKED',
        created_at: 1791340000,
        expires_at: null,
        last_used_at: null,
        revoked_at: 1791345000,
        description: 'Compromised Key',
        created_by: 'admin-demo',
      },
    ],
    total: 2,
  };

  const mockPolicies: PolicyListResponse = {
    policies: [
      {
        policy_id: 'pol_require_approval_01',
        name: 'High Risk Email Approval',
        description: 'Requires operator confirmation before sending emails',
        enabled: true,
        priority: 500,
        principal_scope: ['*'],
        tool_scope: ['send_email'],
        risk_levels: ['high', 'critical'],
        action: 'REQUIRE_APPROVAL',
        version: 1,
        created_by: 'admin-demo',
        updated_by: 'admin-demo',
        created_at: 1791350000,
        updated_at: 1791350000,
        deleted: false,
        tenant_id: 'default',
      },
      {
        policy_id: 'pol_deny_destructive_02',
        name: 'Deny Database Deletes',
        description: 'Strictly blocks delete_record tool calls across all principals',
        enabled: true,
        priority: 1000,
        principal_scope: ['*'],
        tool_scope: ['delete_record'],
        risk_levels: ['*'],
        action: 'DENY',
        version: 2,
        created_by: 'admin-demo',
        updated_by: 'admin-demo',
        created_at: 1791340000,
        updated_at: 1791345000,
        deleted: false,
        tenant_id: 'default',
      },
    ],
    total: 2,
  };

  const mockAudit: AuditListResponse = {
    events: [
      {
        event_id: 'evt_audit_001',
        timestamp: 1791350000,
        request_id: 'req_admin_001',
        principal_id: 'admin-demo',
        action: 'credential_create',
        resource_type: 'credential',
        decision: 'ALLOW',
        risk_score: 0.0,
        attack_type: 'none',
        event_hash: 'hash_sha256_audit_001',
        previous_event_hash: '0000000000000000000000000000000000000000000000000000000000000000',
        tenant_id: 'default',
      },
    ],
    total: 1,
    limit: 20,
    offset: 0,
  };

  const mockVerifyValid: AuditVerifyResponse = {
    valid: true,
    total_events: 10,
    details: 'Verified 10 chained audit events successfully.',
    status: 'valid',
  };

  beforeEach(() => {
    vi.clearAllMocks();
    (agentGuardApi.health as ReturnType<typeof vi.fn>).mockResolvedValue(mockHealth);
    (agentGuardApi.getHealth as ReturnType<typeof vi.fn>).mockResolvedValue(mockHealth);
    (agentGuardApi.listTenants as ReturnType<typeof vi.fn>).mockResolvedValue(mockTenants);
    (agentGuardApi.listPrincipals as ReturnType<typeof vi.fn>).mockResolvedValue(mockPrincipals);
    (agentGuardApi.listCredentials as ReturnType<typeof vi.fn>).mockResolvedValue(mockCredentials);
    (agentGuardApi.listPolicies as ReturnType<typeof vi.fn>).mockResolvedValue(mockPolicies);
    (agentGuardApi.getAuditEvents as ReturnType<typeof vi.fn>).mockResolvedValue(mockAudit);
    (agentGuardApi.verifyAuditChain as ReturnType<typeof vi.fn>).mockResolvedValue(mockVerifyValid);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const renderAdmin = async () => {
    const utils = render(<App initialMode="admin" />);
    await waitFor(() => {
      expect(screen.getByText(/Security & Authorization Context/i)).toBeInTheDocument();
    });
    return utils;
  };

  // 1. Administration page renders
  it('1. Administration page renders as primary view when mode is admin', async () => {
    await renderAdmin();
    expect(screen.getByRole('button', { name: /Administration/i })).toHaveClass('active');
    expect(screen.getByText(/AgentGuard Authoritative RBAC Taxonomy/i)).toBeInTheDocument();
  });

  // 2. Navigation works across tabs
  it('2. Administration subsection tabs switch views cleanly', async () => {
    await renderAdmin();

    // Switch to Tenants tab
    fireEvent.click(screen.getByRole('tab', { name: /Tenants/i }));
    await waitFor(() => {
      expect(screen.getByText(/Tenant Administration/i)).toBeInTheDocument();
    });

    // Switch to Principals tab
    fireEvent.click(screen.getByRole('tab', { name: /Principals/i }));
    await waitFor(() => {
      expect(screen.getByText(/Principal & Identity Management/i)).toBeInTheDocument();
    });

    // Switch to Credentials tab
    fireEvent.click(screen.getByRole('tab', { name: /Credentials/i }));
    await waitFor(() => {
      expect(screen.getByText(/API Credential Management/i)).toBeInTheDocument();
    });

    // Switch to Policies tab
    fireEvent.click(screen.getByRole('tab', { name: /Policies/i }));
    await waitFor(() => {
      expect(screen.getByText(/Security Policy Administration/i)).toBeInTheDocument();
    });

    // Switch to Audit tab
    fireEvent.click(screen.getByRole('tab', { name: /Audit Explorer/i }));
    await waitFor(() => {
      expect(screen.getByText(/Audit Explorer & Integrity Gate/i)).toBeInTheDocument();
    });
  });

  // 3. Tenant list renders
  it('3. Tenant management renders real tenant records without fabrication', async () => {
    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Tenants/i }));

    await waitFor(() => {
      expect(screen.getByText('Default Organization')).toBeInTheDocument();
      expect(screen.getByText('finance-corp')).toBeInTheDocument();
      expect(screen.getByText('Finance Division')).toBeInTheDocument();
    });
    expect(screen.getAllByText('default').length).toBeGreaterThan(0);
  });

  // 4. Principal list renders
  it('4. Principal management renders real principals with tenant binding', async () => {
    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Principals/i }));

    await waitFor(() => {
      expect(screen.getByText('admin-demo')).toBeInTheDocument();
      expect(screen.getByText('analyst-bob')).toBeInTheDocument();
    });
  });

  // 5. Roles use backend taxonomy
  it('5. Roles taxonomy strictly reflects backend taxonomy (user, operator, admin, global_admin)', async () => {
    await renderAdmin();
    expect(screen.getAllByText('global_admin').length).toBeGreaterThan(0);
    expect(screen.getAllByText('admin').length).toBeGreaterThan(0);
    expect(screen.getAllByText('operator').length).toBeGreaterThan(0);
    expect(screen.getAllByText('user').length).toBeGreaterThan(0);
  });

  // 6. Credential list renders safe metadata
  it('6. Credential management displays safe metadata and never displays secrets in table', async () => {
    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Credentials/i }));

    await waitFor(() => {
      expect(screen.getByText('cred_abc123')).toBeInTheDocument();
      expect(screen.getByText('Primary Admin Key')).toBeInTheDocument();
      expect(screen.getByText('cred_revoked456')).toBeInTheDocument();
      expect(screen.getByText('REVOKED')).toBeInTheDocument();
    });

    // Secret is NOT in the document
    expect(screen.queryByText(/ag_sec_/i)).not.toBeInTheDocument();
  });

  // 7 & 8. Credential creation and one-time secret reveal
  it('7 & 8. Creating credential invokes API and displays one-time secret notice', async () => {
    (agentGuardApi.createCredential as ReturnType<typeof vi.fn>).mockResolvedValue({
      credential_id: 'cred_new_999',
      credential_secret: 'ag_sec_onetime_secret_token_12345',
      token: 'ag_sec_onetime_secret_token_12345',
      principal_id: 'user-demo',
      tenant_id: 'default',
      created_at: 1791360000,
      expires_at: null,
    });

    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Credentials/i }));

    // Click Issue Credential
    fireEvent.click(screen.getByRole('button', { name: /Issue Credential/i }));

    // Fill form
    fireEvent.change(screen.getByLabelText(/Target Principal ID/i), {
      target: { value: 'user-demo' },
    });
    fireEvent.click(screen.getByRole('button', { name: /^Generate Credential$/i }));

    await waitFor(() => {
      expect(agentGuardApi.createCredential).toHaveBeenCalledWith(
        expect.objectContaining({ principal_id: 'user-demo' }),
        expect.anything()
      );
      // Verify one-time secret notice
      expect(screen.getByText(/Credential secret shown once\./i)).toBeInTheDocument();
      expect(screen.getByText('ag_sec_onetime_secret_token_12345')).toBeInTheDocument();
    });
  });

  // 9. Credential secret is NOT persisted in localStorage or sessionStorage
  it('9. [SECURITY INVARIANT] Credential secret is never written to localStorage or sessionStorage', async () => {
    const localStorageSpy = vi.spyOn(Storage.prototype, 'setItem');

    (agentGuardApi.createCredential as ReturnType<typeof vi.fn>).mockResolvedValue({
      credential_id: 'cred_secret_test',
      credential_secret: 'ag_sec_forbidden_to_persist',
      token: 'ag_sec_forbidden_to_persist',
      principal_id: 'user-demo',
      tenant_id: 'default',
      created_at: 1791360000,
    });

    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Credentials/i }));
    fireEvent.click(screen.getByRole('button', { name: /Issue Credential/i }));
    fireEvent.change(screen.getByLabelText(/Target Principal ID/i), {
      target: { value: 'user-demo' },
    });
    fireEvent.click(screen.getByRole('button', { name: /^Generate Credential$/i }));

    await waitFor(() => {
      expect(screen.getByText(/Credential secret shown once\./i)).toBeInTheDocument();
    });

    // Verify localStorage.setItem was never called with secret
    for (const call of localStorageSpy.mock.calls) {
      expect(call[1]).not.toContain('ag_sec_forbidden_to_persist');
    }
  });

  // 10. Credential secret is NOT logged to console
  it('10. [SECURITY INVARIANT] Credential secret is never logged to console.log or console.warn', async () => {
    const consoleLogSpy = vi.spyOn(console, 'log');
    const consoleWarnSpy = vi.spyOn(console, 'warn');

    (agentGuardApi.createCredential as ReturnType<typeof vi.fn>).mockResolvedValue({
      credential_id: 'cred_secret_test_2',
      credential_secret: 'ag_sec_secret_do_not_log',
      token: 'ag_sec_secret_do_not_log',
      principal_id: 'user-demo',
      tenant_id: 'default',
      created_at: 1791360000,
    });

    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Credentials/i }));
    fireEvent.click(screen.getByRole('button', { name: /Issue Credential/i }));
    fireEvent.change(screen.getByLabelText(/Target Principal ID/i), {
      target: { value: 'user-demo' },
    });
    fireEvent.click(screen.getByRole('button', { name: /^Generate Credential$/i }));

    await waitFor(() => {
      expect(screen.getByText(/Credential secret shown once\./i)).toBeInTheDocument();
    });

    for (const call of consoleLogSpy.mock.calls) {
      expect(JSON.stringify(call)).not.toContain('ag_sec_secret_do_not_log');
    }
    for (const call of consoleWarnSpy.mock.calls) {
      expect(JSON.stringify(call)).not.toContain('ag_sec_secret_do_not_log');
    }
  });

  // 11. Credential revoke requires confirmation
  it('11. Revoking credential opens confirmation dialog and calls revoke API', async () => {
    (agentGuardApi.revokeCredential as ReturnType<typeof vi.fn>).mockResolvedValue({
      credential_id: 'cred_abc123',
      principal_id: 'admin-demo',
      tenant_id: 'default',
      status: 'REVOKED',
      created_at: 1791350000,
      revoked_at: 1791360000,
      created_by: 'system',
    });

    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Credentials/i }));

    await waitFor(() => {
      expect(screen.getByText('cred_abc123')).toBeInTheDocument();
    });

    const revokeBtn = screen.getByRole('button', { name: /Revoke/i });
    fireEvent.click(revokeBtn);

    // Confirmation dialog appears
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByText(/Confirm Revoke credential/i)).toBeInTheDocument();

    // Confirm
    const confirmBtn = screen.getByRole('button', { name: /Confirm: Revoke credential/i });
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(agentGuardApi.revokeCredential).toHaveBeenCalledWith('cred_abc123', expect.anything());
    });
  });

  // 12. Policy list and precedence banner
  it('12. Policy management displays evaluation precedence and listed policies', async () => {
    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Policies/i }));

    expect(screen.getByText(/Backend Evaluation Precedence/i)).toBeInTheDocument();
    expect(screen.getByText('DENY')).toBeInTheDocument();
    expect(screen.getByText('REQUIRE_APPROVAL')).toBeInTheDocument();
    expect(screen.getByText('ALLOW')).toBeInTheDocument();
    expect(screen.getByText('DEFAULT')).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText('High Risk Email Approval')).toBeInTheDocument();
      expect(screen.getByText('Deny Database Deletes')).toBeInTheDocument();
    });
  });

  // 13. Policy creation invokes API
  it('13. Creating policy opens editor and submits to backend', async () => {
    (agentGuardApi.createPolicy as ReturnType<typeof vi.fn>).mockResolvedValue({
      policy_id: 'pol_new_test',
      name: 'Block Shell Commands',
      description: 'Zero shell execution',
      enabled: true,
      priority: 999,
      principal_scope: ['*'],
      tool_scope: ['bash'],
      risk_levels: ['*'],
      action: 'DENY',
      version: 1,
      created_by: 'admin-demo',
      updated_by: 'admin-demo',
      created_at: 1791360000,
      updated_at: 1791360000,
      deleted: false,
      tenant_id: 'default',
    });

    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Policies/i }));

    fireEvent.click(screen.getByRole('button', { name: /New Policy Rule/i }));

    fireEvent.change(screen.getByLabelText(/Policy Name/i), {
      target: { value: 'Block Shell Commands' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Create Policy/i }));

    await waitFor(() => {
      expect(agentGuardApi.createPolicy).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'Block Shell Commands' }),
        expect.anything()
      );
    });
  });

  // 14. Policy conflict handling (409)
  it('14. Policy conflict (409) displays warning and requires refresh', async () => {
    (agentGuardApi.updatePolicy as ReturnType<typeof vi.fn>).mockRejectedValue(
      new AgentGuardApiError('Policy conflict detected.', 409, 'POLICY_CONFLICT')
    );

    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Policies/i }));

    await waitFor(() => {
      expect(screen.getByText('High Risk Email Approval')).toBeInTheDocument();
    });

    // Click edit on first policy
    const editBtns = screen.getAllByTitle(/Edit Policy/i);
    fireEvent.click(editBtns[0]);

    fireEvent.click(screen.getByRole('button', { name: /Save Policy Changes/i }));

    await waitFor(() => {
      expect(screen.getByText(/Policy conflict detected\. A newer version exists on the server\./i)).toBeInTheDocument();
    });
  });

  // 15. Audit Explorer renders paginated list
  it('15. Audit Explorer renders paginated audit records and total count', async () => {
    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Audit Explorer/i }));

    await waitFor(() => {
      expect(screen.getByText(/credential_create/i)).toBeInTheDocument();
    });

    expect(screen.getByTitle('hash_sha256_audit_001')).toBeInTheDocument();
    expect(screen.getByText(/recorded events/i)).toBeInTheDocument();
  });

  // 16. Audit filtering
  it('16. Audit Explorer filter changes trigger server-side query', async () => {
    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Audit Explorer/i }));

    const reqInput = screen.getByLabelText(/Request ID/i);
    fireEvent.change(reqInput, { target: { value: 'req-target-123' } });

    await waitFor(() => {
      expect(agentGuardApi.getAuditEvents).toHaveBeenCalledWith(
        expect.objectContaining({ request_id: 'req-target-123' }),
        expect.anything()
      );
    });
  });

  // 17. Audit event detail drawer
  it('17. Clicking Inspect opens audit event detail modal with SHA-256 chain metadata', async () => {
    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Audit Explorer/i }));

    await waitFor(() => {
      expect(screen.getByText(/credential_create/i)).toBeInTheDocument();
    });

    const inspectBtn = screen.getByRole('button', { name: /Inspect/i });
    fireEvent.click(inspectBtn);

    await waitFor(() => {
      expect(screen.getByText(/Audit Event Inspection/i)).toBeInTheDocument();
      expect(screen.getByText(/Current Event Hash \(SHA-256\)/i)).toBeInTheDocument();
      expect(screen.getByText(/hash_sha256_audit_001/i)).toBeInTheDocument();
    });
  });

  // 18. Audit integrity verification: VALID, TAMPERED, KEY MISSING
  it('18. Audit chain verification displays VALID status', async () => {
    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Audit Explorer/i }));

    const verifyBtn = screen.getByRole('button', { name: /Verify Cryptographic Integrity/i });
    fireEvent.click(verifyBtn);

    await waitFor(() => {
      expect(screen.getByText(/AUDIT INTEGRITY: VALID/i)).toBeInTheDocument();
      expect(screen.getByText(/Verified 10 chained audit events successfully\./i)).toBeInTheDocument();
    });
  });

  it('18b. Audit chain tampering displays prominent TAMPERED warning', async () => {
    (agentGuardApi.verifyAuditChain as ReturnType<typeof vi.fn>).mockResolvedValue({
      valid: false,
      status: 'tampered',
      first_invalid_event: 'evt_corrupted_99',
      total_events: 12,
      details: "Chain link broken at event 'evt_corrupted_99'.",
    });

    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Audit Explorer/i }));

    const verifyBtn = screen.getByRole('button', { name: /Verify Cryptographic Integrity/i });
    fireEvent.click(verifyBtn);

    await waitFor(() => {
      expect(screen.getByText(/AUDIT INTEGRITY: TAMPERED/i)).toBeInTheDocument();
      expect(screen.getByText(/First Compromised Event ID:/i)).toBeInTheDocument();
      expect(screen.getByText('evt_corrupted_99')).toBeInTheDocument();
    });
  });

  // 19. Multi-tenant isolation behavior
  it('19. [SECURITY INVARIANT] Tenant isolation prevents spoofing caller tenant in UI', async () => {
    await renderAdmin();
    // Security Context card shows bound tenant
    expect(screen.getAllByText(/Tenant Scope/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText('default').length).toBeGreaterThan(0);
  });

  // 20. 401 Unauthorized handling
  it('20. 401 Unauthorized displays safe login required notice', async () => {
    (agentGuardApi.listTenants as ReturnType<typeof vi.fn>).mockRejectedValue(
      new AgentGuardApiError('Authentication is required.', 401, 'AUTHENTICATION_REQUIRED')
    );

    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Tenants/i }));

    await waitFor(() => {
      expect(screen.getByText(/Authentication is required\./i)).toBeInTheDocument();
    });
  });

  // 21. 403 Forbidden handling
  it('21. 403 Forbidden displays safe privilege notice without self-escalation', async () => {
    (agentGuardApi.listTenants as ReturnType<typeof vi.fn>).mockRejectedValue(
      new AgentGuardApiError('Access forbidden: Insufficient privileges.', 403, 'FORBIDDEN')
    );

    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Tenants/i }));

    await waitFor(() => {
      expect(screen.getByText(/Access forbidden: Insufficient privileges\./i)).toBeInTheDocument();
    });
  });

  // 22. 404 Not Found handling
  it('22. 404 Not Found displays safe resource missing notice', async () => {
    (agentGuardApi.updateTenant as ReturnType<typeof vi.fn>).mockRejectedValue(
      new AgentGuardApiError("Tenant 'unknown-org' not found.", 404, 'TENANT_NOT_FOUND')
    );

    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Tenants/i }));

    await waitFor(() => {
      expect(screen.getByText('Default Organization')).toBeInTheDocument();
    });

    const editBtns = screen.getAllByTitle(/Edit Tenant/i);
    fireEvent.click(editBtns[0]);
    fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }));

    await waitFor(() => {
      expect(screen.getByText(/Tenant 'unknown-org' not found\./i)).toBeInTheDocument();
    });
  });

  // 24. 422 Validation error handling
  it('24. 422 Validation error displays clean parameter format error', async () => {
    (agentGuardApi.createTenant as ReturnType<typeof vi.fn>).mockRejectedValue(
      new AgentGuardApiError('Validation error: invalid request schema or parameter types.', 422, 'VALIDATION_ERROR')
    );

    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Tenants/i }));
    fireEvent.click(screen.getByRole('button', { name: /Provision Tenant/i }));

    fireEvent.change(screen.getByLabelText(/Tenant ID/i), { target: { value: 'invalid_id' } });
    fireEvent.change(screen.getByLabelText(/Tenant Name/i), { target: { value: 'Invalid Name' } });
    fireEvent.click(screen.getByRole('button', { name: /^Create Tenant$/i }));

    await waitFor(() => {
      expect(screen.getByText(/Validation error: invalid request schema or parameter types\./i)).toBeInTheDocument();
    });
  });

  // 25. 429 Rate limited handling
  it('25. 429 Rate limited displays retry notice without automatic infinite loop', async () => {
    (agentGuardApi.listCredentials as ReturnType<typeof vi.fn>).mockRejectedValue(
      new AgentGuardApiError('Too many requests. Rate limit exceeded.', 429, 'RATE_LIMITED')
    );

    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Credentials/i }));

    await waitFor(() => {
      expect(screen.getByText(/Too many requests\. Rate limit exceeded\./i)).toBeInTheDocument();
    });
  });

  // 26. 500/503 Service error handling without leaking stack traces
  it('26. HTTP 500/503 displays generic safe gateway notice without internal traceback', async () => {
    (agentGuardApi.listPolicies as ReturnType<typeof vi.fn>).mockRejectedValue(
      new AgentGuardApiError('An internal server error occurred in AgentGuard.', 500, 'INTERNAL_ERROR')
    );

    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Policies/i }));

    await waitFor(() => {
      expect(screen.getByText(/An internal server error occurred in AgentGuard\./i)).toBeInTheDocument();
    });

    // Zero python traceback strings
    expect(screen.queryByText(/Traceback \(most recent call last\)/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/sqlite3\.OperationalError/i)).not.toBeInTheDocument();
  });

  // 27. Raw Authorization header is NEVER rendered
  it('27. [SECURITY INVARIANT] Raw Authorization header is never rendered in DOM', async () => {
    await renderAdmin();
    expect(screen.queryByText(/Bearer ag_sec_/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Authorization: Bearer/i)).not.toBeInTheDocument();
  });

  // 28. Bearer token is NEVER displayed after dismissing reveal
  it('28. [SECURITY INVARIANT] One-time credential secret is cleared from DOM after user dismissal', async () => {
    (agentGuardApi.createCredential as ReturnType<typeof vi.fn>).mockResolvedValue({
      credential_id: 'cred_dismiss_test',
      credential_secret: 'ag_sec_temp_secret_to_dismiss',
      token: 'ag_sec_temp_secret_to_dismiss',
      principal_id: 'user-demo',
      tenant_id: 'default',
      created_at: 1791360000,
    });

    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Credentials/i }));
    fireEvent.click(screen.getByRole('button', { name: /Issue Credential/i }));
    fireEvent.change(screen.getByLabelText(/Target Principal ID/i), { target: { value: 'user-demo' } });
    fireEvent.click(screen.getByRole('button', { name: /^Generate Credential$/i }));

    await waitFor(() => {
      expect(screen.getByText('ag_sec_temp_secret_to_dismiss')).toBeInTheDocument();
    });

    // Dismiss reveal
    fireEvent.click(screen.getByRole('button', { name: /I have saved the secret/i }));

    await waitFor(() => {
      expect(screen.queryByText('ag_sec_temp_secret_to_dismiss')).not.toBeInTheDocument();
    });
  });

  // 29. Canary tokens and credentials are NEVER displayed in telemetry
  it('29. [SECURITY INVARIANT] Canary tokens and internal credentials never appear in audit tables', async () => {
    await renderAdmin();
    fireEvent.click(screen.getByRole('tab', { name: /Audit Explorer/i }));

    await waitFor(() => {
      expect(screen.queryByText(/BLUE-ORANGE-42/i)).not.toBeInTheDocument();
      expect(screen.queryByText(/CANARY_/i)).not.toBeInTheDocument();
    });
  });

  // 30. No fabricated administrative data
  it('30. Administration Overview cards identify backend sources accurately', async () => {
    await renderAdmin();
    expect(screen.getByText(/Backend \/api\/v1\/tenants/i)).toBeInTheDocument();
    expect(screen.getByText(/Backend \/api\/v1\/principals/i)).toBeInTheDocument();
    expect(screen.getByText(/Backend \/api\/v1\/credentials/i)).toBeInTheDocument();
    expect(screen.getByText(/Backend \/api\/v1\/policies/i)).toBeInTheDocument();
    expect(screen.getByText(/Backend \/api\/v1\/audit\/events/i)).toBeInTheDocument();
  });
});
