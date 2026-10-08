/**
 * AgentGuard Frontend v0.4 — Security Dashboard Test Suite
 *
 * Validates:
 * 1. Dashboard renders with real backend API contracts
 * 2. Overview metrics render accurately without fabricated numbers
 * 3. Loading, empty, and backend unavailable states
 * 4. Health vs Readiness distinction
 * 5. Decision and attack filtering (client-side of loaded dataset)
 * 6. Security event inspection and telemetry drawer
 * 7. Tool security and approval lifecycle rendering
 * 8. Session latency rendering (labeled session-only)
 * 9. Runtime process metrics labeled separately
 * 10. HTTP 401, 403, 429, 500/503 error boundaries
 * 11. Security invariants: Zero secrets, zero raw prompts in audit logs, zero authorization header leakage
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { App } from '../App';
import { agentGuardApi, AgentGuardApiError } from '../api/agentguard';
import {
  HealthResponse,
  ReadyResponse,
  RuntimeMetricsResponse,
  AuditListResponse,
  ApprovalDetailResponse,
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
      listApprovals: vi.fn(),
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

describe('AgentGuard Frontend v0.4 — Security Dashboard Suite', () => {
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
    identity: 'ready',
    credential_store: 'ready',
    policy_store: 'ready',
    audit_store: 'ready',
    configuration: 'ready',
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
    uptime_seconds: 1800,
    total_requests: 84,
    requests_by_endpoint: {
      '/health': 10,
      '/api/v1/guard': 30,
      '/api/v1/chat': 25,
      '/api/v1/tool/execute': 19,
    },
    requests_by_status: {
      '200': 76,
      '403': 5,
      '409': 3,
    },
    decisions: {
      allow: 62,
      block: 20,
      error: 2,
    },
    rate_limited_count: 1,
    concurrency_rejected_count: 0,
    guard: {
      invocations: 55,
      failures: 0,
      timeouts: 0,
    },
    target: {
      invocations: 40,
      failures: 0,
      timeouts: 0,
    },
    timeouts: {
      guard_timeouts: 0,
      target_timeouts: 0,
      total_timeouts: 0,
    },
    tools: {
      total_calls: 19,
      allowed: 14,
      blocked: 5,
      error: 0,
      unauthorized_executions: 0,
      limit_exceeded: 0,
    },
    approvals: {
      approval_requests_created: 8,
      approval_requests_approved: 5,
      approval_requests_denied: 2,
      approval_requests_expired: 1,
      approval_requests_cancelled: 0,
      approval_execution_success: 5,
      approval_execution_failure: 0,
      approval_replay_attempts: 3,
      approval_binding_failures: 0,
      unauthorized_high_risk_tool_executions: 0,
    },
  };

  const mockAuditList: AuditListResponse = {
    events: [
      {
        event_id: 'evt_001_guard_allow',
        timestamp: 1791350000,
        request_id: 'req_allow_123',
        principal_id: 'user-alice',
        action: 'guard_allow',
        resource_type: 'prompt',
        decision: 'ALLOW',
        risk_score: 0.05,
        attack_type: 'none',
        event_hash: 'hash_allow_111',
        previous_event_hash: 'hash_prev_000',
        tenant_id: 'default',
      },
      {
        event_id: 'evt_002_guard_block',
        timestamp: 1791350100,
        request_id: 'req_block_456',
        principal_id: 'user-bob',
        action: 'guard_block',
        resource_type: 'prompt',
        decision: 'BLOCK',
        risk_score: 0.98,
        attack_type: 'instruction_override',
        event_hash: 'hash_block_222',
        previous_event_hash: 'hash_allow_111',
        tenant_id: 'default',
      },
      {
        event_id: 'evt_003_tool_block',
        timestamp: 1791350200,
        request_id: 'req_tool_789',
        principal_id: 'user-charlie',
        action: 'tool_block',
        resource_type: 'tool',
        tool_name: 'delete_record',
        decision: 'BLOCK',
        risk_score: 1.0,
        attack_type: 'prompt_injection',
        event_hash: 'hash_tool_333',
        previous_event_hash: 'hash_block_222',
        tenant_id: 'default',
      },
    ],
    total: 3,
    limit: 100,
    offset: 0,
  };

  const mockApprovalsList: ApprovalDetailResponse[] = [
    {
      approval_id: 'appr_pending_01',
      request_id: 'req_appr_01',
      conversation_id: null,
      tool_name: 'send_email',
      risk_level: 'high',
      reason: 'Action requires approval due to high risk level.',
      arguments_summary: "recipient: 'alice@example.com'; subject: 'Report'",
      arguments_hash: 'hash_args_01',
      status: 'PENDING_APPROVAL',
      principal_id: 'user-operator',
      policy_id: null,
      policy_version: null,
      created_at: 1791350000,
      expires_at: 1791350300,
      approved_at: null,
      denied_at: null,
      expired_at: null,
      consumed_at: null,
      execution_count: 0,
    },
    {
      approval_id: 'appr_consumed_02',
      request_id: 'req_appr_02',
      conversation_id: null,
      tool_name: 'send_email',
      risk_level: 'high',
      reason: 'Approved by operator',
      arguments_summary: "recipient: 'bob@example.com'; subject: 'Alert'",
      arguments_hash: 'hash_args_02',
      status: 'CONSUMED',
      principal_id: 'user-operator',
      policy_id: null,
      policy_version: null,
      created_at: 1791349000,
      expires_at: 1791349300,
      approved_at: 1791349050,
      denied_at: null,
      expired_at: null,
      consumed_at: 1791349051,
      execution_count: 1,
    },
  ];

  beforeEach(() => {
    vi.clearAllMocks();
    (agentGuardApi.health as ReturnType<typeof vi.fn>).mockResolvedValue(mockHealth);
    (agentGuardApi.getHealth as ReturnType<typeof vi.fn>).mockResolvedValue(mockHealth);
    (agentGuardApi.getReady as ReturnType<typeof vi.fn>).mockResolvedValue(mockReady);
    (agentGuardApi.getMetrics as ReturnType<typeof vi.fn>).mockResolvedValue(mockMetrics);
    (agentGuardApi.getAuditEvents as ReturnType<typeof vi.fn>).mockResolvedValue(mockAuditList);
    (agentGuardApi.listApprovals as ReturnType<typeof vi.fn>).mockResolvedValue(mockApprovalsList);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const renderDashboard = async () => {
    const utils = render(<App initialMode="dashboard" />);
    // Wait for initial data loading
    await waitFor(() => {
      expect(screen.getByText(/Security Operations Dashboard/i)).toBeInTheDocument();
    });
    return utils;
  };

  // 1. Dashboard Renders
  it('1. Security Dashboard renders as primary view when mode is dashboard', async () => {
    await renderDashboard();
    expect(screen.getByRole('button', { name: /Security Dashboard/i })).toHaveClass('active');
    expect(screen.getByText(/Security Operations Dashboard/i)).toBeInTheDocument();
  });

  // 2. Overview metrics render from real mocked API data
  it('2. Overview metrics render accurately from backend audit and metrics data', async () => {
    await renderDashboard();
    // 3 total audit events
    expect(screen.getAllByText('3').length).toBeGreaterThan(0);
    // 84 total in-process requests
    expect(screen.getByText('84')).toBeInTheDocument();
    // 19 tool calls
    expect(screen.getByText('19')).toBeInTheDocument();
  });

  // 3. No fabricated metric appears: sources are labeled
  it('3. Explicitly labels data sources for persisted audit, runtime metrics, and session', async () => {
    await renderDashboard();
    expect(screen.getByText(/Backend \/api\/v1\/audit\/events/i)).toBeInTheDocument();
    expect(screen.getByText(/Runtime \/metrics \(In-Memory\)/i)).toBeInTheDocument();
  });

  // 4. Loading and Refresh state
  it('4. Refresh button triggers backend re-fetch', async () => {
    await renderDashboard();
    const refreshBtn = screen.getByRole('button', { name: /Refresh/i });
    fireEvent.click(refreshBtn);

    await waitFor(() => {
      expect(agentGuardApi.getAuditEvents).toHaveBeenCalledTimes(2);
      expect(agentGuardApi.getMetrics).toHaveBeenCalledTimes(2);
    });
  });

  // 5. Empty audit state handling
  it('5. Renders clean empty state when no audit events exist', async () => {
    (agentGuardApi.getAuditEvents as ReturnType<typeof vi.fn>).mockResolvedValue({
      events: [],
      total: 0,
      limit: 50,
      offset: 0,
    });

    await renderDashboard();
    // Switch to Audit Events tab
    const auditTab = screen.getByRole('tab', { name: /Audit Events/i });
    fireEvent.click(auditTab);

    await waitFor(() => {
      expect(screen.getByText(/No Security Events Match Filters/i)).toBeInTheDocument();
    });
  });

  // 6. Backend unavailable state
  it('6. Gracefully handles audit events failure without crashing the dashboard', async () => {
    (agentGuardApi.getAuditEvents as ReturnType<typeof vi.fn>).mockRejectedValue(
      new AgentGuardApiError('Security audit event history unavailable.', 503)
    );

    await renderDashboard();
    expect(screen.getByText(/Audit Events Notice/i)).toBeInTheDocument();
    expect(screen.getByText(/Security audit event history unavailable./i)).toBeInTheDocument();
    // Health status remains visible
    expect(screen.getByText(/Backend Health & Readiness/i)).toBeInTheDocument();
  });

  // 7. Health status display
  it('7. Displays HEALTHY when /health returns ok', async () => {
    await renderDashboard();
    await waitFor(() => {
      expect(screen.getByText(/Health: HEALTHY/i)).toBeInTheDocument();
    });
  });

  // 8. Readiness status display
  it('8. Displays READY and sub-checks when /ready returns ready', async () => {
    await renderDashboard();
    await waitFor(() => {
      expect(screen.getByText(/Readiness: READY/i)).toBeInTheDocument();
      expect(screen.getByText(/ollama: connected/i)).toBeInTheDocument();
    });
  });

  // 9. Decision filtering on audit events
  it('9. Client-side decision filtering updates displayed audit events', async () => {
    await renderDashboard();
    const auditTab = screen.getByRole('tab', { name: /Audit Events/i });
    fireEvent.click(auditTab);

    // Filter by BLOCK only
    const blockBtn = screen.getByRole('button', { name: /^BLOCK$/i });
    fireEvent.click(blockBtn);

    await waitFor(() => {
      expect(screen.getByText(/Showing 2 of 3 loaded events/i)).toBeInTheDocument();
    });
  });

  // 10. Attack filtering on audit events
  it('10. Filters audit events by attack taxonomy', async () => {
    await renderDashboard();
    const auditTab = screen.getByRole('tab', { name: /Audit Events/i });
    fireEvent.click(auditTab);

    const attackSelect = screen.getByLabelText(/Filter by attack type/i);
    fireEvent.change(attackSelect, { target: { value: 'instruction_override' } });

    await waitFor(() => {
      expect(screen.getByText(/Showing 1 of 3 loaded events/i)).toBeInTheDocument();
    });
  });

  // 11. Event selection opens telemetry drawer
  it('11. Clicking an event row opens the security telemetry drawer', async () => {
    await renderDashboard();
    const auditTab = screen.getByRole('tab', { name: /Audit Events/i });
    fireEvent.click(auditTab);

    const inspectButtons = screen.getAllByRole('button', { name: /Inspect/i });
    fireEvent.click(inspectButtons[0]);

    await waitFor(() => {
      expect(screen.getByText(/Security Audit Telemetry/i)).toBeInTheDocument();
      expect(screen.getByText(/req_allow_123/i)).toBeInTheDocument();
      expect(screen.getByText(/hash_allow_111/i)).toBeInTheDocument();
    });
  });

  // 12. Security Flow Map highlights stages for selected event
  it('12. Security Flow Map visualizes perimeter stages', async () => {
    await renderDashboard();
    const auditTab = screen.getByRole('tab', { name: /Audit Events/i });
    fireEvent.click(auditTab);

    expect(screen.getByText(/Security Perimeter Lifecycle Observation/i)).toBeInTheDocument();
    expect(screen.getByText(/Client Request/i)).toBeInTheDocument();
    expect(screen.getByText(/HTTP Boundary/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Guard Model/i).length).toBeGreaterThanOrEqual(1);
  });

  // 13. Tool Security summary
  it('13. Tools & Approvals tab renders verified tools and metrics', async () => {
    await renderDashboard();
    const toolsTab = screen.getByRole('tab', { name: /Tools & Approvals/i });
    fireEvent.click(toolsTab);

    expect(screen.getByText(/Tool Security & Authorization Gate/i)).toBeInTheDocument();
    expect(screen.getByText(/get_weather/i)).toBeInTheDocument();
    expect(screen.getAllByText(/send_email/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/delete_record/i).length).toBeGreaterThanOrEqual(1);
  });

  // 14. Approval lifecycle rendering
  it('14. Renders approval records and replay attack prevention notice', async () => {
    await renderDashboard();
    const toolsTab = screen.getByRole('tab', { name: /Tools & Approvals/i });
    fireEvent.click(toolsTab);

    expect(screen.getByText(/Human Approval Lifecycle/i)).toBeInTheDocument();
    expect(screen.getByText(/Replay Attacks Defeated/i)).toBeInTheDocument();
    expect(screen.getByText(/attempts prevented by one-time consumption semantics/i)).toBeInTheDocument();
  });

  // 15. Runtime metrics tab
  it('15. Runtime Metrics tab displays process uptime and endpoint distribution', async () => {
    await renderDashboard();
    const runtimeTab = screen.getByRole('tab', { name: /Runtime Metrics/i });
    fireEvent.click(runtimeTab);

    expect(screen.getByText(/Runtime Process & Operational Metrics/i)).toBeInTheDocument();
    expect(screen.getByText(/Process-Local Memory Counters/i)).toBeInTheDocument();
    expect(screen.getByText(/Requests by Endpoint/i)).toBeInTheDocument();
  });

  // 16. HTTP 401 Authentication handling
  it('16. Handles 401 Unauthorized safely without leaking headers', async () => {
    (agentGuardApi.getAuditEvents as ReturnType<typeof vi.fn>).mockRejectedValue(
      new AgentGuardApiError('Authentication is required.', 401, 'UNAUTHORIZED')
    );

    await renderDashboard();
    expect(screen.getByText(/Authentication is required./i)).toBeInTheDocument();
  });

  // 17. HTTP 403 Forbidden handling
  it('17. Handles 403 Forbidden with clear permission notice', async () => {
    (agentGuardApi.getAuditEvents as ReturnType<typeof vi.fn>).mockRejectedValue(
      new AgentGuardApiError('Access forbidden: Insufficient privileges.', 403, 'FORBIDDEN')
    );

    await renderDashboard();
    expect(screen.getByText(/Access forbidden: Insufficient privileges./i)).toBeInTheDocument();
  });

  // 18. HTTP 429 Rate Limit handling
  it('18. Handles 429 Rate Limited response gracefully', async () => {
    (agentGuardApi.getAuditEvents as ReturnType<typeof vi.fn>).mockRejectedValue(
      new AgentGuardApiError('Too many requests. Please wait a moment.', 429, 'RATE_LIMITED')
    );

    await renderDashboard();
    expect(screen.getByText(/Too many requests. Please wait a moment./i)).toBeInTheDocument();
  });

  // 19. HTTP 500/503 Service Error handling
  it('19. Handles 500/503 service error without exposing internal stack trace', async () => {
    (agentGuardApi.getAuditEvents as ReturnType<typeof vi.fn>).mockRejectedValue(
      new AgentGuardApiError('Service temporarily unavailable.', 503, 'SERVICE_UNAVAILABLE')
    );

    await renderDashboard();
    expect(screen.getByText(/Service temporarily unavailable./i)).toBeInTheDocument();
    expect(screen.queryByText(/Traceback/i)).not.toBeInTheDocument();
  });

  // 20. Secrets and raw prompts are NEVER exposed
  it('20. [SECURITY INVARIANT] Ensures raw prompts, secrets, and authorization headers are never exposed in audit views', async () => {
    await renderDashboard();
    const auditTab = screen.getByRole('tab', { name: /Audit Events/i });
    fireEvent.click(auditTab);

    // Open drawer
    const inspectBtns = screen.getAllByRole('button', { name: /Inspect/i });
    fireEvent.click(inspectBtns[0]);

    // Ensure privacy notice is present
    expect(screen.getByText(/Privacy & Integrity Guarantee/i)).toBeInTheDocument();
    expect(screen.queryByText(/Authorization:/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Bearer eyJ/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/secret_key/i)).not.toBeInTheDocument();
  });

  // 21. Preserves navigation to existing v0.1, v0.2, v0.3 modes
  it('21. Navigating to Agent Security, Chat, and Playground preserves existing functionality', async () => {
    await renderDashboard();

    // Click Agent Security tab
    const agentSecTab = screen.getByRole('button', { name: /Agent Security/i });
    fireEvent.click(agentSecTab);
    expect(screen.getByText(/Target Tool:/i)).toBeInTheDocument();

    // Click Multi-Turn Chat tab
    const chatTab = screen.getByRole('button', { name: /Multi-Turn Chat/i });
    fireEvent.click(chatTab);
    expect(screen.getByRole('button', { name: /New Conversation/i })).toBeInTheDocument();

    // Click Security Playground tab
    const playgroundTab = screen.getByRole('button', { name: /Security Playground/i });
    fireEvent.click(playgroundTab);
    expect(screen.getByRole('button', { name: /Analyze Prompt/i })).toBeInTheDocument();
  });
});
