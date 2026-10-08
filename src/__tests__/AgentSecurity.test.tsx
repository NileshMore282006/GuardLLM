import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import App from '../App';
import { agentGuardApi, AgentGuardApiError } from '../api/agentguard';
import {
  ApprovalCreateResponse,
  ApprovalActionResponse,
  ToolCallResponse,
  HealthResponse,
} from '../types/agentguard';
import fs from 'fs';
import path from 'path';

// Mock API client
vi.mock('../api/agentguard', () => {
  return {
    API_BASE_URL: 'http://127.0.0.1:8000',
    AgentGuardApiError: class extends Error {
      public status: number;
      public code: string;
      constructor(message: string, status: number = 0, code: string = 'ERR') {
        super(message);
        this.status = status;
        this.code = code;
      }
    },
    agentGuardApi: {
      health: vi.fn(),
      guardPrompt: vi.fn(),
      executePrompt: vi.fn(),
      chat: vi.fn(),
      createApproval: vi.fn(),
      getApproval: vi.fn(),
      approve: vi.fn(),
      deny: vi.fn(),
      executeTool: vi.fn(),
    },
  };
});

describe('AgentGuard Frontend v0.3 — Agent Security Suite', () => {
  const mockHealth: HealthResponse = {
    status: 'ok',
    version: '1.0.0',
    guard_model: 'llama3.2:latest',
    target_model: 'llama3.2:latest',
  };

  beforeEach(() => {
    vi.clearAllMocks();
    (agentGuardApi.health as ReturnType<typeof vi.fn>).mockResolvedValue(mockHealth);
  });

  // Helper to render in agent-security mode
  const renderAgentSecurity = async () => {
    const utils = render(<App initialMode="agent-security" />);
    // Verify Agent Security tab is active
    expect(screen.getByRole('button', { name: /Agent Security/i })).toBeInTheDocument();
    return utils;
  };

  // 1. Tool selector renders
  it('1. Tool selector renders with confirmed backend tools', async () => {
    await renderAgentSecurity();

    const toolSelect = screen.getByLabelText(/Target Tool:/i) as HTMLSelectElement;
    expect(toolSelect).toBeInTheDocument();
    expect(toolSelect.options.length).toBe(4);
    expect(screen.getByText(/get_weather/i)).toBeInTheDocument();
    expect(screen.getByText(/search_documents/i)).toBeInTheDocument();
    expect(screen.getByText(/send_email/i)).toBeInTheDocument();
    expect(screen.getByText(/delete_record/i)).toBeInTheDocument();
  });

  // 2. Tool arguments JSON validation
  it('2. Tool arguments JSON validation enforces valid JSON format and shows error', async () => {
    await renderAgentSecurity();

    const editor = screen.getByLabelText(/Tool Arguments \(JSON\):/i) as HTMLTextAreaElement;
    const submitBtn = screen.getByRole('button', { name: /Analyze Tool Request/i });

    // Enter invalid JSON
    fireEvent.change(editor, { target: { value: '{"city": "Mumbai"' } });

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/JSON Syntax Error/i);
      expect(submitBtn).toBeDisabled();
    });

    // Enter valid JSON
    fireEvent.change(editor, { target: { value: '{"city": "Mumbai"}' } });

    await waitFor(() => {
      expect(screen.getByText(/Valid JSON format/i)).toBeInTheDocument();
      expect(submitBtn).not.toBeDisabled();
    });
  });

  // 3. Tool request submission
  it('3. Tool request submission invokes createApproval with parsed arguments', async () => {
    const mockAllowCreate: ApprovalCreateResponse = {
      request_id: 'req-tool-001',
      approval_id: null,
      decision: 'ALLOW',
      approval_status: 'NOT_REQUIRED',
      tool_name: 'get_weather',
      risk_level: 'low',
      arguments_summary: "city: 'Mumbai'",
      reason: 'Low-risk tool; no approval required by policy.',
      created_at: 1700000000,
      expires_at: null,
      result: null,
      latency_ms: 12.5,
    };

    const mockToolExec: ToolCallResponse = {
      request_id: 'req-exec-001',
      decision: 'ALLOW',
      tool_name: 'get_weather',
      result: 'Weather report for Mumbai: 27°C, Partly Cloudy.',
      latency_ms: 15.2,
      risk_level: 'low',
      attack_type: 'none',
      approval_id: null,
      approval_status: 'NOT_REQUIRED',
    };

    (agentGuardApi.createApproval as ReturnType<typeof vi.fn>).mockResolvedValue(mockAllowCreate);
    (agentGuardApi.executeTool as ReturnType<typeof vi.fn>).mockResolvedValue(mockToolExec);

    await renderAgentSecurity();

    const submitBtn = screen.getByRole('button', { name: /Analyze Tool Request/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(agentGuardApi.createApproval).toHaveBeenCalledWith(
        expect.objectContaining({
          tool_name: 'get_weather',
          arguments: { city: 'Mumbai' },
        }),
        '',
        expect.any(AbortSignal)
      );
    });
  });

  // 4. ALLOW result auto-executes and displays result
  it('4. ALLOW result triggers execution through backend Tool Gateway', async () => {
    const mockAllowCreate: ApprovalCreateResponse = {
      request_id: 'req-allow-01',
      approval_id: null,
      decision: 'ALLOW',
      approval_status: 'NOT_REQUIRED',
      tool_name: 'get_weather',
      risk_level: 'low',
      arguments_summary: "city: 'Delhi'",
      reason: 'Low-risk tool',
      created_at: 1700000000,
      expires_at: null,
      result: null,
      latency_ms: 8.0,
    };

    const mockToolExec: ToolCallResponse = {
      request_id: 'req-exec-01',
      decision: 'ALLOW',
      tool_name: 'get_weather',
      result: 'Weather report for Delhi: 30°C, Clear.',
      latency_ms: 10.0,
      risk_level: 'low',
      attack_type: 'none',
      approval_id: null,
      approval_status: 'NOT_REQUIRED',
    };

    (agentGuardApi.createApproval as ReturnType<typeof vi.fn>).mockResolvedValue(mockAllowCreate);
    (agentGuardApi.executeTool as ReturnType<typeof vi.fn>).mockResolvedValue(mockToolExec);

    await renderAgentSecurity();

    fireEvent.click(screen.getByRole('button', { name: /Analyze Tool Request/i }));

    await waitFor(() => {
      expect(agentGuardApi.executeTool).toHaveBeenCalled();
      expect(screen.getByText(/Weather report for Delhi: 30°C, Clear\./i)).toBeInTheDocument();
      expect(screen.getAllByText(/UNTRUSTED DATA/i).length).toBeGreaterThan(0);
    });
  });

  // 5. BLOCK result shows BLOCKED and never calls tool executor
  it('5. BLOCK result displays block reason and never calls tool execution endpoint', async () => {
    const mockBlockCreate: ApprovalCreateResponse = {
      request_id: 'req-block-01',
      approval_id: null,
      decision: 'BLOCK',
      approval_status: 'DENIED',
      tool_name: 'search_documents',
      risk_level: 'low',
      arguments_summary: null,
      reason: 'Security violation: prompt_injection_in_arguments',
      created_at: 1700000000,
      expires_at: null,
      result: null,
      latency_ms: 5.5,
    };

    (agentGuardApi.createApproval as ReturnType<typeof vi.fn>).mockResolvedValue(mockBlockCreate);

    await renderAgentSecurity();

    // Select search_documents
    const select = screen.getByLabelText(/Target Tool:/i);
    fireEvent.change(select, { target: { value: 'search_documents' } });

    fireEvent.click(screen.getByRole('button', { name: /Analyze Tool Request/i }));

    await waitFor(() => {
      expect(screen.getAllByText('BLOCK').length).toBeGreaterThan(0);
      expect(screen.getAllByText(/Security violation: prompt_injection_in_arguments/i)[0]).toBeInTheDocument();
      // SECURITY INVARIANT: tool executor was NEVER called!
      expect(agentGuardApi.executeTool).not.toHaveBeenCalled();
    });
  });

  // 6. REQUIRE_APPROVAL / PENDING_APPROVAL result displays human approval card
  it('6. REQUIRE_APPROVAL result creates PENDING_APPROVAL state and renders Human Approval Card', async () => {
    const mockPendingCreate: ApprovalCreateResponse = {
      request_id: 'req-pending-01',
      approval_id: 'appr_0123456789abcdef0123456789abcdef',
      decision: 'PENDING_APPROVAL',
      approval_status: 'PENDING_APPROVAL',
      tool_name: 'send_email',
      risk_level: 'high',
      arguments_summary: "recipient: 'a***@example.com'; subject: 'Report'",
      reason: 'Action requires approval due to high risk level.',
      created_at: 1700000000,
      expires_at: 1700000300,
      result: null,
      latency_ms: 14.2,
    };

    (agentGuardApi.createApproval as ReturnType<typeof vi.fn>).mockResolvedValue(mockPendingCreate);

    await renderAgentSecurity();

    // Select send_email
    const select = screen.getByLabelText(/Target Tool:/i);
    fireEvent.change(select, { target: { value: 'send_email' } });

    fireEvent.click(screen.getByRole('button', { name: /Analyze Tool Request/i }));

    await waitFor(() => {
      expect(screen.getByText('HUMAN APPROVAL REQUIRED')).toBeInTheDocument();
      expect(screen.getAllByText('PENDING_APPROVAL').length).toBeGreaterThan(0);
      expect(screen.getByRole('button', { name: /Approve/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Deny/i })).toBeInTheDocument();
      // Tool executor must NOT have been called yet
      expect(agentGuardApi.executeTool).not.toHaveBeenCalled();
    });
  });

  // 7. Approve API call
  it('7. Clicking Approve calls real approve endpoint and consumes token', async () => {
    const mockPendingCreate: ApprovalCreateResponse = {
      request_id: 'req-pending-02',
      approval_id: 'appr_aabbccddeeff00112233445566778899',
      decision: 'PENDING_APPROVAL',
      approval_status: 'PENDING_APPROVAL',
      tool_name: 'send_email',
      risk_level: 'high',
      arguments_summary: "recipient: 'alice@example.com'",
      reason: 'High risk action',
      created_at: 1700000000,
      expires_at: 1700000300,
      result: null,
      latency_ms: 10.0,
    };

    const mockApproveOutcome: ApprovalActionResponse = {
      request_id: 'req-pending-02',
      approval_id: 'appr_aabbccddeeff00112233445566778899',
      decision: 'ALLOW',
      approval_status: 'CONSUMED',
      tool_name: 'send_email',
      result: 'MOCK_SIMULATION: Email queued to alice@example.com.',
      risk_level: 'high',
      latency_ms: 22.0,
      attack_type: 'none',
    };

    (agentGuardApi.createApproval as ReturnType<typeof vi.fn>).mockResolvedValue(mockPendingCreate);
    (agentGuardApi.approve as ReturnType<typeof vi.fn>).mockResolvedValue(mockApproveOutcome);

    await renderAgentSecurity();

    const select = screen.getByLabelText(/Target Tool:/i);
    fireEvent.change(select, { target: { value: 'send_email' } });
    fireEvent.click(screen.getByRole('button', { name: /Analyze Tool Request/i }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Approve/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Approve/i }));

    await waitFor(() => {
      expect(agentGuardApi.approve).toHaveBeenCalledWith(
        'appr_aabbccddeeff00112233445566778899',
        '',
        expect.any(AbortSignal)
      );
      expect(screen.getByText(/MOCK_SIMULATION: Email queued to alice@example.com\./i)).toBeInTheDocument();
      expect(screen.getByText(/HUMAN APPROVAL: COMPLETED & EXECUTED/i)).toBeInTheDocument();
    });
  });

  // 8. Deny API call
  it('8. Clicking Deny calls real deny endpoint and prevents execution', async () => {
    const mockPendingCreate: ApprovalCreateResponse = {
      request_id: 'req-pending-03',
      approval_id: 'appr_deny1234567890abcdef1234567890ab',
      decision: 'PENDING_APPROVAL',
      approval_status: 'PENDING_APPROVAL',
      tool_name: 'delete_record',
      risk_level: 'critical',
      arguments_summary: "record_id: 'rec-99'",
      reason: 'Critical destructive action',
      created_at: 1700000000,
      expires_at: 1700000300,
      result: null,
      latency_ms: 11.0,
    };

    const mockDenyOutcome: ApprovalActionResponse = {
      request_id: 'req-pending-03',
      approval_id: 'appr_deny1234567890abcdef1234567890ab',
      decision: 'BLOCK',
      approval_status: 'DENIED',
      tool_name: 'delete_record',
      result: null,
      risk_level: 'critical',
      attack_type: 'none',
    };

    (agentGuardApi.createApproval as ReturnType<typeof vi.fn>).mockResolvedValue(mockPendingCreate);
    (agentGuardApi.deny as ReturnType<typeof vi.fn>).mockResolvedValue(mockDenyOutcome);

    await renderAgentSecurity();

    const select = screen.getByLabelText(/Target Tool:/i);
    fireEvent.change(select, { target: { value: 'delete_record' } });
    fireEvent.click(screen.getByRole('button', { name: /Analyze Tool Request/i }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Deny/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Deny/i }));

    await waitFor(() => {
      expect(agentGuardApi.deny).toHaveBeenCalledWith(
        'appr_deny1234567890abcdef1234567890ab',
        '',
        expect.any(AbortSignal)
      );
      expect(screen.getByText(/HUMAN APPROVAL: DENIED/i)).toBeInTheDocument();
      expect(screen.getByText(/DENIED — Execution blocked\./i)).toBeInTheDocument();
      expect(agentGuardApi.executeTool).not.toHaveBeenCalled();
    });
  });

  // 9. Replay attack handling (409 Conflict)
  it('9. [SECURITY INVARIANT] Approval replay returns 409 conflict and displays consumed message', async () => {
    const mockPendingCreate: ApprovalCreateResponse = {
      request_id: 'req-replay-01',
      approval_id: 'appr_replay00001111222233334444555566',
      decision: 'PENDING_APPROVAL',
      approval_status: 'PENDING_APPROVAL',
      tool_name: 'send_email',
      risk_level: 'high',
      arguments_summary: "recipient: 'alice@example.com'",
      reason: 'High risk action',
      created_at: 1700000000,
      expires_at: 1700000300,
      result: null,
      latency_ms: 10.0,
    };

    const mockApproveOutcome: ApprovalActionResponse = {
      request_id: 'req-replay-01',
      approval_id: 'appr_replay00001111222233334444555566',
      decision: 'ALLOW',
      approval_status: 'CONSUMED',
      tool_name: 'send_email',
      result: 'MOCK_SIMULATION: Email queued.',
      risk_level: 'high',
      latency_ms: 20.0,
      attack_type: 'none',
    };

    (agentGuardApi.createApproval as ReturnType<typeof vi.fn>).mockResolvedValue(mockPendingCreate);
    (agentGuardApi.approve as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce(mockApproveOutcome)
      .mockRejectedValueOnce(
        new AgentGuardApiError('Approval has already been consumed.', 409, 'APPROVAL_ALREADY_CONSUMED')
      );

    await renderAgentSecurity();

    const select = screen.getByLabelText(/Target Tool:/i);
    fireEvent.change(select, { target: { value: 'send_email' } });
    fireEvent.click(screen.getByRole('button', { name: /Analyze Tool Request/i }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Approve/i })).toBeInTheDocument();
    });

    // 1st call: Approved and consumed
    fireEvent.click(screen.getByRole('button', { name: /Approve/i }));

    await waitFor(() => {
      expect(screen.getByText(/HUMAN APPROVAL: COMPLETED & EXECUTED/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Attempt Replay/i })).toBeInTheDocument();
    });

    // 2nd call: Replay attempt
    fireEvent.click(screen.getByRole('button', { name: /Attempt Replay/i }));

    await waitFor(() => {
      expect(screen.getByText(/Approval has already been consumed\./i)).toBeInTheDocument();
    });
  });

  // 10. Argument modification handling (Argument Tampering Invariant)
  it('10. [SECURITY INVARIANT] Modifying arguments after approval creation warns and prevents execution', async () => {
    const mockPendingCreate: ApprovalCreateResponse = {
      request_id: 'req-tamper-01',
      approval_id: 'appr_tamper000011112222333344445555',
      decision: 'PENDING_APPROVAL',
      approval_status: 'PENDING_APPROVAL',
      tool_name: 'send_email',
      risk_level: 'high',
      arguments_summary: "recipient: 'alice@example.com'",
      reason: 'High risk action',
      created_at: 1700000000,
      expires_at: 1700000300,
      result: null,
      latency_ms: 10.0,
    };

    (agentGuardApi.createApproval as ReturnType<typeof vi.fn>).mockResolvedValue(mockPendingCreate);

    await renderAgentSecurity();

    const select = screen.getByLabelText(/Target Tool:/i);
    fireEvent.change(select, { target: { value: 'send_email' } });
    fireEvent.click(screen.getByRole('button', { name: /Analyze Tool Request/i }));

    await waitFor(() => {
      expect(screen.getByText('HUMAN APPROVAL REQUIRED')).toBeInTheDocument();
    });

    // Tamper with arguments in the editor: change recipient to attacker
    const editor = screen.getByLabelText(/Tool Arguments \(JSON\):/i);
    fireEvent.change(editor, {
      target: {
        value: JSON.stringify({
          recipient: 'attacker@example.com',
          subject: 'Tampered Subject',
          body: 'Tampered Body',
        }),
      },
    });

    await waitFor(() => {
      expect(
        screen.getByText(/Approval invalidated: tool arguments changed since authorization\./i)
      ).toBeInTheDocument();
    });

    // Attempting to approve now is blocked locally
    fireEvent.click(screen.getByRole('button', { name: /Approve/i }));

    await waitFor(() => {
      expect(
        screen.getByText(/Cannot approve: arguments have been tampered with since creation\./i)
      ).toBeInTheDocument();
      expect(agentGuardApi.approve).not.toHaveBeenCalled();
    });
  });

  // 11. Expired approval handling
  it('11. [SECURITY INVARIANT] Expired approval returns error and disables execution', async () => {
    const mockPendingCreate: ApprovalCreateResponse = {
      request_id: 'req-exp-01',
      approval_id: 'appr_exp00001111222233334444555566667',
      decision: 'PENDING_APPROVAL',
      approval_status: 'PENDING_APPROVAL',
      tool_name: 'send_email',
      risk_level: 'high',
      arguments_summary: "recipient: 'alice@example.com'",
      reason: 'High risk action',
      created_at: 1700000000,
      expires_at: 1700000300,
      result: null,
      latency_ms: 10.0,
    };

    (agentGuardApi.createApproval as ReturnType<typeof vi.fn>).mockResolvedValue(mockPendingCreate);
    (agentGuardApi.approve as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new AgentGuardApiError('Approval has expired.', 400, 'APPROVAL_EXPIRED')
    );

    await renderAgentSecurity();

    const select = screen.getByLabelText(/Target Tool:/i);
    fireEvent.change(select, { target: { value: 'send_email' } });
    fireEvent.click(screen.getByRole('button', { name: /Analyze Tool Request/i }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Approve/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Approve/i }));

    await waitFor(() => {
      expect(screen.getAllByText('EXPIRED').length).toBeGreaterThan(0);
      expect(screen.getByText(/HUMAN APPROVAL: EXPIRED/i)).toBeInTheDocument();
      expect(agentGuardApi.executeTool).not.toHaveBeenCalled();
    });
  });

  // 12. HTTP 401 handling
  it('12. HTTP 401 Authentication error displays safe message and does not auto-retry', async () => {
    (agentGuardApi.createApproval as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new AgentGuardApiError('Authentication is required.', 401, 'UNAUTHORIZED')
    );

    await renderAgentSecurity();

    fireEvent.click(screen.getByRole('button', { name: /Analyze Tool Request/i }));

    await waitFor(() => {
      expect(screen.getAllByText(/Authentication is required\./i)[0]).toBeInTheDocument();
      expect(agentGuardApi.createApproval).toHaveBeenCalledTimes(1);
    });
  });

  // 13. HTTP 403 Forbidden handling
  it('13. HTTP 403 Forbidden error displays safe message without leaking internal roles', async () => {
    (agentGuardApi.createApproval as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new AgentGuardApiError('Access forbidden: Insufficient privileges.', 403, 'FORBIDDEN')
    );

    await renderAgentSecurity();

    fireEvent.click(screen.getByRole('button', { name: /Analyze Tool Request/i }));

    await waitFor(() => {
      expect(screen.getAllByText(/Access forbidden: Insufficient privileges\./i)[0]).toBeInTheDocument();
    });
  });

  // 14. HTTP 429 Rate limiting handling
  it('14. HTTP 429 Rate limited response displays retry message without automatic loop', async () => {
    (agentGuardApi.createApproval as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new AgentGuardApiError('Too many requests. Rate limit exceeded.', 429, 'RATE_LIMITED')
    );

    await renderAgentSecurity();

    fireEvent.click(screen.getByRole('button', { name: /Analyze Tool Request/i }));

    await waitFor(() => {
      expect(screen.getAllByText(/Too many requests\. Rate limit exceeded\./i)[0]).toBeInTheDocument();
      expect(agentGuardApi.createApproval).toHaveBeenCalledTimes(1);
    });
  });

  // 15. HTTP 500 / 503 handling
  it('15. HTTP 500/503 Service error displays safe error and does not leak backend stack trace', async () => {
    (agentGuardApi.createApproval as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new AgentGuardApiError('An internal server error occurred in AgentGuard.', 500, 'INTERNAL_ERROR')
    );

    await renderAgentSecurity();

    fireEvent.click(screen.getByRole('button', { name: /Analyze Tool Request/i }));

    await waitFor(() => {
      expect(screen.getAllByText(/An internal server error occurred in AgentGuard\./i)[0]).toBeInTheDocument();
      // Verify no python tracebacks are shown
      expect(screen.queryByText(/Traceback/i)).not.toBeInTheDocument();
      expect(screen.queryByText(/sqlite3/i)).not.toBeInTheDocument();
    });
  });

  // 16. Indirect Tool Injection scenario
  it('16. Indirect Tool Injection result displays as untrusted data with safety notice', async () => {
    const mockToolExec: ToolCallResponse = {
      request_id: 'req-indirect-01',
      decision: 'ALLOW',
      tool_name: 'search_documents',
      result: 'Documentation Search: [UNTRUSTED TOOL DATA FILTERED: Adversarial instruction stripped]',
      latency_ms: 12.0,
      risk_level: 'low',
      attack_type: 'indirect_prompt_injection',
      approval_id: null,
      approval_status: 'NOT_REQUIRED',
    };

    const mockAllowCreate: ApprovalCreateResponse = {
      request_id: 'req-indirect-01',
      approval_id: null,
      decision: 'ALLOW',
      approval_status: 'NOT_REQUIRED',
      tool_name: 'search_documents',
      risk_level: 'low',
      arguments_summary: "query: 'override test'",
      reason: 'Low risk search',
      created_at: 1700000000,
      expires_at: null,
      result: null,
      latency_ms: 8.0,
    };

    (agentGuardApi.createApproval as ReturnType<typeof vi.fn>).mockResolvedValue(mockAllowCreate);
    (agentGuardApi.executeTool as ReturnType<typeof vi.fn>).mockResolvedValue(mockToolExec);

    await renderAgentSecurity();

    const select = screen.getByLabelText(/Target Tool:/i);
    fireEvent.change(select, { target: { value: 'search_documents' } });
    fireEvent.click(screen.getByRole('button', { name: /Analyze Tool Request/i }));

    await waitFor(() => {
      expect(screen.getByText(/Indirect Injection Detected:/i)).toBeInTheDocument();
      expect(screen.getAllByText(/UNTRUSTED DATA/i).length).toBeGreaterThan(0);
      expect(screen.getAllByText(/SANITIZED/i)[0]).toBeInTheDocument();
    });
  });

  // 17. Security Scenario Chips
  it('17. Quick Security Scenario chips populate composer without auto-executing', async () => {
    await renderAgentSecurity();

    const weatherChip = screen.getByRole('button', { name: /Low-Risk Tool/i });
    fireEvent.click(weatherChip);

    const select = screen.getByLabelText(/Target Tool:/i) as HTMLSelectElement;
    expect(select.value).toBe('get_weather');

    const emailChip = screen.getByRole('button', { name: /High-Risk Email/i });
    fireEvent.click(emailChip);

    expect(select.value).toBe('send_email');
    const editor = screen.getByLabelText(/Tool Arguments \(JSON\):/i) as HTMLTextAreaElement;
    expect(editor.value).toContain('alice@example.com');

    // Not automatically executed!
    expect(agentGuardApi.createApproval).not.toHaveBeenCalled();
  });

  // 18. Telemetry Details Expand/Collapse
  it('18. Tool Request Details section expands to show telemetry and redacts secrets', async () => {
    await renderAgentSecurity();

    const toggleBtn = screen.getByRole('button', { name: /Tool Request Details & Telemetry/i });
    fireEvent.click(toggleBtn);

    await waitFor(() => {
      expect(screen.getByText(/Canonical Arguments \(Safe Representation\):/i)).toBeInTheDocument();
      expect(screen.getByText(/Execution State:/i)).toBeInTheDocument();
    });
  });

  // 19. Session Event History
  it('19. Session Event History records events in memory and clears on button click', async () => {
    const mockAllowCreate: ApprovalCreateResponse = {
      request_id: 'req-hist-01',
      approval_id: null,
      decision: 'ALLOW',
      approval_status: 'NOT_REQUIRED',
      tool_name: 'get_weather',
      risk_level: 'low',
      arguments_summary: "city: 'Mumbai'",
      reason: 'Low risk',
      created_at: 1700000000,
      expires_at: null,
      result: null,
      latency_ms: 10.0,
    };

    const mockToolExec: ToolCallResponse = {
      request_id: 'req-hist-01',
      decision: 'ALLOW',
      tool_name: 'get_weather',
      result: 'Weather report: 25°C.',
      latency_ms: 10.0,
      risk_level: 'low',
      attack_type: 'none',
      approval_id: null,
      approval_status: 'NOT_REQUIRED',
    };

    (agentGuardApi.createApproval as ReturnType<typeof vi.fn>).mockResolvedValue(mockAllowCreate);
    (agentGuardApi.executeTool as ReturnType<typeof vi.fn>).mockResolvedValue(mockToolExec);

    await renderAgentSecurity();

    fireEvent.click(screen.getByRole('button', { name: /Analyze Tool Request/i }));

    await waitFor(() => {
      expect(screen.getByText(/Session Event History \(1\)/i)).toBeInTheDocument();
    });

    // Clear history
    fireEvent.click(screen.getByRole('button', { name: /Clear/i }));

    await waitFor(() => {
      expect(screen.getByText(/No tool security events in this session yet\./i)).toBeInTheDocument();
    });
  });

  // 20. [SECURITY AUDIT] No secrets in source code
  it('20. [SECURITY AUDIT] No sensitive keys or secrets exist in frontend codebase', () => {
    const srcDir = path.resolve(process.cwd(), 'src');
    const files = fs.readdirSync(srcDir, { recursive: true }) as string[];

    const forbiddenPatterns = [
      /AGENTGUARD_MASTER_KEY/i,
      /AGENTGUARD_AUDIT_INTEGRITY_KEY/i,
      /BLUE-ORANGE-42/,
      /argon2id/i,
      /ag_[0-9a-f]{16}_/i,
      /eval\(/,
      /exec\(/,
    ];

    for (const file of files) {
      if (
        typeof file === 'string' &&
        (file.endsWith('.ts') || file.endsWith('.tsx') || file.endsWith('.css'))
      ) {
        const fullPath = path.join(srcDir, file);
        if (fs.statSync(fullPath).isFile() && !fullPath.includes('.test.tsx')) {
          const content = fs.readFileSync(fullPath, 'utf-8');
          for (const pattern of forbiddenPatterns) {
            expect(content).not.toMatch(pattern);
          }
        }
      }
    }
  });

  // 21. [SECURITY INVARIANT] Frontend never calls operating-system tools or direct execution
  it('21. [SECURITY INVARIANT] Frontend codebase has zero OS/shell/eval invocation logic', () => {
    const srcDir = path.resolve(process.cwd(), 'src');
    const files = fs.readdirSync(srcDir, { recursive: true }) as string[];

    const forbiddenCalls = [
      /\bchild_process\b/,
      /\bexecSync\b/,
      /\bspawnSync\b/,
      /\bfs\b\.(writeFile|unlink|rmdir)/,
      /\bprocess\.env\.OLLAMA\b/,
    ];

    for (const file of files) {
      if (typeof file === 'string' && (file.endsWith('.ts') || file.endsWith('.tsx'))) {
        const fullPath = path.join(srcDir, file);
        if (fs.statSync(fullPath).isFile() && !fullPath.includes('.test.tsx')) {
          const content = fs.readFileSync(fullPath, 'utf-8');
          for (const pattern of forbiddenCalls) {
            expect(content).not.toMatch(pattern);
          }
        }
      }
    }
  });
});
