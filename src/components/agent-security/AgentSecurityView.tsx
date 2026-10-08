import React, { useState, useRef } from 'react';
import {
  ToolSecurityState,
  ToolRiskLevel,
  ToolSecurityDecision,
  ApprovalStatus,
  ApprovalCreateResponse,
  ApprovalActionResponse,
  ToolCallResponse,
  ToolTimelineEvent,
  ToolSecurityHistoryItem,
} from '../../types/agentguard';
import { agentGuardApi, AgentGuardApiError } from '../../api/agentguard';
import { CONFIRMED_BACKEND_TOOLS } from './toolRegistry';
import { ToolComposer } from './ToolComposer';
import { HumanApprovalCard } from './HumanApprovalCard';
import { ToolRiskCard } from './ToolRiskCard';
import { ToolResultDisplay } from './ToolResultDisplay';
import { ToolSecurityTimeline } from './ToolSecurityTimeline';
import { ToolRequestDetails } from './ToolRequestDetails';
import { ToolSecurityHistory } from './ToolSecurityHistory';
import { SecurityContextCard } from './SecurityContextCard';
import { AlertCircle } from 'lucide-react';

interface AgentSecurityViewProps {
  developerToken: string;
  setDeveloperToken: (token: string) => void;
}

export const AgentSecurityView: React.FC<AgentSecurityViewProps> = ({
  developerToken,
  setDeveloperToken,
}) => {
  // Composer state
  const [selectedToolName, setSelectedToolName] = useState<string>(
    CONFIRMED_BACKEND_TOOLS[0].tool_name
  );
  const [argumentsJson, setArgumentsJson] = useState<string>(
    JSON.stringify(CONFIRMED_BACKEND_TOOLS[0].default_arguments, null, 2)
  );

  // Snapshot of arguments at time of approval creation (to detect argument tampering)
  const [approvedArgsSnapshot, setApprovedArgsSnapshot] = useState<string | null>(null);
  const [tamperWarning, setTamperWarning] = useState<string | null>(null);

  // Overall security state machine
  const [securityState, setSecurityState] = useState<ToolSecurityState>('IDLE');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [replayMessage, setReplayMessage] = useState<string | null>(null);

  // Backend response models
  const [approvalCreateData, setApprovalCreateData] = useState<ApprovalCreateResponse | null>(null);
  const [approvalActionData, setApprovalActionData] = useState<ApprovalActionResponse | null>(null);
  const [, setToolCallData] = useState<ToolCallResponse | null>(null);

  // Active status representations
  const [activeDecision, setActiveDecision] = useState<ToolSecurityDecision | null>(null);
  const [activeRiskLevel, setActiveRiskLevel] = useState<ToolRiskLevel | null>(null);
  const [activeApprovalStatus, setActiveApprovalStatus] = useState<ApprovalStatus | null>(null);
  const [activeResult, setActiveResult] = useState<string | null>(null);
  const [activeAttackType, setActiveAttackType] = useState<string | null>(null);
  const [activeLatency, setActiveLatency] = useState<number | null>(null);
  const [activeReason, setActiveReason] = useState<string | null>(null);
  const [activeRequestId, setActiveRequestId] = useState<string | null>(null);
  const [activeApprovalId, setActiveApprovalId] = useState<string | null>(null);

  // Telemetry: Timeline & Session History
  const [timelineEvents, setTimelineEvents] = useState<ToolTimelineEvent[]>([]);
  const [history, setHistory] = useState<ToolSecurityHistoryItem[]>([]);

  // AbortController for cancelation
  const abortControllerRef = useRef<AbortController | null>(null);

  // Helper to add timeline event
  const addTimelineEvent = (
    stage: string,
    status: ToolTimelineEvent['status'],
    detail: string,
    backendTimestamp?: number
  ) => {
    const timestampStr = backendTimestamp
      ? new Date(backendTimestamp * 1000).toLocaleTimeString()
      : new Date().toLocaleTimeString();

    setTimelineEvents((prev) => [
      ...prev,
      {
        id: `tl-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        stage,
        status,
        timestamp: timestampStr,
        detail,
        isBackendTimestamp: Boolean(backendTimestamp),
      },
    ]);
  };

  // Helper to append to session history
  const appendHistory = (
    toolName: string,
    decision: ToolSecurityDecision,
    risk: ToolRiskLevel | null,
    approvalStatus: ApprovalStatus | null,
    result: string | null,
    latency: number,
    attackType?: string | null
  ) => {
    const newItem: ToolSecurityHistoryItem = {
      id: `hist-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toLocaleTimeString(),
      tool_name: toolName,
      decision,
      risk_level: risk,
      approval_status: approvalStatus,
      result,
      latency_ms: latency,
      attack_type: attackType,
    };
    setHistory((prev) => [newItem, ...prev.slice(0, 19)]);
  };

  // Handle Tool Selection
  const handleToolChange = (toolName: string, defaultArgsJson: string) => {
    setSelectedToolName(toolName);
    setArgumentsJson(defaultArgsJson);
    setApprovedArgsSnapshot(null);
    setTamperWarning(null);
    setReplayMessage(null);
  };

  // Handle Arguments editing with tampering check
  const handleArgumentsChange = (newJson: string) => {
    setArgumentsJson(newJson);

    // If an approval ID already exists and the user alters arguments, flag tampering
    if (approvedArgsSnapshot !== null && activeApprovalId) {
      try {
        const parsedNew = JSON.stringify(JSON.parse(newJson));
        const parsedSnap = JSON.stringify(JSON.parse(approvedArgsSnapshot));
        if (parsedNew !== parsedSnap) {
          setTamperWarning('Approval invalidated: tool arguments changed since authorization.');
        } else {
          setTamperWarning(null);
        }
      } catch {
        setTamperWarning('Approval invalidated: tool arguments changed.');
      }
    }
  };

  // =========================================================================
  // Primary Workflow: Analyze & Request Tool Action
  // =========================================================================
  const handleAnalyzeToolRequest = async () => {
    setErrorMessage(null);
    setReplayMessage(null);
    setTamperWarning(null);
    setActiveResult(null);
    setApprovalActionData(null);
    setTimelineEvents([]);

    let parsedArgs: Record<string, any>;
    try {
      parsedArgs = JSON.parse(argumentsJson);
    } catch {
      setErrorMessage('Cannot submit malformed JSON arguments.');
      return;
    }

    setSecurityState('ANALYZING');
    const nowStr = new Date().toLocaleTimeString();

    // Reset timeline
    setTimelineEvents([
      {
        id: 'tl-start',
        stage: 'Tool Request Created',
        status: 'PENDING',
        timestamp: nowStr,
        detail: `Proposing tool '${selectedToolName}' with user-supplied arguments.`,
      },
    ]);

    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    try {
      // 1. Submit proposal to backend approval & risk gateway (POST /api/v1/approvals)
      const approvalResp = await agentGuardApi.createApproval(
        {
          tool_name: selectedToolName,
          arguments: parsedArgs,
        },
        developerToken,
        abortController.signal
      );

      setApprovalCreateData(approvalResp);
      setActiveRequestId(approvalResp.request_id);
      setActiveDecision(approvalResp.decision);
      setActiveRiskLevel(approvalResp.risk_level);
      setActiveApprovalStatus(approvalResp.approval_status);
      setActiveReason(approvalResp.reason);
      setActiveAttackType(null);
      setActiveLatency(approvalResp.latency_ms || null);

      // Branch A: BLOCK (Unknown tool, argument injection, schema violation)
      if (approvalResp.decision === 'BLOCK') {
        setSecurityState('BLOCKED');
        addTimelineEvent(
          'Tool Guard',
          'BLOCKED',
          approvalResp.reason || 'Rejected by AgentGuard Tool Guard.'
        );
        addTimelineEvent(
          'Tool Execution',
          'BLOCKED',
          'Blocked actions are NEVER executed by the backend.'
        );
        appendHistory(
          selectedToolName,
          'BLOCK',
          approvalResp.risk_level,
          approvalResp.approval_status,
          null,
          approvalResp.latency_ms || 0
        );
        return;
      }

      // Branch B: PENDING_APPROVAL (High-risk or critical action requiring human authorization)
      if (approvalResp.decision === 'PENDING_APPROVAL') {
        setSecurityState('PENDING_APPROVAL');
        setActiveApprovalId(approvalResp.approval_id);
        setApprovedArgsSnapshot(argumentsJson);

        addTimelineEvent(
          'Tool Guard',
          'ALLOWED',
          'Argument schema and injection filters validated successfully.'
        );
        addTimelineEvent(
          'Policy Gate',
          'PENDING APPROVAL',
          `Requires human approval due to ${approvalResp.risk_level} risk level.`
        );
        addTimelineEvent(
          'Approval Created',
          'PENDING APPROVAL',
          `Cryptographic approval ID '${approvalResp.approval_id}' generated by server.`,
          approvalResp.created_at || undefined
        );

        appendHistory(
          selectedToolName,
          'PENDING_APPROVAL',
          approvalResp.risk_level,
          'PENDING_APPROVAL',
          null,
          approvalResp.latency_ms || 0
        );
        return;
      }

      // Branch C: ALLOW (Low-risk tool, no approval required by policy)
      if (approvalResp.decision === 'ALLOW') {
        addTimelineEvent(
          'Tool Guard',
          'ALLOWED',
          'Argument safety passed; tool is registered and safe.'
        );
        addTimelineEvent(
          'Policy Gate',
          'ALLOWED',
          'Low-risk tool; no human approval required by policy.'
        );

        // Execute tool directly through authoritative POST /api/v1/tool/execute
        setSecurityState('EXECUTING');
        addTimelineEvent(
          'Tool Execution',
          'PENDING',
          'Dispatching authorized request to backend Tool Gateway...'
        );

        const execResp = await agentGuardApi.executeTool(
          {
            tool_name: selectedToolName,
            arguments: parsedArgs,
          },
          developerToken,
          abortController.signal
        );

        setToolCallData(execResp);
        setActiveDecision(execResp.decision);
        setActiveRiskLevel(execResp.risk_level || approvalResp.risk_level);
        setActiveApprovalStatus(execResp.approval_status || 'NOT_REQUIRED');
        setActiveResult(execResp.result);
        setActiveAttackType(execResp.attack_type || null);
        setActiveLatency(execResp.latency_ms);

        if (execResp.decision === 'ALLOW') {
          setSecurityState('ALLOWED');
          addTimelineEvent(
            'Tool Execution',
            'CONSUMED',
            'Executed deterministic mock tool successfully.'
          );
          addTimelineEvent(
            'Result Guard',
            'ALLOWED',
            execResp.attack_type && execResp.attack_type !== 'none'
              ? `Tool output sanitized: ${execResp.attack_type}.`
              : 'Tool result sanitized and marked as UNTRUSTED DATA.'
          );
        } else {
          setSecurityState('BLOCKED');
          addTimelineEvent(
            'Tool Execution',
            'BLOCKED',
            `Execution rejected: ${execResp.attack_type || 'authorization error'}.`
          );
        }

        appendHistory(
          selectedToolName,
          execResp.decision,
          execResp.risk_level || approvalResp.risk_level,
          execResp.approval_status || null,
          execResp.result,
          execResp.latency_ms,
          execResp.attack_type || null
        );
      }
    } catch (err: unknown) {
      setSecurityState('ERROR');
      const msg = err instanceof AgentGuardApiError ? err.message : 'Tool request evaluation failed.';
      setErrorMessage(msg);
      addTimelineEvent('Security Gateway', 'ERROR', msg);
    }
  };

  // =========================================================================
  // Human Action: Approve Action
  // =========================================================================
  const handleApprove = async () => {
    if (!activeApprovalId) return;

    // Check if arguments changed before sending
    if (tamperWarning) {
      setErrorMessage('Cannot approve: arguments have been tampered with since creation.');
      return;
    }

    setSecurityState('SUBMITTING_APPROVAL');
    setErrorMessage(null);
    setReplayMessage(null);

    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    try {
      const resp = await agentGuardApi.approve(activeApprovalId, developerToken, abortController.signal);
      setApprovalActionData(resp);
      setActiveDecision(resp.decision);
      setActiveApprovalStatus(resp.approval_status);
      setActiveResult(resp.result);
      setActiveRiskLevel(resp.risk_level || activeRiskLevel);
      setActiveAttackType(resp.attack_type || null);
      setActiveLatency(resp.latency_ms || null);

      if (resp.decision === 'ALLOW') {
        setSecurityState('CONSUMED');
        addTimelineEvent(
          'Human Approval',
          'APPROVED',
          `Operator explicitly approved action (ID: ${activeApprovalId}).`
        );
        addTimelineEvent(
          'Tool Execution',
          'CONSUMED',
          'Tool executed exactly once and approval token consumed.'
        );
        addTimelineEvent(
          'Result Guard',
          'ALLOWED',
          'Mock execution result sanitized and labeled as UNTRUSTED DATA.'
        );

        appendHistory(
          resp.tool_name,
          'ALLOW',
          resp.risk_level || activeRiskLevel,
          resp.approval_status,
          resp.result,
          resp.latency_ms || 0
        );
      } else {
        setSecurityState('BLOCKED');
        addTimelineEvent('Tool Execution', 'BLOCKED', 'Execution rejected by backend.');
      }
    } catch (err: unknown) {
      if (err instanceof AgentGuardApiError) {
        if (err.status === 409 || err.code === 'APPROVAL_ALREADY_CONSUMED') {
          setReplayMessage('Approval has already been consumed.');
          addTimelineEvent('Approval Replay', 'BLOCKED', 'Replay attempt rejected: 409 Conflict.');
        } else if (err.status === 400 || err.code === 'APPROVAL_EXPIRED') {
          setActiveApprovalStatus('EXPIRED');
          setSecurityState('EXPIRED');
          addTimelineEvent('Approval Status', 'EXPIRED', 'Approval TTL has expired.');
        } else {
          setErrorMessage(err.message);
          addTimelineEvent('Approval Gate', 'ERROR', err.message);
        }
      } else {
        setErrorMessage('Failed to submit approval.');
      }
      setSecurityState('ERROR');
    }
  };

  // =========================================================================
  // Human Action: Deny Action
  // =========================================================================
  const handleDeny = async () => {
    if (!activeApprovalId) return;

    setSecurityState('ANALYZING');
    setErrorMessage(null);
    setReplayMessage(null);

    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    try {
      const resp = await agentGuardApi.deny(activeApprovalId, developerToken, abortController.signal);
      setApprovalActionData(resp);
      setActiveDecision('BLOCK');
      setActiveApprovalStatus('DENIED');
      setActiveResult(null);
      setSecurityState('DENIED');

      addTimelineEvent(
        'Human Approval',
        'DENIED',
        `Operator explicitly denied approval request '${activeApprovalId}'.`
      );
      addTimelineEvent(
        'Tool Execution',
        'BLOCKED',
        'Tool execution strictly prevented. Action will never run.'
      );

      appendHistory(
        resp.tool_name,
        'BLOCK',
        resp.risk_level || activeRiskLevel,
        'DENIED',
        null,
        resp.latency_ms || 0
      );
    } catch (err: unknown) {
      const msg = err instanceof AgentGuardApiError ? err.message : 'Denial request failed.';
      setErrorMessage(msg);
      addTimelineEvent('Approval Gate', 'ERROR', msg);
      setSecurityState('ERROR');
    }
  };

  // =========================================================================
  // Replay Attack Demonstration
  // =========================================================================
  const handleAttemptReplay = async () => {
    if (!activeApprovalId) return;

    setReplayMessage(null);
    addTimelineEvent(
      'Replay Test',
      'PENDING',
      `Attempting to re-execute already consumed approval ID '${activeApprovalId}'...`
    );

    try {
      // Replay attempt to /approve
      await agentGuardApi.approve(activeApprovalId, developerToken);
      // If it somehow succeeded (which backend prevents), note it
      setErrorMessage('Unexpected: server did not reject replay.');
    } catch (err: unknown) {
      if (err instanceof AgentGuardApiError && (err.status === 409 || err.code === 'APPROVAL_ALREADY_CONSUMED')) {
        setReplayMessage('Approval has already been consumed.');
        addTimelineEvent(
          'Replay Protection',
          'BLOCKED',
          'Backend returned 409 Conflict: One-time token already consumed. Replay prevented!'
        );
      } else {
        setReplayMessage(err instanceof Error ? err.message : 'Replay rejected.');
        addTimelineEvent('Replay Protection', 'BLOCKED', 'Server rejected re-execution attempt.');
      }
    }
  };

  // Handle selecting an item from session history
  const handleSelectHistory = (item: ToolSecurityHistoryItem) => {
    setSelectedToolName(item.tool_name);
    setActiveDecision(item.decision);
    setActiveRiskLevel(item.risk_level);
    setActiveApprovalStatus(item.approval_status);
    setActiveResult(item.result);
    setActiveAttackType(item.attack_type || null);
    setActiveLatency(item.latency_ms);
  };

  const handleClearHistory = () => {
    setHistory([]);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Error Notice */}
      {errorMessage && (
        <div className="alert-box danger" role="alert">
          <AlertCircle size={20} style={{ flexShrink: 0 }} />
          <div>
            <div style={{ fontWeight: 600 }}>Security Gateway Notice</div>
            <div style={{ fontSize: '0.8125rem' }}>{errorMessage}</div>
          </div>
        </div>
      )}

      {/* Main Grid: Left Column Composer + Approvals, Right Column Decisions + Results + Timeline */}
      <div className="playground-grid">
        {/* Left Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <ToolComposer
            selectedToolName={selectedToolName}
            argumentsJson={argumentsJson}
            onToolChange={handleToolChange}
            onArgumentsChange={handleArgumentsChange}
            onSubmit={handleAnalyzeToolRequest}
            isLoading={securityState === 'ANALYZING' || securityState === 'EXECUTING'}
            disabled={securityState === 'SUBMITTING_APPROVAL'}
          />

          {/* Human Approval Card (when PENDING_APPROVAL, or showing terminal outcome) */}
          {(activeApprovalStatus || approvalCreateData || approvalActionData) && (
            <HumanApprovalCard
              approvalData={approvalCreateData}
              approvalOutcome={approvalActionData}
              approvalStatus={activeApprovalStatus || 'NOT_REQUIRED'}
              isSubmitting={securityState === 'SUBMITTING_APPROVAL'}
              onApprove={handleApprove}
              onDeny={handleDeny}
              onAttemptReplay={handleAttemptReplay}
              replayMessage={replayMessage}
              tamperWarning={tamperWarning}
            />
          )}

          {/* Security Context */}
          <SecurityContextCard
            developerToken={developerToken}
            setDeveloperToken={setDeveloperToken}
          />
        </div>

        {/* Right Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Risk & Security Evaluation Card */}
          <ToolRiskCard
            decision={activeDecision}
            riskLevel={activeRiskLevel}
            approvalStatus={activeApprovalStatus}
            attackType={activeAttackType}
            latencyMs={activeLatency}
            reason={activeReason}
          />

          {/* Tool Result Container (UNTRUSTED DATA) */}
          {activeResult !== null && (
            <ToolResultDisplay
              toolName={selectedToolName}
              result={activeResult}
              attackType={activeAttackType}
            />
          )}

          {/* Lifecycle Timeline */}
          {timelineEvents.length > 0 && (
            <ToolSecurityTimeline events={timelineEvents} />
          )}

          {/* Expandable Telemetry Details */}
          <ToolRequestDetails
            toolName={selectedToolName}
            argumentsObj={(() => {
              try {
                return JSON.parse(argumentsJson);
              } catch {
                return { raw: argumentsJson };
              }
            })()}
            riskLevel={activeRiskLevel}
            decision={activeDecision}
            approvalId={activeApprovalId}
            approvalStatus={activeApprovalStatus}
            requestId={activeRequestId}
            executionState={securityState}
            result={activeResult}
            latencyMs={activeLatency}
            attackType={activeAttackType}
          />

          {/* In-memory Session Event History */}
          <ToolSecurityHistory
            history={history}
            onSelect={handleSelectHistory}
            onClear={handleClearHistory}
          />
        </div>
      </div>
    </div>
  );
};
