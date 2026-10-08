import React from 'react';
import { AuditEventItem, PipelineStageInfo } from '../../types/agentguard';

interface PipelineTimelineProps {
  selectedEvent: AuditEventItem | null;
  allCorrelatedEvents: AuditEventItem[];
}

export const PipelineTimeline: React.FC<PipelineTimelineProps> = ({
  selectedEvent,
  allCorrelatedEvents,
}) => {
  if (!selectedEvent) {
    return (
      <div
        className="glass-panel"
        style={{
          padding: '2rem',
          borderRadius: '10px',
          textAlign: 'center',
          color: 'var(--text-muted)',
          fontSize: '0.8125rem',
        }}
      >
        Select an audit event or approval record to inspect the correlated security execution pipeline.
      </div>
    );
  }

  // Derive stage observation strictly from real backend event metadata across all correlated events for this request
  const hasAuthSuccess = allCorrelatedEvents.some((e) => e.action === 'auth_success');
  const hasAuthFailure = allCorrelatedEvents.some((e) => e.action === 'auth_failure');
  const hasAuthzFailure = allCorrelatedEvents.some((e) => e.action === 'authz_failure');
  const hasPolicyAction = allCorrelatedEvents.some((e) => e.policy_id !== null && e.policy_id !== undefined);
  const hasGuardAction = allCorrelatedEvents.some((e) => ['guard_analyze', 'guard_block', 'prompt_injection'].includes(e.action) || e.attack_type);
  const hasToolOrApproval = allCorrelatedEvents.some((e) => e.tool_name || e.approval_id || e.action?.includes('tool') || e.action?.includes('approval'));
  const hasSanitizer = allCorrelatedEvents.some((e) => e.action === 'sanitizer_redact' || e.action?.includes('sanitize'));

  const stages: PipelineStageInfo[] = [
    {
      name: '1. Request',
      status: 'OBSERVED',
      detail: `Tracking Request ID: ${selectedEvent.request_id || 'anonymous'}`,
      observedData: { request_id: selectedEvent.request_id },
    },
    {
      name: '2. Authentication',
      status: hasAuthFailure
        ? 'BLOCKED'
        : hasAuthSuccess
        ? 'OBSERVED'
        : selectedEvent.principal_id
        ? 'OBSERVED'
        : 'UNAVAILABLE',
      detail: hasAuthFailure
        ? 'Authentication failed: Invalid credential or missing Bearer token'
        : selectedEvent.principal_id
        ? `Principal authenticated: ${selectedEvent.principal_id} (${selectedEvent.tenant_id || 'default'})`
        : 'Not available from current audit data.',
    },
    {
      name: '3. Authorization',
      status: hasAuthzFailure
        ? 'BLOCKED'
        : hasAuthSuccess || selectedEvent.principal_id
        ? 'OBSERVED'
        : 'UNAVAILABLE',
      detail: hasAuthzFailure
        ? 'Authorization rejected: Insufficient role permissions'
        : selectedEvent.principal_id
        ? 'RBAC authority verified for requested tenant scope'
        : 'Not available from current audit data.',
    },
    {
      name: '4. Policy',
      status: hasPolicyAction
        ? 'OBSERVED'
        : selectedEvent.action === 'policy_denial'
        ? 'BLOCKED'
        : 'UNAVAILABLE',
      detail: selectedEvent.policy_id
        ? `Policy applied: ${selectedEvent.policy_id} (v${selectedEvent.policy_version || 1})`
        : 'Not available from current audit data.',
    },
    {
      name: '5. Guard',
      status: selectedEvent.decision === 'BLOCK' && (selectedEvent.attack_type || selectedEvent.action?.includes('guard'))
        ? 'BLOCKED'
        : hasGuardAction || selectedEvent.risk_score !== null
        ? 'OBSERVED'
        : 'UNAVAILABLE',
      detail: selectedEvent.decision === 'BLOCK'
        ? `Guard classified threat: ${selectedEvent.attack_type || 'Malicious prompt detected'}`
        : selectedEvent.risk_score !== null && selectedEvent.risk_score !== undefined
        ? `Guard evaluation complete: Risk score ${selectedEvent.risk_score.toFixed(2)}`
        : 'Not available from current audit data.',
    },
    {
      name: '6. Tool / Approval',
      status: selectedEvent.approval_id && selectedEvent.decision === 'BLOCK'
        ? 'BLOCKED'
        : hasToolOrApproval
        ? 'OBSERVED'
        : 'UNAVAILABLE',
      detail: selectedEvent.tool_name
        ? `Tool: ${selectedEvent.tool_name} (Approval ID: ${selectedEvent.approval_id || 'Direct'})`
        : selectedEvent.approval_id
        ? `Approval boundary active: ${selectedEvent.approval_id}`
        : 'Not available from current audit data.',
    },
    {
      name: '7. Target Model',
      status: selectedEvent.decision === 'BLOCK'
        ? 'BLOCKED'
        : selectedEvent.action === 'execute_prompt' || selectedEvent.action === 'chat_turn'
        ? 'OBSERVED'
        : 'UNAVAILABLE',
      detail: selectedEvent.decision === 'BLOCK'
        ? 'Target execution aborted by upstream Guard block'
        : selectedEvent.action === 'execute_prompt' || selectedEvent.action === 'chat_turn'
        ? 'Target model invoked downstream'
        : 'Not available from current audit data.',
    },
    {
      name: '8. Sanitizer',
      status: hasSanitizer
        ? 'OBSERVED'
        : 'UNAVAILABLE',
      detail: hasSanitizer
        ? 'Response content sanitized and secret-redacted'
        : 'Not available from current audit data.',
    },
    {
      name: '9. Audit Hash Chain',
      status: selectedEvent.event_hash ? 'OBSERVED' : 'UNAVAILABLE',
      detail: selectedEvent.event_hash
        ? `Chained SHA-256: ${selectedEvent.event_hash.substring(0, 16)}...`
        : 'Not available from current audit data.',
    },
  ];

  return (
    <div
      className="glass-panel"
      style={{
        padding: '1.25rem',
        borderRadius: '10px',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.75rem',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h4 style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
            Observed Request Pipeline Trajectory
          </h4>
          <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
            Correlated across {allCorrelatedEvents.length} recorded events for Request ID: <code>{selectedEvent.request_id || 'unknown'}</code>
          </span>
        </div>
      </div>

      {/* Trajectory Sequence */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: '0.65rem',
          marginTop: '0.5rem',
        }}
      >
        {stages.map((st, idx) => {
          const isObserved = st.status === 'OBSERVED';
          const isBlocked = st.status === 'BLOCKED';
          const isUnavailable = st.status === 'UNAVAILABLE';

          return (
            <div
              key={idx}
              style={{
                padding: '0.65rem 0.85rem',
                borderRadius: '6px',
                background: isBlocked
                  ? 'rgba(239, 68, 68, 0.08)'
                  : isObserved
                  ? 'rgba(16, 185, 129, 0.05)'
                  : 'var(--bg-tertiary)',
                border: `1px solid ${
                  isBlocked
                    ? 'rgba(239, 68, 68, 0.35)'
                    : isObserved
                    ? 'rgba(16, 185, 129, 0.25)'
                    : 'var(--border-subtle)'
                }`,
                display: 'flex',
                flexDirection: 'column',
                gap: '0.25rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {st.name}
                </span>
                <span
                  className="status-pill"
                  style={{
                    fontSize: '0.5625rem',
                    padding: '0.05rem 0.35rem',
                    background: isBlocked
                      ? 'rgba(239, 68, 68, 0.2)'
                      : isObserved
                      ? 'var(--color-allow-bg)'
                      : 'var(--bg-card)',
                    color: isBlocked
                      ? 'var(--color-block)'
                      : isObserved
                      ? 'var(--color-allow)'
                      : 'var(--text-muted)',
                    borderColor: isBlocked
                      ? 'rgba(239, 68, 68, 0.4)'
                      : isObserved
                      ? 'var(--color-allow-border)'
                      : 'var(--border-subtle)',
                    fontWeight: 700,
                  }}
                >
                  {st.status}
                </span>
              </div>
              <span
                style={{
                  fontSize: '0.6875rem',
                  color: isUnavailable ? 'var(--text-muted)' : 'var(--text-secondary)',
                  fontStyle: isUnavailable ? 'italic' : 'normal',
                  lineHeight: 1.35,
                }}
              >
                {st.detail}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
