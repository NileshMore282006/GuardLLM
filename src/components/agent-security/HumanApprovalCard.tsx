import React from 'react';
import { ApprovalCreateResponse, ApprovalActionResponse, ApprovalStatus } from '../../types/agentguard';
import { ShieldCheck, ShieldX, Clock, AlertOctagon, CheckCircle2, XCircle, RefreshCw } from 'lucide-react';

interface HumanApprovalCardProps {
  approvalData: ApprovalCreateResponse | null;
  approvalOutcome: ApprovalActionResponse | null;
  approvalStatus: ApprovalStatus;
  isSubmitting: boolean;
  onApprove: () => void;
  onDeny: () => void;
  onAttemptReplay?: () => void;
  replayMessage?: string | null;
  tamperWarning?: string | null;
}

export const HumanApprovalCard: React.FC<HumanApprovalCardProps> = ({
  approvalData,
  approvalOutcome,
  approvalStatus,
  isSubmitting,
  onApprove,
  onDeny,
  onAttemptReplay,
  replayMessage,
  tamperWarning,
}) => {
  if (!approvalData && !approvalOutcome) {
    return null;
  }

  const toolName = approvalOutcome?.tool_name || approvalData?.tool_name || 'unknown';
  const riskLevel = (approvalOutcome?.risk_level || approvalData?.risk_level || 'high').toUpperCase();
  const approvalId = approvalOutcome?.approval_id || approvalData?.approval_id || null;
  const reason = approvalData?.reason || 'High-risk action requires human verification.';
  const summary = approvalData?.arguments_summary;

  const isPending = approvalStatus === 'PENDING_APPROVAL';
  const isApproved = approvalStatus === 'APPROVED' || approvalStatus === 'CONSUMED';
  const isDenied = approvalStatus === 'DENIED';
  const isExpired = approvalStatus === 'EXPIRED';

  return (
    <div
      className="glass-panel"
      id="human-approval-card"
      style={{
        padding: '1.5rem',
        border: isPending
          ? '2px solid rgba(245, 158, 11, 0.6)'
          : isDenied
          ? '2px solid var(--color-block-border)'
          : isApproved
          ? '2px solid var(--color-allow-border)'
          : '1px solid var(--border-subtle)',
        background: isPending
          ? 'linear-gradient(180deg, rgba(245, 158, 11, 0.08) 0%, rgba(17, 22, 34, 0.9) 100%)'
          : undefined,
        display: 'flex',
        flexDirection: 'column',
        gap: '1.25rem',
      }}
    >
      {/* Header Badge */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          {isPending && <Clock size={20} style={{ color: '#f59e0b' }} />}
          {isApproved && <CheckCircle2 size={20} style={{ color: 'var(--color-allow)' }} />}
          {isDenied && <XCircle size={20} style={{ color: 'var(--color-block)' }} />}
          {isExpired && <AlertOctagon size={20} style={{ color: 'var(--text-muted)' }} />}
          <div>
            <h3 style={{ fontSize: '1.0625rem', fontWeight: 700, letterSpacing: '0.02em', color: 'var(--text-primary)' }}>
              {isPending && 'HUMAN APPROVAL REQUIRED'}
              {isApproved && 'HUMAN APPROVAL: COMPLETED & EXECUTED'}
              {isDenied && 'HUMAN APPROVAL: DENIED'}
              {isExpired && 'HUMAN APPROVAL: EXPIRED'}
            </h3>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Explicit Authorization Gate for High-Risk & Critical Actions
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <span
            className={`status-badge ${riskLevel.toLowerCase()}`}
            style={{ fontSize: '0.6875rem', fontWeight: 700, padding: '0.25rem 0.6rem' }}
          >
            {riskLevel} RISK
          </span>
          <span
            id="approval-status-badge"
            className="status-badge"
            style={{
              fontSize: '0.6875rem',
              fontWeight: 700,
              padding: '0.25rem 0.6rem',
              background: isPending
                ? 'rgba(245, 158, 11, 0.2)'
                : isDenied
                ? 'var(--color-block-bg)'
                : isApproved
                ? 'var(--color-allow-bg)'
                : 'rgba(255,255,255,0.05)',
              color: isPending
                ? '#f59e0b'
                : isDenied
                ? 'var(--color-block)'
                : isApproved
                ? 'var(--color-allow)'
                : 'var(--text-muted)',
              border: isPending
                ? '1px solid rgba(245, 158, 11, 0.4)'
                : isDenied
                ? '1px solid var(--color-block-border)'
                : isApproved
                ? '1px solid var(--color-allow-border)'
                : '1px solid var(--border-subtle)',
            }}
          >
            {approvalStatus}
          </span>
        </div>
      </div>

      {/* Description / Statement */}
      <div
        style={{
          background: 'rgba(0, 0, 0, 0.25)',
          padding: '0.85rem 1rem',
          borderRadius: 'var(--radius-md)',
          fontSize: '0.8125rem',
          lineHeight: 1.5,
          color: 'var(--text-secondary)',
          border: '1px solid var(--border-subtle)',
        }}
      >
        <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '0.5rem 1rem', marginBottom: '0.5rem' }}>
          <span style={{ color: 'var(--text-muted)', fontWeight: 500 }}>Tool:</span>
          <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', fontWeight: 600 }}>{toolName}</span>

          <span style={{ color: 'var(--text-muted)', fontWeight: 500 }}>Reason:</span>
          <span>{reason}</span>

          {summary && (
            <>
              <span style={{ color: 'var(--text-muted)', fontWeight: 500 }}>Arguments:</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', wordBreak: 'break-all' }}>{summary}</span>
            </>
          )}

          {approvalId && (
            <>
              <span style={{ color: 'var(--text-muted)', fontWeight: 500 }}>Approval ID:</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#a5b4fc' }}>{approvalId}</span>
            </>
          )}
        </div>

        {isPending && (
          <div style={{ marginTop: '0.5rem', paddingTop: '0.5rem', borderTop: '1px solid var(--border-subtle)', color: '#fbbf24', fontSize: '0.75rem' }}>
            <strong>Security Invariant:</strong> This action cannot execute until explicitly approved by a human operator. The model cannot approve its own action.
          </div>
        )}
      </div>

      {/* Tamper Warning Banner if arguments changed */}
      {tamperWarning && (
        <div
          id="tamper-warning-alert"
          role="alert"
          style={{
            padding: '0.75rem 1rem',
            borderRadius: 'var(--radius-md)',
            background: 'rgba(239, 68, 68, 0.12)',
            border: '1px solid var(--color-block-border)',
            color: '#f87171',
            fontSize: '0.8125rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <AlertOctagon size={16} style={{ flexShrink: 0 }} />
          <span>{tamperWarning}</span>
        </div>
      )}

      {/* Replay Notice if 409 returned */}
      {replayMessage && (
        <div
          id="replay-alert"
          role="alert"
          style={{
            padding: '0.75rem 1rem',
            borderRadius: 'var(--radius-md)',
            background: 'rgba(239, 68, 68, 0.12)',
            border: '1px solid var(--color-block-border)',
            color: '#f87171',
            fontSize: '0.8125rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <AlertOctagon size={16} style={{ flexShrink: 0 }} />
          <span>{replayMessage}</span>
        </div>
      )}

      {/* Action Buttons for Pending State */}
      {isPending && (
        <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end', flexWrap: 'wrap' }}>
          <button
            type="button"
            id="btn-deny-approval"
            onClick={onDeny}
            disabled={isSubmitting}
            className="btn-secondary"
            style={{
              padding: '0.65rem 1.25rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              borderColor: 'var(--color-block-border)',
              color: '#f87171',
              cursor: isSubmitting ? 'not-allowed' : 'pointer',
            }}
          >
            <ShieldX size={16} />
            <span>Deny</span>
          </button>

          <button
            type="button"
            id="btn-approve-action"
            onClick={onApprove}
            disabled={isSubmitting}
            className="btn-primary"
            style={{
              padding: '0.65rem 1.5rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              background: '#059669',
              borderColor: '#10b981',
              cursor: isSubmitting ? 'not-allowed' : 'pointer',
            }}
          >
            {isSubmitting ? (
              <>
                <span className="spinner-border" />
                <span>Submitting approval...</span>
              </>
            ) : (
              <>
                <ShieldCheck size={16} />
                <span>Approve</span>
              </>
            )}
          </button>
        </div>
      )}

      {/* Consumed / Approved state: Replay Attack Demonstration Button */}
      {isApproved && onAttemptReplay && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            paddingTop: '0.5rem',
            borderTop: '1px solid var(--border-subtle)',
            fontSize: '0.75rem',
          }}
        >
          <span style={{ color: 'var(--text-muted)' }}>
            One-time token consumed. Test backend replay prevention:
          </span>
          <button
            type="button"
            id="btn-attempt-replay"
            onClick={onAttemptReplay}
            disabled={isSubmitting}
            style={{
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--text-secondary)',
              padding: '0.35rem 0.75rem',
              fontSize: '0.75rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
            }}
          >
            <RefreshCw size={13} />
            <span>Attempt Replay (Test 409)</span>
          </button>
        </div>
      )}

      {/* Denied state message */}
      {isDenied && (
        <div style={{ color: 'var(--color-block)', fontSize: '0.8125rem', fontWeight: 500 }}>
          DENIED — Execution blocked. Tool was not executed and cannot be retried with this request.
        </div>
      )}

      {/* Expired state message */}
      {isExpired && (
        <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
          EXPIRED — Approval TTL has elapsed. Execution disabled. A fresh authorization request is required.
        </div>
      )}
    </div>
  );
};
