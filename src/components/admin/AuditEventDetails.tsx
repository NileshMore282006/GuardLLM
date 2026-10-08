import React from 'react';
import { ScrollText, X, Link2, ShieldAlert, CheckCircle2, ShieldX } from 'lucide-react';
import { AuditEventItem } from '../../types/agentguard';

interface AuditEventDetailsProps {
  event: AuditEventItem | null;
  onClose: () => void;
}

export const AuditEventDetails: React.FC<AuditEventDetailsProps> = ({ event, onClose }) => {
  if (!event) return null;

  const isBlock = event.decision === 'BLOCK';
  const isAllow = event.decision === 'ALLOW';

  return (
    <div
      role="dialog"
      aria-modal="true"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(5, 8, 16, 0.85)',
        backdropFilter: 'blur(8px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
        padding: '1rem',
      }}
    >
      <div
        className="glass-panel"
        style={{
          width: '100%',
          maxWidth: '640px',
          maxHeight: '90vh',
          overflowY: 'auto',
          padding: '1.75rem',
          borderRadius: '12px',
          background: 'var(--bg-secondary)',
          display: 'flex',
          flexDirection: 'column',
          gap: '1.25rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <div style={{ padding: '0.45rem', borderRadius: '8px', background: 'rgba(99, 102, 241, 0.15)', color: 'var(--color-accent)' }}>
              <ScrollText size={20} />
            </div>
            <div>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                Audit Event Inspection
              </h3>
              <span className="mono-text" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                {event.event_id}
              </span>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close audit details"
            style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
          >
            <X size={18} />
          </button>
        </div>

        {/* Decision & Action Summary Card */}
        <div
          style={{
            background: 'var(--bg-tertiary)',
            padding: '1rem',
            borderRadius: '8px',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
            gap: '0.75rem',
          }}
        >
          <div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Decision</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', marginTop: '0.2rem' }}>
              {isBlock ? (
                <ShieldX size={16} style={{ color: 'var(--color-block)' }} />
              ) : isAllow ? (
                <CheckCircle2 size={16} style={{ color: 'var(--color-allow)' }} />
              ) : (
                <ShieldAlert size={16} style={{ color: 'var(--color-warn)' }} />
              )}
              <span
                style={{
                  fontWeight: 700,
                  fontSize: '0.875rem',
                  color: isBlock ? 'var(--color-block)' : isAllow ? 'var(--color-allow)' : 'var(--color-warn)',
                }}
              >
                {event.decision || 'NONE'}
              </span>
            </div>
          </div>

          <div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Action</div>
            <div className="mono-text" style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.2rem' }}>
              {event.action}
            </div>
          </div>

          <div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Risk Score</div>
            <div className="mono-text" style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.2rem' }}>
              {event.risk_score !== null && event.risk_score !== undefined ? event.risk_score.toFixed(2) : '—'}
            </div>
          </div>

          <div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Attack Type</div>
            <div className="mono-text" style={{ fontSize: '0.8125rem', color: event.attack_type && event.attack_type !== 'none' ? 'var(--color-block)' : 'var(--text-secondary)', marginTop: '0.2rem' }}>
              {event.attack_type || 'none'}
            </div>
          </div>
        </div>

        {/* Metadata Details Grid */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.8125rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem 0', borderBottom: '1px solid var(--border-subtle)' }}>
            <span style={{ color: 'var(--text-muted)' }}>Timestamp:</span>
            <span style={{ color: 'var(--text-secondary)' }}>
              {new Date(event.timestamp * 1000).toISOString()} ({event.timestamp})
            </span>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem 0', borderBottom: '1px solid var(--border-subtle)' }}>
            <span style={{ color: 'var(--text-muted)' }}>Request ID:</span>
            <span className="mono-text" style={{ color: 'var(--text-primary)' }}>
              {event.request_id || '—'}
            </span>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem 0', borderBottom: '1px solid var(--border-subtle)' }}>
            <span style={{ color: 'var(--text-muted)' }}>Principal ID:</span>
            <span className="mono-text" style={{ color: 'var(--text-primary)' }}>
              {event.principal_id || 'anonymous'}
            </span>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem 0', borderBottom: '1px solid var(--border-subtle)' }}>
            <span style={{ color: 'var(--text-muted)' }}>Tenant ID:</span>
            <span className="mono-text" style={{ color: 'var(--color-accent)' }}>
              {event.tenant_id || 'default'}
            </span>
          </div>

          {event.tool_name && (
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem 0', borderBottom: '1px solid var(--border-subtle)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Tool Name:</span>
              <span className="mono-text" style={{ color: 'var(--color-accent)' }}>
                {event.tool_name}
              </span>
            </div>
          )}

          {event.approval_id && (
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem 0', borderBottom: '1px solid var(--border-subtle)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Approval ID:</span>
              <span className="mono-text" style={{ color: 'var(--text-primary)' }}>
                {event.approval_id}
              </span>
            </div>
          )}

          {event.policy_id && (
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem 0', borderBottom: '1px solid var(--border-subtle)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Bound Policy:</span>
              <span className="mono-text" style={{ color: 'var(--text-primary)' }}>
                {event.policy_id} (v{event.policy_version})
              </span>
            </div>
          )}

          {event.error_code && (
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem 0', borderBottom: '1px solid var(--border-subtle)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Error Code:</span>
              <span className="mono-text" style={{ color: 'var(--color-block)' }}>
                {event.error_code}
              </span>
            </div>
          )}
        </div>

        {/* Cryptographic Hash Chaining Block */}
        <div style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '0.85rem 1rem', display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
            <Link2 size={14} style={{ color: 'var(--color-accent)' }} />
            <span>Cryptographic Chain Link</span>
          </div>

          <div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Previous Event Hash (SHA-256)
            </div>
            <div className="mono-text" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
              {event.previous_event_hash}
            </div>
          </div>

          <div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Current Event Hash (SHA-256)
            </div>
            <div className="mono-text" style={{ fontSize: '0.75rem', color: 'var(--color-allow)', wordBreak: 'break-all' }}>
              {event.event_hash}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
          <button
            type="button"
            className="secondary-btn"
            onClick={onClose}
            style={{ padding: '0.45rem 1.25rem', fontSize: '0.8125rem' }}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
