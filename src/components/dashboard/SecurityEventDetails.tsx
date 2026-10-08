import React from 'react';
import { AuditEventItem } from '../../types/agentguard';
import { X, ShieldAlert, ShieldCheck, Key } from 'lucide-react';

interface SecurityEventDetailsProps {
  event: AuditEventItem | null;
  onClose: () => void;
}

export const SecurityEventDetails: React.FC<SecurityEventDetailsProps> = ({ event, onClose }) => {
  if (!event) return null;

  const formattedDate = new Date(event.timestamp * 1000).toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short',
  });

  const isBlocked = event.decision === 'BLOCK' || event.action.includes('block') || event.action.includes('deny');

  return (
    <div
      className="event-details-overlay"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.65)',
        backdropFilter: 'blur(4px)',
        display: 'flex',
        justifyContent: 'flex-end',
        zIndex: 1000,
      }}
      onClick={onClose}
    >
      <div
        className="glass-panel event-details-drawer"
        style={{
          width: '100%',
          maxWidth: '560px',
          height: '100%',
          background: 'var(--bg-secondary)',
          borderLeft: '1px solid var(--border-subtle)',
          display: 'flex',
          flexDirection: 'column',
          overflowY: 'auto',
          padding: '1.5rem',
        }}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-label="Security Event Telemetry Details"
      >
        {/* Drawer Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem', paddingBottom: '1rem', borderBottom: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
            <div
              style={{
                padding: '0.4rem',
                borderRadius: '8px',
                background: isBlocked ? 'var(--color-block-bg)' : 'var(--color-allow-bg)',
                color: isBlocked ? 'var(--color-block)' : 'var(--color-allow)',
              }}
            >
              {isBlocked ? <ShieldAlert size={20} /> : <ShieldCheck size={20} />}
            </div>
            <div>
              <h2 style={{ fontSize: '1.0625rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                Security Audit Telemetry
              </h2>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {event.event_id}
              </span>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            aria-label="Close details"
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: '0.25rem',
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Telemetry Key-Value Grid */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          
          {/* Top Status Card */}
          <div
            style={{
              background: 'var(--bg-tertiary)',
              padding: '1rem',
              borderRadius: '8px',
              border: '1px solid var(--border-subtle)',
              display: 'grid',
              gridTemplateColumns: 'repeat(2, 1fr)',
              gap: '0.75rem',
            }}
          >
            <div>
              <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Authoritative Decision</div>
              <span
                className={`status-badge ${event.decision === 'BLOCK' ? 'block' : 'allow'}`}
                style={{ marginTop: '0.25rem', display: 'inline-block' }}
              >
                {event.decision || 'N/A'}
              </span>
            </div>

            <div>
              <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Action Name</div>
              <div style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.25rem' }}>
                {event.action}
              </div>
            </div>

            <div>
              <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Risk Score</div>
              <div style={{ fontSize: '0.875rem', fontWeight: 600, color: event.risk_score && event.risk_score > 0 ? 'var(--color-block)' : 'var(--text-secondary)', marginTop: '0.25rem' }}>
                {event.risk_score !== null && event.risk_score !== undefined ? event.risk_score.toFixed(2) : '0.00'}
              </div>
            </div>

            <div>
              <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Attack Type</div>
              <div style={{ fontSize: '0.875rem', fontWeight: 600, color: event.attack_type && event.attack_type !== 'none' ? 'var(--color-block)' : 'var(--text-muted)', marginTop: '0.25rem' }}>
                {event.attack_type || 'none'}
              </div>
            </div>
          </div>

          {/* Context Details */}
          <div style={{ background: 'var(--bg-tertiary)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
            <h3 style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Correlation & Context
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', fontSize: '0.8125rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Timestamp (Local):</span>
                <span style={{ color: 'var(--text-primary)' }}>{formattedDate}</span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Correlation Request ID:</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-accent)', fontSize: '0.75rem' }}>
                  {event.request_id || 'N/A'}
                </span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Resource Type:</span>
                <span style={{ color: 'var(--text-primary)' }}>{event.resource_type || 'N/A'}</span>
              </div>

              {event.resource_id && (
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Resource ID:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', fontSize: '0.75rem' }}>
                    {event.resource_id}
                  </span>
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Tenant ID:</span>
                <span style={{ color: 'var(--text-primary)' }}>{event.tenant_id || 'default'}</span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Principal ID:</span>
                <span style={{ color: 'var(--text-primary)' }}>{event.principal_id || 'anonymous'}</span>
              </div>

              {event.tool_name && (
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Tool Name:</span>
                  <span style={{ color: 'var(--color-accent)', fontWeight: 600 }}>{event.tool_name}</span>
                </div>
              )}

              {event.approval_id && (
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Approval ID:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-warn)', fontSize: '0.75rem' }}>
                    {event.approval_id}
                  </span>
                </div>
              )}

              {event.error_code && (
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Error Code:</span>
                  <span style={{ color: 'var(--color-block)', fontWeight: 600 }}>{event.error_code}</span>
                </div>
              )}
            </div>
          </div>

          {/* Cryptographic Chain Integrity */}
          <div style={{ background: 'var(--bg-tertiary)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
            <h3 style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.04em', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Key size={14} color="var(--color-accent)" />
              Cryptographic Hash Chaining (SHA-256)
            </h3>
            <p style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
              Audit events are cryptographically chained to prevent retroactive tampering.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <div>
                <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>Event Hash:</span>
                <div style={{ fontSize: '0.6875rem', fontFamily: 'var(--font-mono)', background: 'var(--bg-input)', padding: '0.35rem 0.5rem', borderRadius: '4px', color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
                  {event.event_hash}
                </div>
              </div>

              <div>
                <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>Previous Event Hash:</span>
                <div style={{ fontSize: '0.6875rem', fontFamily: 'var(--font-mono)', background: 'var(--bg-input)', padding: '0.35rem 0.5rem', borderRadius: '4px', color: 'var(--text-dim)', wordBreak: 'break-all' }}>
                  {event.previous_event_hash}
                </div>
              </div>
            </div>
          </div>

          {/* Safety & Redaction Notice */}
          <div
            style={{
              padding: '0.75rem',
              borderRadius: '6px',
              background: 'rgba(99, 102, 241, 0.08)',
              border: '1px solid rgba(99, 102, 241, 0.2)',
              fontSize: '0.6875rem',
              color: 'var(--text-secondary)',
            }}
          >
            <strong>Privacy & Integrity Guarantee:</strong> In compliance with AgentGuard security standards, raw user prompts, credentials, Bearer tokens, and canary secrets are excluded from persistent audit logs and never exposed in frontend telemetry.
          </div>

        </div>
      </div>
    </div>
  );
};
