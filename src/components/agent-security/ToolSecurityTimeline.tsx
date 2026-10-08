import React from 'react';
import { ToolTimelineEvent } from '../../types/agentguard';
import { GitCommit, CheckCircle2, XCircle, Clock, AlertTriangle, ShieldCheck } from 'lucide-react';

interface ToolSecurityTimelineProps {
  events: ToolTimelineEvent[];
}

export const ToolSecurityTimeline: React.FC<ToolSecurityTimelineProps> = ({ events }) => {
  if (!events || events.length === 0) {
    return null;
  }

  const getStatusIcon = (status: ToolTimelineEvent['status']) => {
    switch (status) {
      case 'ALLOWED':
      case 'APPROVED':
      case 'CONSUMED':
        return <CheckCircle2 size={15} style={{ color: 'var(--color-allow)' }} />;
      case 'BLOCKED':
      case 'DENIED':
        return <XCircle size={15} style={{ color: 'var(--color-block)' }} />;
      case 'PENDING':
      case 'PENDING APPROVAL':
        return <Clock size={15} style={{ color: '#f59e0b' }} />;
      case 'EXPIRED':
      case 'ERROR':
        return <AlertTriangle size={15} style={{ color: '#f87171' }} />;
      default:
        return <GitCommit size={15} style={{ color: 'var(--color-accent)' }} />;
    }
  };

  const getStatusBadgeStyle = (status: ToolTimelineEvent['status']) => {
    switch (status) {
      case 'ALLOWED':
      case 'APPROVED':
      case 'CONSUMED':
        return {
          background: 'var(--color-allow-bg)',
          color: 'var(--color-allow)',
          border: '1px solid var(--color-allow-border)',
        };
      case 'BLOCKED':
      case 'DENIED':
      case 'ERROR':
        return {
          background: 'var(--color-block-bg)',
          color: 'var(--color-block)',
          border: '1px solid var(--color-block-border)',
        };
      case 'PENDING':
      case 'PENDING APPROVAL':
        return {
          background: 'rgba(245, 158, 11, 0.15)',
          color: '#f59e0b',
          border: '1px solid rgba(245, 158, 11, 0.3)',
        };
      case 'EXPIRED':
        return {
          background: 'rgba(255, 255, 255, 0.05)',
          color: 'var(--text-muted)',
          border: '1px solid var(--border-subtle)',
        };
      default:
        return {
          background: 'rgba(99, 102, 241, 0.15)',
          color: 'var(--color-accent)',
          border: '1px solid rgba(99, 102, 241, 0.3)',
        };
    }
  };

  return (
    <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <ShieldCheck size={16} style={{ color: 'var(--color-accent)' }} />
          <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Security Lifecycle Timeline
          </h3>
        </div>
        <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
          Authoritative Gateway Evaluation
        </span>
      </div>

      <div style={{ position: 'relative', paddingLeft: '1.25rem', marginTop: '0.25rem' }}>
        {/* Vertical line connecting nodes */}
        <div
          style={{
            position: 'absolute',
            left: '0.45rem',
            top: '0.5rem',
            bottom: '0.5rem',
            width: '2px',
            background: 'var(--border-subtle)',
          }}
        />

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          {events.map((evt, idx) => (
            <div
              key={evt.id || idx}
              style={{
                position: 'relative',
                display: 'flex',
                alignItems: 'flex-start',
                gap: '0.75rem',
              }}
            >
              {/* Node Icon on the line */}
              <div
                style={{
                  position: 'absolute',
                  left: '-1.25rem',
                  top: '0.15rem',
                  background: 'var(--bg-primary)',
                  borderRadius: '50%',
                  padding: '2px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                {getStatusIcon(evt.status)}
              </div>

              {/* Event Content */}
              <div
                style={{
                  flex: 1,
                  background: 'rgba(0, 0, 0, 0.2)',
                  padding: '0.6rem 0.85rem',
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid var(--border-subtle)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.25rem',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem' }}>
                  <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {evt.stage}
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span
                      style={{
                        fontSize: '0.6875rem',
                        fontWeight: 600,
                        padding: '0.15rem 0.45rem',
                        borderRadius: 'var(--radius-sm)',
                        ...getStatusBadgeStyle(evt.status),
                      }}
                    >
                      {evt.status}
                    </span>
                    <span
                      style={{
                        fontSize: '0.6875rem',
                        color: 'var(--text-muted)',
                        fontFamily: 'var(--font-mono)',
                      }}
                      title={evt.isBackendTimestamp ? 'Server timestamp' : 'Client observation time'}
                    >
                      {evt.timestamp}
                    </span>
                  </div>
                </div>

                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                  {evt.detail}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
