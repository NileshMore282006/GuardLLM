import React from 'react';
import { AuditEventItem } from '../../types/agentguard';
import { ChevronRight, FileText } from 'lucide-react';

interface SecurityEventListProps {
  events: AuditEventItem[];
  selectedEventId: string | null;
  onSelectEvent: (event: AuditEventItem) => void;
  isLoading: boolean;
}

export const SecurityEventList: React.FC<SecurityEventListProps> = ({
  events,
  selectedEventId,
  onSelectEvent,
  isLoading,
}) => {
  if (isLoading && events.length === 0) {
    return (
      <div className="glass-panel" style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
        <p>Loading security audit events from AgentGuard gateway...</p>
      </div>
    );
  }

  if (events.length === 0) {
    return (
      <div className="glass-panel" style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
        <FileText size={32} style={{ margin: '0 auto 0.75rem auto', opacity: 0.5 }} />
        <h4 style={{ color: 'var(--text-primary)', marginBottom: '0.25rem' }}>No Security Events Match Filters</h4>
        <p style={{ fontSize: '0.8125rem' }}>Adjust your decision or attack filters above to inspect more audit records.</p>
      </div>
    );
  }

  return (
    <div className="glass-panel" style={{ overflow: 'hidden' }}>
      <div style={{ padding: '0.875rem 1.25rem', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Recent Security Events
          </span>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>
            Authoritative chained log from /api/v1/audit/events
          </span>
        </div>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          {events.length} records shown
        </span>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8125rem' }}>
          <thead>
            <tr style={{ background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
              <th style={{ padding: '0.625rem 1rem', fontWeight: 600 }}>Timestamp</th>
              <th style={{ padding: '0.625rem 1rem', fontWeight: 600 }}>Action</th>
              <th style={{ padding: '0.625rem 1rem', fontWeight: 600 }}>Decision</th>
              <th style={{ padding: '0.625rem 1rem', fontWeight: 600 }}>Attack Type</th>
              <th style={{ padding: '0.625rem 1rem', fontWeight: 600 }}>Resource / Tool</th>
              <th style={{ padding: '0.625rem 1rem', fontWeight: 600 }}>Request ID</th>
              <th style={{ padding: '0.625rem 1rem', fontWeight: 600, textAlign: 'right' }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {events.map((evt) => {
              const isSelected = selectedEventId === evt.event_id;
              const formattedTime = new Date(evt.timestamp * 1000).toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
              });
              const isBlocked = evt.decision === 'BLOCK' || evt.action.includes('block') || evt.action.includes('deny');

              return (
                <tr
                  key={evt.event_id}
                  onClick={() => onSelectEvent(evt)}
                  style={{
                    borderBottom: '1px solid var(--border-subtle)',
                    cursor: 'pointer',
                    background: isSelected ? 'rgba(99, 102, 241, 0.12)' : 'transparent',
                    transition: 'background var(--transition-fast)',
                  }}
                  className="audit-table-row"
                >
                  <td style={{ padding: '0.625rem 1rem', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                    {formattedTime}
                  </td>

                  <td style={{ padding: '0.625rem 1rem' }}>
                    <span
                      style={{
                        fontSize: '0.6875rem',
                        fontWeight: 600,
                        padding: '0.15rem 0.45rem',
                        borderRadius: '4px',
                        background: 'var(--bg-tertiary)',
                        color: 'var(--text-primary)',
                        fontFamily: 'var(--font-mono)',
                      }}
                    >
                      {evt.action}
                    </span>
                  </td>

                  <td style={{ padding: '0.625rem 1rem' }}>
                    <span
                      className={`status-badge ${isBlocked ? 'block' : 'allow'}`}
                      style={{ fontSize: '0.6875rem', padding: '0.15rem 0.45rem' }}
                    >
                      {evt.decision || (isBlocked ? 'BLOCK' : 'ALLOW')}
                    </span>
                  </td>

                  <td style={{ padding: '0.625rem 1rem' }}>
                    {evt.attack_type && evt.attack_type !== 'none' ? (
                      <span
                        style={{
                          fontSize: '0.6875rem',
                          fontWeight: 600,
                          padding: '0.15rem 0.45rem',
                          borderRadius: '4px',
                          background: 'rgba(239, 68, 68, 0.12)',
                          color: 'var(--color-block)',
                          border: '1px solid rgba(239, 68, 68, 0.25)',
                        }}
                      >
                        {evt.attack_type}
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>—</span>
                    )}
                  </td>

                  <td style={{ padding: '0.625rem 1rem', color: 'var(--text-secondary)' }}>
                    {evt.tool_name ? (
                      <span style={{ color: 'var(--color-accent)', fontWeight: 600 }}>{evt.tool_name}</span>
                    ) : evt.resource_type ? (
                      <span>{evt.resource_type}</span>
                    ) : (
                      <span style={{ color: 'var(--text-dim)' }}>general</span>
                    )}
                  </td>

                  <td style={{ padding: '0.625rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    {evt.request_id ? `${evt.request_id.substring(0, 8)}...` : '—'}
                  </td>

                  <td style={{ padding: '0.625rem 1rem', textAlign: 'right' }}>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectEvent(evt);
                      }}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: 'var(--color-accent)',
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        cursor: 'pointer',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '0.2rem',
                      }}
                    >
                      Inspect <ChevronRight size={13} />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
