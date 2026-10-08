import {
  AlertOctagon,
  AlertTriangle,
  Info,
  ShieldCheck,
  Search,
} from 'lucide-react';
import { SecOpsAlert } from '../../types/agentguard';

interface SecurityAlertsPanelProps {
  alerts: SecOpsAlert[];
  onInvestigateAlert: (alert: SecOpsAlert) => void;
  filterSeverity?: 'all' | 'critical' | 'high' | 'info';
  onFilterChange?: (severity: 'all' | 'critical' | 'high' | 'info') => void;
}

export const SecurityAlertsPanel: React.FC<SecurityAlertsPanelProps> = ({
  alerts,
  onInvestigateAlert,
  filterSeverity = 'all',
  onFilterChange,
}) => {
  const filteredAlerts = alerts.filter((a) => {
    if (filterSeverity === 'all') return true;
    return a.severity.toLowerCase() === filterSeverity.toLowerCase();
  });

  const criticalCount = alerts.filter((a) => a.severity === 'CRITICAL').length;
  const highCount = alerts.filter((a) => a.severity === 'HIGH').length;
  const infoCount = alerts.filter((a) => a.severity === 'INFO').length;

  return (
    <div
      className="glass-panel"
      style={{
        borderRadius: '12px',
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Panel Header */}
      <div
        style={{
          padding: '1rem 1.25rem',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '0.75rem',
          background: 'var(--bg-tertiary)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <div
            style={{
              padding: '0.4rem',
              borderRadius: '8px',
              background: criticalCount > 0 ? 'rgba(239, 68, 68, 0.2)' : highCount > 0 ? 'rgba(245, 158, 11, 0.2)' : 'rgba(99, 102, 241, 0.15)',
              color: criticalCount > 0 ? 'var(--color-block)' : highCount > 0 ? 'var(--color-warn)' : 'var(--color-accent)',
            }}
          >
            <AlertOctagon size={18} />
          </div>
          <div>
            <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
              High-Signal Security Alerts
            </h3>
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
              Derived Authoritatively from Audit Stream & System Posture
            </span>
          </div>
        </div>

        {/* Severity Filter Tabs */}
        {onFilterChange && (
          <div style={{ display: 'flex', gap: '0.35rem' }} role="tablist" aria-label="Alert Severity Filter">
            <button
              type="button"
              className={`secondary-btn ${filterSeverity === 'all' ? 'active' : ''}`}
              onClick={() => onFilterChange('all')}
              style={{
                padding: '0.2rem 0.5rem',
                fontSize: '0.6875rem',
                borderRadius: '5px',
                background: filterSeverity === 'all' ? 'var(--bg-card)' : 'transparent',
              }}
            >
              All ({alerts.length})
            </button>
            <button
              type="button"
              className={`secondary-btn ${filterSeverity === 'critical' ? 'active' : ''}`}
              onClick={() => onFilterChange('critical')}
              style={{
                padding: '0.2rem 0.5rem',
                fontSize: '0.6875rem',
                borderRadius: '5px',
                color: criticalCount > 0 ? 'var(--color-block)' : 'inherit',
                fontWeight: criticalCount > 0 ? 600 : 400,
              }}
            >
              Critical ({criticalCount})
            </button>
            <button
              type="button"
              className={`secondary-btn ${filterSeverity === 'high' ? 'active' : ''}`}
              onClick={() => onFilterChange('high')}
              style={{
                padding: '0.2rem 0.5rem',
                fontSize: '0.6875rem',
                borderRadius: '5px',
                color: highCount > 0 ? 'var(--color-warn)' : 'inherit',
                fontWeight: highCount > 0 ? 600 : 400,
              }}
            >
              High ({highCount})
            </button>
            <button
              type="button"
              className={`secondary-btn ${filterSeverity === 'info' ? 'active' : ''}`}
              onClick={() => onFilterChange('info')}
              style={{
                padding: '0.2rem 0.5rem',
                fontSize: '0.6875rem',
                borderRadius: '5px',
              }}
            >
              Info ({infoCount})
            </button>
          </div>
        )}
      </div>

      {/* Alerts List */}
      <div style={{ maxHeight: '360px', overflowY: 'auto', display: 'flex', flexDirection: 'column' }}>
        {filteredAlerts.length === 0 ? (
          <div
            style={{
              padding: '2.5rem 1rem',
              textAlign: 'center',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
              color: 'var(--text-muted)',
            }}
          >
            <ShieldCheck size={28} style={{ color: 'var(--color-allow)' }} />
            <span style={{ fontSize: '0.8125rem' }}>
              No active security alerts observed for selected filter.
            </span>
            <span style={{ fontSize: '0.6875rem' }}>
              Backend security gates and audit integrity reporting nominal.
            </span>
          </div>
        ) : (
          filteredAlerts.map((alert) => {
            const isCritical = alert.severity === 'CRITICAL';
            const isHigh = alert.severity === 'HIGH';

            return (
              <div
                key={alert.id}
                style={{
                  padding: '0.85rem 1.25rem',
                  borderBottom: '1px solid var(--border-subtle)',
                  display: 'flex',
                  alignItems: 'flex-start',
                  justifyContent: 'space-between',
                  gap: '1rem',
                  background: isCritical
                    ? 'rgba(239, 68, 68, 0.04)'
                    : isHigh
                    ? 'rgba(245, 158, 11, 0.04)'
                    : 'transparent',
                }}
              >
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start', flex: 1 }}>
                  <div style={{ marginTop: '0.15rem' }}>
                    {isCritical ? (
                      <AlertOctagon size={16} style={{ color: 'var(--color-block)' }} />
                    ) : isHigh ? (
                      <AlertTriangle size={16} style={{ color: 'var(--color-warn)' }} />
                    ) : (
                      <Info size={16} style={{ color: 'var(--color-accent)' }} />
                    )}
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem', flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                      <span
                        className="status-pill"
                        style={{
                          fontSize: '0.625rem',
                          padding: '0.1rem 0.4rem',
                          background: isCritical
                            ? 'rgba(239, 68, 68, 0.2)'
                            : isHigh
                            ? 'rgba(245, 158, 11, 0.2)'
                            : 'var(--bg-tertiary)',
                          color: isCritical
                            ? 'var(--color-block)'
                            : isHigh
                            ? 'var(--color-warn)'
                            : 'var(--color-accent)',
                          fontWeight: 700,
                        }}
                      >
                        {alert.severity}
                      </span>
                      <strong style={{ fontSize: '0.8125rem', color: 'var(--text-primary)' }}>
                        {alert.title}
                      </strong>
                      <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                        {alert.timestamp ? new Date(alert.timestamp * 1000).toLocaleTimeString() : '—'}
                      </span>
                    </div>

                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                      {alert.description}
                    </div>

                    {/* Raw Backend Traceability */}
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.6rem',
                        fontSize: '0.6875rem',
                        color: 'var(--text-muted)',
                        marginTop: '0.25rem',
                        flexWrap: 'wrap',
                      }}
                    >
                      <span>
                        Source: <code>{alert.source}</code>
                      </span>
                      {alert.rawAction && (
                        <span>
                          Action: <code>{alert.rawAction}</code>
                        </span>
                      )}
                      {alert.rawDecision && (
                        <span>
                          Decision: <code style={{ color: alert.rawDecision === 'BLOCK' ? 'var(--color-block)' : 'inherit' }}>{alert.rawDecision}</code>
                        </span>
                      )}
                      {alert.requestId && (
                        <span>
                          Req: <code className="mono-text">{alert.requestId.substring(0, 8)}...</code>
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Action button */}
                <button
                  type="button"
                  className="secondary-btn"
                  onClick={() => onInvestigateAlert(alert)}
                  title="Load into local Incident Workspace"
                  style={{
                    padding: '0.3rem 0.6rem',
                    fontSize: '0.6875rem',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.35rem',
                    flexShrink: 0,
                  }}
                >
                  <Search size={12} />
                  <span>Investigate</span>
                </button>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
