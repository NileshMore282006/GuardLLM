import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Activity,
  AlertTriangle,
  Database,
  Cpu,
  Lock,
} from 'lucide-react';
import {
  HealthResponse,
  ReadyResponse,
  RuntimeMetricsResponse,
  AuditVerifyResponse,
} from '../../types/agentguard';

interface SecurityPostureCardProps {
  health: HealthResponse | null;
  readiness: ReadyResponse | null;
  metrics: RuntimeMetricsResponse | null;
  integrity: AuditVerifyResponse | null;
  developerToken: string;
  onClearToken: () => void;
  isRefreshing?: boolean;
}

export const SecurityPostureCard: React.FC<SecurityPostureCardProps> = ({
  health,
  readiness,
  metrics,
  integrity,
  developerToken,
  onClearToken,
  isRefreshing = false,
}) => {
  const isHealthy = health?.status === 'ok';
  const isReady = readiness?.status === 'ready';
  const isTampered = integrity?.status === 'tampered' || (integrity && !integrity.valid);
  const isValidIntegrity = integrity?.valid === true;

  // Masked token presentation (never render full secret)
  const maskedToken = developerToken
    ? `${developerToken.substring(0, 7)}••••••••${developerToken.slice(-4)}`
    : null;

  return (
    <div
      className="glass-panel"
      style={{
        padding: '1.25rem 1.5rem',
        borderRadius: '12px',
        display: 'flex',
        flexDirection: 'column',
        gap: '1rem',
      }}
    >
      {/* Header with data tier provenance badges */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <div
            style={{
              padding: '0.45rem',
              borderRadius: '8px',
              background: isTampered
                ? 'rgba(239, 68, 68, 0.2)'
                : isReady
                ? 'rgba(16, 185, 129, 0.15)'
                : 'rgba(245, 158, 11, 0.15)',
              color: isTampered
                ? 'var(--color-block)'
                : isReady
                ? 'var(--color-allow)'
                : 'var(--color-warn)',
            }}
          >
            {isTampered ? <ShieldAlert size={20} /> : <ShieldCheck size={20} />}
          </div>
          <div>
            <h2 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
              AgentGuard Security Posture & Boundary Status
            </h2>
            <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.2rem', alignItems: 'center', flexWrap: 'wrap' }}>
              <span className="mono-text" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                Perimeter: {health ? `v${health.version}` : 'Unknown'}
              </span>
              <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>•</span>
              <span
                className="status-pill"
                style={{
                  fontSize: '0.625rem',
                  padding: '0.1rem 0.4rem',
                  background: 'var(--bg-tertiary)',
                  color: 'var(--text-secondary)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                Persisted: SQLite Hardened
              </span>
              <span
                className="status-pill"
                style={{
                  fontSize: '0.625rem',
                  padding: '0.1rem 0.4rem',
                  background: 'var(--bg-tertiary)',
                  color: 'var(--text-secondary)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                Runtime: In-Process Memory
              </span>
              <span
                className="status-pill"
                style={{
                  fontSize: '0.625rem',
                  padding: '0.1rem 0.4rem',
                  background: 'var(--bg-tertiary)',
                  color: 'var(--color-accent)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                Session: Memory-Only
              </span>
            </div>
          </div>
        </div>

        {/* Operational status badges */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          {isRefreshing && (
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
              <Activity size={12} className="spin" /> Syncing...
            </span>
          )}
          <span
            className={`status-pill ${isHealthy ? 'online' : 'offline'}`}
            style={{ fontSize: '0.6875rem', padding: '0.2rem 0.55rem' }}
          >
            Process: {health?.status?.toUpperCase() || 'OFFLINE'}
          </span>
          <span
            className={`status-pill ${isReady ? 'online' : 'offline'}`}
            style={{
              fontSize: '0.6875rem',
              padding: '0.2rem 0.55rem',
              background: isReady ? 'var(--color-allow-bg)' : 'rgba(245, 158, 11, 0.15)',
              color: isReady ? 'var(--color-allow)' : 'var(--color-warn)',
              borderColor: isReady ? 'var(--color-allow-border)' : 'rgba(245, 158, 11, 0.4)',
            }}
          >
            Readiness: {readiness?.status?.toUpperCase() || 'UNAVAILABLE'}
          </span>
          <span
            className="status-pill"
            style={{
              fontSize: '0.6875rem',
              padding: '0.2rem 0.55rem',
              background: isTampered
                ? 'rgba(239, 68, 68, 0.2)'
                : isValidIntegrity
                ? 'var(--color-allow-bg)'
                : 'var(--bg-tertiary)',
              color: isTampered
                ? 'var(--color-block)'
                : isValidIntegrity
                ? 'var(--color-allow)'
                : 'var(--text-muted)',
              borderColor: isTampered
                ? 'rgba(239, 68, 68, 0.5)'
                : isValidIntegrity
                ? 'var(--color-allow-border)'
                : 'var(--border-subtle)',
              fontWeight: 600,
            }}
          >
            Audit Chain: {isTampered ? 'TAMPERED' : isValidIntegrity ? 'VALID' : 'UNVERIFIED'}
          </span>
        </div>
      </div>

      {/* Operational Warnings Banner */}
      {isTampered && (
        <div className="alert-box danger" role="alert" style={{ margin: 0, padding: '0.75rem 1rem' }}>
          <ShieldAlert size={18} style={{ flexShrink: 0 }} />
          <div>
            <div style={{ fontWeight: 600 }}>AUDIT CHAIN INTEGRITY BREACH DETECTED</div>
            <div style={{ fontSize: '0.75rem' }}>
              The cryptographic SHA-256 audit hash link was broken. First corrupted event:{' '}
              <code>{integrity?.first_invalid_event || 'Unknown'}</code>. Immediate incident investigation required.
            </div>
          </div>
        </div>
      )}

      {!isReady && readiness && (
        <div className="alert-box warning" role="status" style={{ margin: 0, padding: '0.65rem 1rem' }}>
          <AlertTriangle size={16} style={{ flexShrink: 0 }} />
          <div style={{ fontSize: '0.75rem' }}>
            <strong>Operational Readiness Warning:</strong> One or more dependencies are degraded (Ollama status:{' '}
            {readiness.ollama || 'disconnected'}). Check dependency stores.
          </div>
        </div>
      )}

      {/* Grid of Posture Indicators */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
          gap: '0.75rem',
        }}
      >
        {/* Card 1: Auth & Session Token */}
        <div
          style={{
            padding: '0.75rem 1rem',
            background: 'var(--bg-tertiary)',
            borderRadius: '8px',
            border: '1px solid var(--border-subtle)',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.35rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
              Session Auth State
            </span>
            <Lock size={12} style={{ color: 'var(--text-muted)' }} />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.1rem' }}>
            {maskedToken ? (
              <>
                <span className="mono-text" style={{ fontSize: '0.75rem', color: 'var(--color-allow)', fontWeight: 600 }}>
                  {maskedToken}
                </span>
                <button
                  type="button"
                  onClick={onClearToken}
                  className="secondary-btn"
                  title="Purge session token from memory"
                  style={{ padding: '0.1rem 0.4rem', fontSize: '0.625rem', height: 'auto' }}
                >
                  Reset
                </button>
              </>
            ) : (
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Default / Anonymous Context
              </span>
            )}
          </div>
          <span style={{ fontSize: '0.625rem', color: 'var(--text-muted)' }}>
            Tier: In-Memory Frontend Session
          </span>
        </div>

        {/* Card 2: Inference & Guard Models */}
        <div
          style={{
            padding: '0.75rem 1rem',
            background: 'var(--bg-tertiary)',
            borderRadius: '8px',
            border: '1px solid var(--border-subtle)',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.35rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
              AI Guard Perimeter
            </span>
            <Cpu size={12} style={{ color: 'var(--text-muted)' }} />
          </div>
          <div className="mono-text" style={{ fontSize: '0.75rem', color: 'var(--text-primary)', fontWeight: 600 }}>
            {health?.guard_model || 'llama3.2:latest'}
          </div>
          <span style={{ fontSize: '0.625rem', color: 'var(--text-muted)' }}>
            Target: {health?.target_model || 'llama3.2:latest'}
          </span>
        </div>

        {/* Card 3: Cryptographic Audit Chain */}
        <div
          style={{
            padding: '0.75rem 1rem',
            background: 'var(--bg-tertiary)',
            borderRadius: '8px',
            border: '1px solid var(--border-subtle)',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.35rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
              Audit Chain Integrity
            </span>
            <Database size={12} style={{ color: 'var(--text-muted)' }} />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <span
              className="mono-text"
              style={{
                fontSize: '0.75rem',
                fontWeight: 700,
                color: isTampered ? 'var(--color-block)' : isValidIntegrity ? 'var(--color-allow)' : 'var(--text-muted)',
              }}
            >
              {integrity?.valid ? `${integrity.total_events} Events Verified` : integrity ? 'Integrity Compromised' : 'Not Verified'}
            </span>
          </div>
          <span style={{ fontSize: '0.625rem', color: 'var(--text-muted)' }}>
            Tier: Authoritative SQLite Chain
          </span>
        </div>

        {/* Card 4: In-Process Runtime Metrics */}
        <div
          style={{
            padding: '0.75rem 1rem',
            background: 'var(--bg-tertiary)',
            borderRadius: '8px',
            border: '1px solid var(--border-subtle)',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.35rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
              Runtime In-Process Metrics
            </span>
            <Activity size={12} style={{ color: 'var(--text-muted)' }} />
          </div>
          {metrics ? (
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem' }}>
              <span className="mono-text" style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                {metrics.total_requests} reqs
              </span>
              <span style={{ fontSize: '0.6875rem', color: 'var(--color-block)' }}>
                {metrics.decisions?.block || 0} blk
              </span>
              <span style={{ fontSize: '0.6875rem', color: 'var(--color-allow)' }}>
                {metrics.decisions?.allow || 0} alw
              </span>
            </div>
          ) : (
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Metrics Not Available</span>
          )}
          <span style={{ fontSize: '0.625rem', color: 'var(--text-muted)' }}>
            Uptime: {metrics ? `${Math.floor(metrics.uptime_seconds)}s` : '—'} (Process Memory)
          </span>
        </div>
      </div>
    </div>
  );
};
