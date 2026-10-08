import React from 'react';
import { HealthResponse, ReadyResponse } from '../../types/agentguard';
import { Activity, Server, ShieldCheck } from 'lucide-react';

interface BackendStatusCardProps {
  health: HealthResponse | null;
  ready: ReadyResponse | null;
  isOnline: boolean;
  isLoading?: boolean;
}

export const BackendStatusCard: React.FC<BackendStatusCardProps> = ({
  health,
  ready,
  isOnline,
}) => {
  // Determine authoritative health and readiness states
  let healthState: 'HEALTHY' | 'UNAVAILABLE' = 'UNAVAILABLE';
  if (isOnline && health?.status === 'ok') {
    healthState = 'HEALTHY';
  }

  let readyState: 'READY' | 'NOT_READY' | 'UNAVAILABLE' = 'UNAVAILABLE';
  if (!isOnline) {
    readyState = 'UNAVAILABLE';
  } else if (ready?.status === 'ready') {
    readyState = 'READY';
  } else if (ready?.status === 'not_ready') {
    readyState = 'NOT_READY';
  }

  return (
    <div className="glass-panel dashboard-status-card" style={{ padding: '1.25rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
          <div className="status-icon-badge" style={{ padding: '0.4rem', borderRadius: '8px', background: 'rgba(99, 102, 241, 0.15)', color: 'var(--color-accent)' }}>
            <Server size={18} />
          </div>
          <div>
            <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Backend Health & Readiness
            </h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Gateway status via /health and /ready endpoints
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {/* Health Badge */}
          <div
            className={`status-pill ${healthState === 'HEALTHY' ? 'online' : 'offline'}`}
            title="Authoritative status from /health"
            style={{ fontSize: '0.75rem', padding: '0.2rem 0.6rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <Activity size={12} />
            <span>Health: {healthState}</span>
          </div>

          {/* Readiness Badge */}
          <div
            className={`status-pill ${readyState === 'READY' ? 'online' : readyState === 'NOT_READY' ? 'offline' : 'offline'}`}
            title="Authoritative status from /ready (Ollama and security dependencies)"
            style={{
              fontSize: '0.75rem',
              padding: '0.2rem 0.6rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
              background: readyState === 'READY' ? 'var(--color-allow-bg)' : 'rgba(239, 68, 68, 0.15)',
              borderColor: readyState === 'READY' ? 'var(--color-allow-border)' : 'rgba(239, 68, 68, 0.3)',
              color: readyState === 'READY' ? 'var(--color-allow)' : 'var(--color-block)',
            }}
          >
            <ShieldCheck size={12} />
            <span>Readiness: {readyState}</span>
          </div>
        </div>
      </div>

      <div className="status-details-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.75rem' }}>
        <div className="status-metric-cell" style={{ background: 'var(--bg-tertiary)', padding: '0.625rem 0.75rem', borderRadius: '6px' }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Version</div>
          <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            v{health?.version || ready?.version || '1.0.0'}
          </div>
        </div>

        <div className="status-metric-cell" style={{ background: 'var(--bg-tertiary)', padding: '0.625rem 0.75rem', borderRadius: '6px' }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Profile</div>
          <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            {ready?.environment || 'development'}
          </div>
        </div>

        <div className="status-metric-cell" style={{ background: 'var(--bg-tertiary)', padding: '0.625rem 0.75rem', borderRadius: '6px' }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Guard Model</div>
          <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--color-accent)', fontFamily: 'var(--font-mono)' }}>
            {ready?.guard_model || health?.guard_model || 'llama3.2:latest'}
          </div>
        </div>

        <div className="status-metric-cell" style={{ background: 'var(--bg-tertiary)', padding: '0.625rem 0.75rem', borderRadius: '6px' }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Target Model</div>
          <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
            {ready?.target_model || health?.target_model || 'llama3.2:latest'}
          </div>
        </div>

        <div className="status-metric-cell" style={{ background: 'var(--bg-tertiary)', padding: '0.625rem 0.75rem', borderRadius: '6px' }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Ollama Service</div>
          <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: ready?.ollama === 'connected' ? 'var(--color-allow)' : 'var(--color-warn)' }}>
            {ready?.ollama || (isOnline ? 'connected' : 'unreachable')}
          </div>
        </div>
      </div>

      {ready?.checks && (
        <div style={{ marginTop: '0.75rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border-subtle)' }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: '0.4rem', textTransform: 'uppercase' }}>
            Authoritative Dependency Verification (/ready checks)
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
            {Object.entries(ready.checks).map(([subsystem, statusVal]) => {
              const isOk = statusVal === 'ok' || statusVal === 'connected' || statusVal === 'single_process';
              return (
                <span
                  key={subsystem}
                  style={{
                    fontSize: '0.6875rem',
                    padding: '0.15rem 0.5rem',
                    borderRadius: '4px',
                    background: isOk ? 'rgba(16, 185, 129, 0.08)' : 'rgba(239, 68, 68, 0.08)',
                    border: `1px solid ${isOk ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)'}`,
                    color: isOk ? 'var(--color-allow)' : 'var(--color-block)',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  {subsystem}: {statusVal}
                </span>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
