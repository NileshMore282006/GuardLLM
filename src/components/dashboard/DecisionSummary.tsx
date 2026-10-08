import React from 'react';
import { AuditEventItem, RuntimeMetricsResponse } from '../../types/agentguard';

interface DecisionSummaryProps {
  events: AuditEventItem[];
  metrics: RuntimeMetricsResponse | null;
}

export const DecisionSummary: React.FC<DecisionSummaryProps> = ({ events, metrics }) => {
  // 1. Loaded Events Statistics
  const totalLoaded = events.length;
  const allowEvents = events.filter((e) => e.decision === 'ALLOW' || e.action === 'guard_allow');
  const blockEvents = events.filter((e) => e.decision === 'BLOCK' || e.action.includes('block') || e.action.includes('deny'));
  const otherEvents = events.filter((e) => !allowEvents.includes(e) && !blockEvents.includes(e));

  const allowPct = totalLoaded > 0 ? ((allowEvents.length / totalLoaded) * 100).toFixed(1) : '0.0';
  const blockPct = totalLoaded > 0 ? ((blockEvents.length / totalLoaded) * 100).toFixed(1) : '0.0';
  const otherPct = totalLoaded > 0 ? ((otherEvents.length / totalLoaded) * 100).toFixed(1) : '0.0';

  // 2. Runtime Metrics Statistics (from /metrics.decisions)
  const runtimeAllow = metrics?.decisions?.allow ?? 0;
  const runtimeBlock = metrics?.decisions?.block ?? 0;
  const runtimeError = metrics?.decisions?.error ?? 0;
  const runtimeTotal = runtimeAllow + runtimeBlock + runtimeError;

  const runtimeAllowPct = runtimeTotal > 0 ? ((runtimeAllow / runtimeTotal) * 100).toFixed(1) : '0.0';
  const runtimeBlockPct = runtimeTotal > 0 ? ((runtimeBlock / runtimeTotal) * 100).toFixed(1) : '0.0';

  return (
    <div className="glass-panel" style={{ padding: '1.25rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
        <div>
          <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Security Decision Analytics
          </h3>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Authoritative breakdown of security outcomes
          </p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
        
        {/* Panel A: Loaded Persistent Audit Events */}
        <div style={{ background: 'var(--bg-tertiary)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Loaded Audit Sample ({totalLoaded})
            </span>
            <span style={{ fontSize: '0.625rem', padding: '0.1rem 0.35rem', borderRadius: '4px', background: 'rgba(99, 102, 241, 0.1)', color: 'var(--color-accent)' }}>
              Audit Events
            </span>
          </div>

          {/* Visual Percentage Progress Bar */}
          <div style={{ display: 'flex', height: '10px', borderRadius: '5px', overflow: 'hidden', marginBottom: '0.75rem', background: 'rgba(255, 255, 255, 0.05)' }}>
            <div style={{ width: `${allowPct}%`, background: 'var(--color-allow)', transition: 'width 0.3s' }} title={`ALLOW: ${allowPct}%`} />
            <div style={{ width: `${blockPct}%`, background: 'var(--color-block)', transition: 'width 0.3s' }} title={`BLOCK: ${blockPct}%`} />
            <div style={{ width: `${otherPct}%`, background: 'var(--text-muted)', transition: 'width 0.3s' }} title={`OTHER: ${otherPct}%`} />
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '2px', background: 'var(--color-allow)' }} />
              <span style={{ color: 'var(--text-secondary)' }}>ALLOW: <strong>{allowEvents.length}</strong> ({allowPct}%)</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '2px', background: 'var(--color-block)' }} />
              <span style={{ color: 'var(--text-secondary)' }}>BLOCK: <strong>{blockEvents.length}</strong> ({blockPct}%)</span>
            </div>
          </div>
        </div>

        {/* Panel B: Runtime /metrics Process Counters */}
        <div style={{ background: 'var(--bg-tertiary)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              In-Process Runtime Decisions ({runtimeTotal})
            </span>
            <span style={{ fontSize: '0.625rem', padding: '0.1rem 0.35rem', borderRadius: '4px', background: 'rgba(245, 158, 11, 0.1)', color: 'var(--color-warn)' }}>
              Runtime /metrics
            </span>
          </div>

          {/* Visual Percentage Progress Bar */}
          <div style={{ display: 'flex', height: '10px', borderRadius: '5px', overflow: 'hidden', marginBottom: '0.75rem', background: 'rgba(255, 255, 255, 0.05)' }}>
            <div style={{ width: `${runtimeAllowPct}%`, background: 'var(--color-allow)', transition: 'width 0.3s' }} title={`ALLOW: ${runtimeAllowPct}%`} />
            <div style={{ width: `${runtimeBlockPct}%`, background: 'var(--color-block)', transition: 'width 0.3s' }} title={`BLOCK: ${runtimeBlockPct}%`} />
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '2px', background: 'var(--color-allow)' }} />
              <span style={{ color: 'var(--text-secondary)' }}>ALLOW: <strong>{runtimeAllow}</strong> ({runtimeAllowPct}%)</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '2px', background: 'var(--color-block)' }} />
              <span style={{ color: 'var(--text-secondary)' }}>BLOCK: <strong>{runtimeBlock}</strong> ({runtimeBlockPct}%)</span>
            </div>
            {runtimeError > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                <span style={{ color: 'var(--color-warn)' }}>ERR: <strong>{runtimeError}</strong></span>
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
};
