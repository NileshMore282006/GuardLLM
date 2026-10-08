import React from 'react';
import { RuntimeMetricsResponse } from '../../types/agentguard';
import { Cpu } from 'lucide-react';

interface RuntimeMetricsCardProps {
  metrics: RuntimeMetricsResponse | null;
  isLoading: boolean;
}

export const RuntimeMetricsCard: React.FC<RuntimeMetricsCardProps> = ({ metrics, isLoading }) => {
  if (isLoading && !metrics) {
    return (
      <div className="glass-panel" style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
        Loading runtime process metrics...
      </div>
    );
  }

  if (!metrics) {
    return (
      <div className="glass-panel" style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
        Runtime process metrics currently unavailable.
      </div>
    );
  }

  const formatUptime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const hrs = Math.floor(mins / 60);
    const secs = Math.floor(seconds % 60);
    if (hrs > 0) return `${hrs}h ${mins % 60}m ${secs}s`;
    if (mins > 0) return `${mins}m ${secs}s`;
    return `${secs}s`;
  };

  const topEndpoints = Object.entries(metrics.requests_by_endpoint || {})
    .sort(([, a], [, b]) => b - a)
    .slice(0, 8);

  const statusCodes = Object.entries(metrics.requests_by_status || {}).sort(([, a], [, b]) => b - a);

  return (
    <div className="glass-panel" style={{ padding: '1.25rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Cpu size={18} color="var(--color-warn)" />
          <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Runtime Process & Operational Metrics
          </h3>
        </div>
        <span style={{ fontSize: '0.6875rem', color: 'var(--color-warn)', background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.25)', padding: '0.15rem 0.5rem', borderRadius: '4px' }}>
          Process-Local Memory Counters (/metrics) — Resets on Gateway Restart
        </span>
      </div>

      <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
        Live telemetry counters measured in-memory by the AgentGuard gateway process.
      </p>

      {/* Primary KPI Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '0.75rem', marginBottom: '1.25rem' }}>
        <div style={{ background: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Process Uptime</div>
          <div style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.2rem' }}>
            {formatUptime(metrics.uptime_seconds)}
          </div>
        </div>

        <div style={{ background: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Total In-Process Requests</div>
          <div style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.2rem', fontFamily: 'var(--font-mono)' }}>
            {metrics.total_requests}
          </div>
        </div>

        <div style={{ background: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Rate Limited Requests</div>
          <div style={{ fontSize: '1.125rem', fontWeight: 700, color: metrics.rate_limited_count > 0 ? 'var(--color-warn)' : 'var(--text-primary)', marginTop: '0.2rem', fontFamily: 'var(--font-mono)' }}>
            {metrics.rate_limited_count}
          </div>
        </div>

        <div style={{ background: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Concurrency Rejections</div>
          <div style={{ fontSize: '1.125rem', fontWeight: 700, color: metrics.concurrency_rejected_count > 0 ? 'var(--color-block)' : 'var(--text-primary)', marginTop: '0.2rem', fontFamily: 'var(--font-mono)' }}>
            {metrics.concurrency_rejected_count}
          </div>
        </div>

        <div style={{ background: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Total Timeouts</div>
          <div style={{ fontSize: '1.125rem', fontWeight: 700, color: metrics.timeouts?.total_timeouts > 0 ? 'var(--color-warn)' : 'var(--text-primary)', marginTop: '0.2rem', fontFamily: 'var(--font-mono)' }}>
            {metrics.timeouts?.total_timeouts ?? 0}
          </div>
        </div>
      </div>

      {/* Endpoints & Status Codes Split */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1rem' }}>
        
        {/* Endpoints */}
        <div style={{ background: 'var(--bg-tertiary)', padding: '0.875rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
          <h4 style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.5rem', textTransform: 'uppercase' }}>
            Requests by Endpoint
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            {topEndpoints.map(([ep, count]) => (
              <div key={ep} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem' }}>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '200px' }} title={ep}>
                  {ep}
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {count}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* HTTP Status Codes */}
        <div style={{ background: 'var(--bg-tertiary)', padding: '0.875rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
          <h4 style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.5rem', textTransform: 'uppercase' }}>
            HTTP Status Distribution
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            {statusCodes.map(([code, count]) => {
              const is2xx = code.startsWith('2');
              const is4xx = code.startsWith('4');
              return (
                <div key={code} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem' }}>
                  <span
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 600,
                      color: is2xx ? 'var(--color-allow)' : is4xx ? 'var(--color-warn)' : 'var(--color-block)',
                    }}
                  >
                    HTTP {code}
                  </span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {count}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

      </div>
    </div>
  );
};
