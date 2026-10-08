import React from 'react';
import { HistoryItem, ChatTurn } from '../../types/agentguard';
import { Clock } from 'lucide-react';

interface LatencySummaryProps {
  sessionHistory: HistoryItem[];
  sessionChatTurns: ChatTurn[];
}

export const LatencySummary: React.FC<LatencySummaryProps> = ({ sessionHistory, sessionChatTurns }) => {
  // Extract Guard latency samples from session
  const guardLatencies: number[] = [];
  const targetLatencies: number[] = [];
  const totalLatencies: number[] = [];

  sessionHistory.forEach((h) => {
    if (h.guardResult?.latency_ms) {
      guardLatencies.push(h.guardResult.latency_ms);
      totalLatencies.push(h.guardResult.latency_ms);
    }
    if (h.executeResult?.latency_ms) {
      targetLatencies.push(h.executeResult.latency_ms);
      totalLatencies.push(h.executeResult.latency_ms);
    }
  });

  sessionChatTurns.forEach((t) => {
    if (t.security?.latency_ms) {
      guardLatencies.push(t.security.latency_ms);
      totalLatencies.push(t.security.latency_ms);
    }
  });

  const calcAvg = (arr: number[]) => {
    if (arr.length === 0) return null;
    return (arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(1);
  };

  const calcMin = (arr: number[]) => {
    if (arr.length === 0) return null;
    return Math.min(...arr).toFixed(1);
  };

  const calcMax = (arr: number[]) => {
    if (arr.length === 0) return null;
    return Math.max(...arr).toFixed(1);
  };

  const avgGuard = calcAvg(guardLatencies);
  const minGuard = calcMin(guardLatencies);
  const maxGuard = calcMax(guardLatencies);

  const avgTarget = calcAvg(targetLatencies);
  const avgTotal = calcAvg(totalLatencies);

  return (
    <div className="glass-panel" style={{ padding: '1.25rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Clock size={18} color="var(--color-accent)" />
          <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Session Latency Performance
          </h3>
        </div>
        <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', background: 'var(--bg-tertiary)', padding: '0.15rem 0.5rem', borderRadius: '4px' }}>
          Frontend Session Samples (In-Memory Only)
        </span>
      </div>

      <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
        Measured round-trip latencies for Guard security checks and Target inferences recorded during your active session.
      </p>

      {totalLatencies.length === 0 ? (
        <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8125rem', background: 'var(--bg-tertiary)', borderRadius: '6px' }}>
          No session latency samples available yet. Test prompts in Playground, Chat, or Agent Security to generate telemetry.
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.75rem' }}>
          <div style={{ background: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Avg Guard Latency</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--color-accent)', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
              {avgGuard ? `${avgGuard} ms` : 'N/A'}
            </div>
            {minGuard && maxGuard && (
              <div style={{ fontSize: '0.6875rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
                min: {minGuard}ms | max: {maxGuard}ms
              </div>
            )}
          </div>

          <div style={{ background: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Avg Target Latency</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
              {avgTarget ? `${avgTarget} ms` : 'N/A'}
            </div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
              {targetLatencies.length} inference calls
            </div>
          </div>

          <div style={{ background: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Total Gateway Latency</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--color-allow)', fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
              {avgTotal ? `${avgTotal} ms` : 'N/A'}
            </div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
              across {totalLatencies.length} session interactions
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
