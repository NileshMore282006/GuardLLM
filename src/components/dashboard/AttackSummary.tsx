import React from 'react';
import { AuditEventItem } from '../../types/agentguard';
import { ShieldAlert } from 'lucide-react';

interface AttackSummaryProps {
  events: AuditEventItem[];
}

export const AttackSummary: React.FC<AttackSummaryProps> = ({ events }) => {
  // Aggregate attack types strictly from backend audit records
  const attackCounts: Record<string, { count: number; blocked: number; avgRisk: number; totalRisk: number }> = {};

  events.forEach((evt) => {
    const atk = evt.attack_type;
    if (atk && atk !== 'none') {
      if (!attackCounts[atk]) {
        attackCounts[atk] = { count: 0, blocked: 0, avgRisk: 0, totalRisk: 0 };
      }
      attackCounts[atk].count += 1;
      if (evt.decision === 'BLOCK' || evt.action.includes('block') || evt.action.includes('deny')) {
        attackCounts[atk].blocked += 1;
      }
      if (evt.risk_score !== null && evt.risk_score !== undefined) {
        attackCounts[atk].totalRisk += evt.risk_score;
      }
    }
  });

  const attackList = Object.entries(attackCounts)
    .map(([type, stats]) => ({
      type,
      count: stats.count,
      blocked: stats.blocked,
      blockRate: ((stats.blocked / stats.count) * 100).toFixed(0),
      avgRisk: stats.count > 0 ? (stats.totalRisk / stats.count).toFixed(2) : 'N/A',
    }))
    .sort((a, b) => b.count - a.count);

  return (
    <div className="glass-panel" style={{ padding: '1.25rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <ShieldAlert size={18} color="var(--color-block)" />
          <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Attack Detections Taxonomy
          </h3>
        </div>
        <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', background: 'var(--bg-tertiary)', padding: '0.15rem 0.5rem', borderRadius: '4px' }}>
          Extracted Authoritatively from Audit Records
        </span>
      </div>

      <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
        Taxonomy of adversarial patterns detected and classified by the AgentGuard Guard model.
      </p>

      {attackList.length === 0 ? (
        <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8125rem', background: 'var(--bg-tertiary)', borderRadius: '6px' }}>
          No adversarial attacks recorded in the currently loaded audit events.
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '0.5rem 0.75rem', fontWeight: 600 }}>Attack Taxonomy</th>
                <th style={{ padding: '0.5rem 0.75rem', fontWeight: 600 }}>Occurrences</th>
                <th style={{ padding: '0.5rem 0.75rem', fontWeight: 600 }}>Enforcement</th>
                <th style={{ padding: '0.5rem 0.75rem', fontWeight: 600 }}>Avg Risk Score</th>
              </tr>
            </thead>
            <tbody>
              {attackList.map((item) => (
                <tr key={item.type} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '0.5rem 0.75rem' }}>
                    <span
                      style={{
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        fontFamily: 'var(--font-mono)',
                        padding: '0.15rem 0.45rem',
                        borderRadius: '4px',
                        background: 'rgba(239, 68, 68, 0.1)',
                        color: 'var(--color-block)',
                        border: '1px solid rgba(239, 68, 68, 0.25)',
                      }}
                    >
                      {item.type}
                    </span>
                  </td>
                  <td style={{ padding: '0.5rem 0.75rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {item.count}
                  </td>
                  <td style={{ padding: '0.5rem 0.75rem' }}>
                    <span style={{ color: 'var(--color-block)', fontWeight: 600 }}>
                      {item.blocked} blocked ({item.blockRate}%)
                    </span>
                  </td>
                  <td style={{ padding: '0.5rem 0.75rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                    {item.avgRisk}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
