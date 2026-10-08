import React from 'react';
import { ApprovalDetailResponse, RuntimeMetricsResponse } from '../../types/agentguard';
import { UserCheck, AlertTriangle } from 'lucide-react';

interface ApprovalSummaryProps {
  approvals: ApprovalDetailResponse[] | null;
  metrics: RuntimeMetricsResponse | null;
}

export const ApprovalSummary: React.FC<ApprovalSummaryProps> = ({ approvals, metrics }) => {
  const records = approvals || [];

  const pending = records.filter((r) => r.status === 'PENDING_APPROVAL');
  const approved = records.filter((r) => r.status === 'APPROVED');
  const denied = records.filter((r) => r.status === 'DENIED');
  const consumed = records.filter((r) => r.status === 'CONSUMED');
  const expired = records.filter((r) => r.status === 'EXPIRED');

  // Runtime replay counter
  const replayAttempts = metrics?.approvals?.approval_replay_attempts ?? 0;

  return (
    <div className="glass-panel" style={{ padding: '1.25rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <UserCheck size={18} color="var(--color-warn)" />
          <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Human Approval Lifecycle
          </h3>
        </div>
        <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', background: 'var(--bg-tertiary)', padding: '0.15rem 0.5rem', borderRadius: '4px' }}>
          Backend /api/v1/approvals Records ({records.length})
        </span>
      </div>

      <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
        State of one-time human-in-the-loop authorization tokens bound to high-risk tools.
      </p>

      {/* Lifecycle status breakdown cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.625rem', marginBottom: '1rem' }}>
        <div style={{ background: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', textAlign: 'center' }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--color-warn)', fontWeight: 600, textTransform: 'uppercase' }}>Pending</div>
          <div style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.2rem' }}>{pending.length}</div>
        </div>

        <div style={{ background: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', textAlign: 'center' }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--color-allow)', fontWeight: 600, textTransform: 'uppercase' }}>Approved</div>
          <div style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.2rem' }}>{approved.length}</div>
        </div>

        <div style={{ background: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', textAlign: 'center' }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--color-accent)', fontWeight: 600, textTransform: 'uppercase' }}>Consumed</div>
          <div style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.2rem' }}>{consumed.length}</div>
        </div>

        <div style={{ background: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', textAlign: 'center' }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--color-block)', fontWeight: 600, textTransform: 'uppercase' }}>Denied</div>
          <div style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.2rem' }}>{denied.length}</div>
        </div>

        <div style={{ background: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-subtle)', textAlign: 'center' }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Expired</div>
          <div style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.2rem' }}>{expired.length}</div>
        </div>
      </div>

      {replayAttempts > 0 && (
        <div style={{ background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.25)', padding: '0.6rem 0.8rem', borderRadius: '6px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.75rem', marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--color-block)' }}>
            <AlertTriangle size={15} />
            <span>Replay Attacks Defeated: <strong>{replayAttempts}</strong> attempts prevented by one-time consumption semantics.</span>
          </div>
          <span style={{ fontSize: '0.625rem', color: 'var(--text-muted)' }}>HTTP 409 Conflict</span>
        </div>
      )}

      {/* Recent Approvals list */}
      {records.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '0.4rem 0.5rem' }}>Approval ID</th>
                <th style={{ padding: '0.4rem 0.5rem' }}>Tool</th>
                <th style={{ padding: '0.4rem 0.5rem' }}>Status</th>
                <th style={{ padding: '0.4rem 0.5rem' }}>Safe Arguments Summary</th>
                <th style={{ padding: '0.4rem 0.5rem' }}>Executions</th>
              </tr>
            </thead>
            <tbody>
              {records.slice(0, 5).map((rec) => (
                <tr key={rec.approval_id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '0.4rem 0.5rem', fontFamily: 'var(--font-mono)', color: 'var(--color-accent)' }}>
                    {rec.approval_id}
                  </td>
                  <td style={{ padding: '0.4rem 0.5rem', fontWeight: 600 }}>{rec.tool_name}</td>
                  <td style={{ padding: '0.4rem 0.5rem' }}>
                    <span
                      style={{
                        padding: '0.1rem 0.35rem',
                        borderRadius: '3px',
                        fontSize: '0.6875rem',
                        fontWeight: 600,
                        background:
                          rec.status === 'CONSUMED' || rec.status === 'APPROVED'
                            ? 'rgba(16, 185, 129, 0.15)'
                            : rec.status === 'DENIED'
                            ? 'rgba(239, 68, 68, 0.15)'
                            : 'rgba(245, 158, 11, 0.15)',
                        color:
                          rec.status === 'CONSUMED' || rec.status === 'APPROVED'
                            ? 'var(--color-allow)'
                            : rec.status === 'DENIED'
                            ? 'var(--color-block)'
                            : 'var(--color-warn)',
                      }}
                    >
                      {rec.status}
                    </span>
                  </td>
                  <td style={{ padding: '0.4rem 0.5rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '0.6875rem' }}>
                    {rec.arguments_summary || '—'}
                  </td>
                  <td style={{ padding: '0.4rem 0.5rem', fontFamily: 'var(--font-mono)' }}>
                    {rec.execution_count}
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
