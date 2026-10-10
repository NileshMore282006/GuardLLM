import React, { useState } from 'react';
import {
  CheckCircle2,
  Clock,
  ShieldAlert,
  Search,
  Check,
  X,
  RotateCw,
} from 'lucide-react';
import {
  ApprovalDetailResponse,
  SecOpsConfirmationState,
} from '../../types/agentguard';
import { agentGuardApi } from '../../api/agentguard';

interface OperationalQueueProps {
  approvals: ApprovalDetailResponse[];
  developerToken: string;
  onRefreshApprovals: () => void;
  onRequestConfirmation: (confirmState: SecOpsConfirmationState) => void;
  onInvestigateApproval: (approval: ApprovalDetailResponse) => void;
  isLoading?: boolean;
}

export const OperationalQueue: React.FC<OperationalQueueProps> = ({
  approvals,
  developerToken,
  onRefreshApprovals,
  onRequestConfirmation,
  onInvestigateApproval,
  isLoading = false,
}) => {
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'PENDING' | 'RESOLVED'>('ALL');
  const [errorNotice, setErrorNotice] = useState<string | null>(null);
  const [successNotice, setSuccessNotice] = useState<string | null>(null);
  const [executingId, setExecutingId] = useState<string | null>(null);
  const [isSimulating, setIsSimulating] = useState(false);

  const handleSimulate = async () => {
    setIsSimulating(true);
    setErrorNotice(null);
    try {
      const res = await agentGuardApi.simulateApproval('send_wire_transfer', 'critical', developerToken);
      setSuccessNotice(`Simulated High-Risk action generated: ${res.approval_id} (${res.tool_name}). Added to Human Queue!`);
      onRefreshApprovals();
    } catch (err: any) {
      setErrorNotice(err?.message || 'Failed to simulate approval request.');
    } finally {
      setIsSimulating(false);
    }
  };

  const safeApprovals = Array.isArray(approvals) ? approvals : [];

  const isPending = (status: string) => status === 'PENDING_APPROVAL' || status === 'PENDING';

  const filteredApprovals = safeApprovals.filter((a) => {
    if (statusFilter === 'ALL') return true;
    if (statusFilter === 'PENDING') return isPending(a.status);
    if (statusFilter === 'RESOLVED') return !isPending(a.status);
    return true;
  });

  const pendingCount = safeApprovals.filter((a) => isPending(a.status)).length;

  const handleApprove = (appr: ApprovalDetailResponse) => {
    setErrorNotice(null);
    setSuccessNotice(null);

    onRequestConfirmation({
      isOpen: true,
      operation: 'Approve & Execute Tool Action',
      targetId: appr.approval_id,
      targetType: 'approval',
      securityImpact: `Tool '${appr.tool_name}' will execute once on behalf of principal '${appr.principal_id || 'user-demo'}'. This approval token will be consumed immediately and cannot be replayed.`,
      onConfirm: async () => {
        setExecutingId(appr.approval_id);
        try {
          const resp = await agentGuardApi.approve(appr.approval_id, developerToken);
          setSuccessNotice(`Approval '${appr.approval_id}' granted. Execution decision: ${resp.decision}.`);
          onRefreshApprovals();
        } catch (err: any) {
          setErrorNotice(err?.message || 'Failed to approve tool action.');
        } finally {
          setExecutingId(null);
        }
      },
    });
  };

  const handleDeny = (appr: ApprovalDetailResponse) => {
    setErrorNotice(null);
    setSuccessNotice(null);

    onRequestConfirmation({
      isOpen: true,
      operation: 'Deny Tool Action',
      targetId: appr.approval_id,
      targetType: 'approval',
      securityImpact: `Tool '${appr.tool_name}' will be permanently blocked. The approval request will transition to DENIED state and the tool will NEVER run.`,
      onConfirm: async () => {
        setExecutingId(appr.approval_id);
        try {
          await agentGuardApi.deny(appr.approval_id, developerToken);
          setSuccessNotice(`Approval '${appr.approval_id}' denied. Action blocked.`);
          onRefreshApprovals();
        } catch (err: any) {
          setErrorNotice(err?.message || 'Failed to deny tool action.');
        } finally {
          setExecutingId(null);
        }
      },
    });
  };

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
      {/* Header & Filter Controls */}
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
              background: pendingCount > 0 ? 'rgba(245, 158, 11, 0.2)' : 'rgba(16, 185, 129, 0.15)',
              color: pendingCount > 0 ? 'var(--color-warn)' : 'var(--color-allow)',
            }}
          >
            <Clock size={18} />
          </div>
          <div>
            <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
              Operational Approval Queue
            </h3>
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
              Authoritative Human Authorization Boundary ({pendingCount} pending)
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          {/* Status Tabs */}
          <div style={{ display: 'flex', gap: '0.25rem' }} role="tablist" aria-label="Approval Status Filter">
            <button
              type="button"
              className={`secondary-btn ${statusFilter === 'ALL' ? 'active' : ''}`}
              onClick={() => setStatusFilter('ALL')}
              style={{ padding: '0.2rem 0.5rem', fontSize: '0.6875rem', borderRadius: '5px' }}
            >
              All ({approvals.length})
            </button>
            <button
              type="button"
              className={`secondary-btn ${statusFilter === 'PENDING' ? 'active' : ''}`}
              onClick={() => setStatusFilter('PENDING')}
              style={{
                padding: '0.2rem 0.5rem',
                fontSize: '0.6875rem',
                borderRadius: '5px',
                color: pendingCount > 0 ? 'var(--color-warn)' : 'inherit',
                fontWeight: pendingCount > 0 ? 600 : 400,
              }}
            >
              Pending ({pendingCount})
            </button>
            <button
              type="button"
              className={`secondary-btn ${statusFilter === 'RESOLVED' ? 'active' : ''}`}
              onClick={() => setStatusFilter('RESOLVED')}
              style={{ padding: '0.2rem 0.5rem', fontSize: '0.6875rem', borderRadius: '5px' }}
            >
              Resolved ({approvals.length - pendingCount})
            </button>
          </div>

          <button
            type="button"
            className="secondary-btn"
            onClick={onRefreshApprovals}
            disabled={isLoading}
            title="Refresh approval records from backend"
            style={{ padding: '0.25rem 0.5rem', fontSize: '0.6875rem', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}
          >
            <RotateCw size={12} className={isLoading ? 'spin' : ''} />
            <span>Refresh</span>
          </button>

          <button
            type="button"
            className="primary-btn"
            onClick={handleSimulate}
            disabled={isSimulating}
            title="Simulate high-risk tool action for 1-click HITL approval testing"
            style={{
              padding: '0.25rem 0.65rem',
              fontSize: '0.6875rem',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.35rem',
              background: 'linear-gradient(135deg, #f59e0b, #d97706)',
              color: '#fff',
              border: 'none',
              borderRadius: '5px',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            <ShieldAlert size={12} className={isSimulating ? 'spin' : ''} />
            <span>{isSimulating ? 'Simulating...' : '+ Simulate High-Risk Action'}</span>
          </button>
        </div>
      </div>

      {/* Notifications */}
      {errorNotice && (
        <div className="alert-box danger" role="alert" style={{ margin: '0.5rem 1rem', padding: '0.65rem 1rem' }}>
          <ShieldAlert size={16} style={{ flexShrink: 0 }} />
          <div style={{ fontSize: '0.75rem' }}>{errorNotice}</div>
        </div>
      )}

      {successNotice && (
        <div className="alert-box success" role="status" style={{ margin: '0.5rem 1rem', padding: '0.65rem 1rem' }}>
          <CheckCircle2 size={16} style={{ flexShrink: 0 }} />
          <div style={{ fontSize: '0.75rem' }}>{successNotice}</div>
        </div>
      )}

      {/* Queue Table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8125rem' }}>
          <thead>
            <tr style={{ background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
              <th style={{ padding: '0.65rem 1rem', fontWeight: 600 }}>Approval ID</th>
              <th style={{ padding: '0.65rem 1rem', fontWeight: 600 }}>Tool</th>
              <th style={{ padding: '0.65rem 1rem', fontWeight: 600 }}>Risk Level</th>
              <th style={{ padding: '0.65rem 1rem', fontWeight: 600 }}>Principal</th>
              <th style={{ padding: '0.65rem 1rem', fontWeight: 600 }}>Status</th>
              <th style={{ padding: '0.65rem 1rem', fontWeight: 600 }}>Arguments Summary</th>
              <th style={{ padding: '0.65rem 1rem', fontWeight: 600 }}>Created</th>
              <th style={{ padding: '0.65rem 1rem', fontWeight: 600, textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredApprovals.length === 0 ? (
              <tr>
                <td colSpan={8} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No approval records found matching status filter.
                </td>
              </tr>
            ) : (
              filteredApprovals.map((appr) => {
                const isPending = appr.status === 'PENDING_APPROVAL';
                const isApproved = appr.status === 'APPROVED' || appr.status === 'CONSUMED';
                const isDenied = appr.status === 'DENIED';
                const isCritical = appr.risk_level === 'critical';
                const isHigh = appr.risk_level === 'high';

                return (
                  <tr
                    key={appr.approval_id}
                    style={{
                      borderBottom: '1px solid var(--border-subtle)',
                      background: isPending
                        ? 'rgba(245, 158, 11, 0.03)'
                        : 'transparent',
                    }}
                  >
                    <td style={{ padding: '0.65rem 1rem' }}>
                      <span className="mono-text" style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                        {appr.approval_id}
                      </span>
                    </td>
                    <td style={{ padding: '0.65rem 1rem' }}>
                      <span className="mono-text" style={{ color: 'var(--color-accent)' }}>
                        {appr.tool_name}
                      </span>
                    </td>
                    <td style={{ padding: '0.65rem 1rem' }}>
                      <span
                        className="status-pill"
                        style={{
                          fontSize: '0.625rem',
                          padding: '0.1rem 0.45rem',
                          background: isCritical
                            ? 'rgba(239, 68, 68, 0.2)'
                            : isHigh
                            ? 'rgba(245, 158, 11, 0.2)'
                            : 'var(--bg-tertiary)',
                          color: isCritical
                            ? 'var(--color-block)'
                            : isHigh
                            ? 'var(--color-warn)'
                            : 'var(--text-secondary)',
                          fontWeight: 700,
                        }}
                      >
                        {appr.risk_level?.toUpperCase()}
                      </span>
                    </td>
                    <td style={{ padding: '0.65rem 1rem' }}>
                      <span className="mono-text" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {appr.principal_id || 'user-demo'}
                      </span>
                    </td>
                    <td style={{ padding: '0.65rem 1rem' }}>
                      <span
                        className="status-pill"
                        style={{
                          fontSize: '0.625rem',
                          padding: '0.1rem 0.45rem',
                          background: isPending
                            ? 'rgba(245, 158, 11, 0.15)'
                            : isApproved
                            ? 'var(--color-allow-bg)'
                            : isDenied
                            ? 'rgba(239, 68, 68, 0.15)'
                            : 'var(--bg-tertiary)',
                          color: isPending
                            ? 'var(--color-warn)'
                            : isApproved
                            ? 'var(--color-allow)'
                            : isDenied
                            ? 'var(--color-block)'
                            : 'var(--text-muted)',
                          borderColor: isPending
                            ? 'rgba(245, 158, 11, 0.4)'
                            : isApproved
                            ? 'var(--color-allow-border)'
                            : isDenied
                            ? 'rgba(239, 68, 68, 0.4)'
                            : 'var(--border-subtle)',
                        }}
                      >
                        {appr.status}
                      </span>
                    </td>
                    <td style={{ padding: '0.65rem 1rem', maxWidth: '240px' }}>
                      <span
                        className="mono-text"
                        style={{
                          fontSize: '0.6875rem',
                          color: 'var(--text-muted)',
                          display: 'block',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                        title={appr.arguments_summary}
                      >
                        {appr.arguments_summary || '—'}
                      </span>
                    </td>
                    <td style={{ padding: '0.65rem 1rem', color: 'var(--text-muted)', fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                      {appr.created_at ? new Date(appr.created_at * 1000).toLocaleTimeString() : '—'}
                    </td>
                    <td style={{ padding: '0.65rem 1rem', textAlign: 'right', whiteSpace: 'nowrap' }}>
                      <div style={{ display: 'inline-flex', gap: '0.35rem' }}>
                        {isPending && (
                          <>
                            <button
                              type="button"
                              className="secondary-btn"
                              data-testid={`approve-action-${appr.approval_id}`}
                              onClick={() => handleApprove(appr)}
                              disabled={executingId === appr.approval_id}
                              title="Authoritatively approve tool execution"
                              style={{
                                padding: '0.2rem 0.45rem',
                                fontSize: '0.6875rem',
                                color: 'var(--color-allow)',
                                borderColor: 'rgba(16, 185, 129, 0.3)',
                              }}
                            >
                              <Check size={12} style={{ marginRight: '0.2rem' }} />
                              Approve
                            </button>
                            <button
                              type="button"
                              className="secondary-btn"
                              data-testid={`deny-action-${appr.approval_id}`}
                              onClick={() => handleDeny(appr)}
                              disabled={executingId === appr.approval_id}
                              title="Deny tool action"
                              style={{
                                padding: '0.2rem 0.45rem',
                                fontSize: '0.6875rem',
                                color: 'var(--color-block)',
                                borderColor: 'rgba(239, 68, 68, 0.3)',
                              }}
                            >
                              <X size={12} style={{ marginRight: '0.2rem' }} />
                              Deny
                            </button>
                          </>
                        )}
                        <button
                          type="button"
                          className="secondary-btn"
                          onClick={() => onInvestigateApproval(appr)}
                          title="Investigate in Incident Workspace"
                          style={{ padding: '0.2rem 0.45rem', fontSize: '0.6875rem' }}
                        >
                          <Search size={12} />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
