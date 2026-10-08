import React from 'react';
import {
  AuditListResponse,
  RuntimeMetricsResponse,
  ApprovalDetailResponse,
  HistoryItem,
  ChatTurn,
} from '../../types/agentguard';
import {
  ShieldAlert,
  Wrench,
  UserCheck,
  Clock,
  Database,
  Cpu,
} from 'lucide-react';

interface DashboardOverviewProps {
  auditData: AuditListResponse | null;
  metricsData: RuntimeMetricsResponse | null;
  approvals: ApprovalDetailResponse[] | null;
  sessionHistory: HistoryItem[];
  sessionChatTurns: ChatTurn[];
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  auditData,
  metricsData,
  approvals,
  sessionHistory,
  sessionChatTurns,
}) => {
  // Authoritative calculations from loaded audit events
  const totalAuditEvents = auditData?.total ?? 0;
  const loadedAuditEvents = auditData?.events ?? [];

  const attackDetectionsInAudit = loadedAuditEvents.filter(
    (e) => e.attack_type && e.attack_type !== 'none'
  ).length;

  // Runtime In-process counters from /metrics
  const runtimeTotalRequests = metricsData?.total_requests ?? 0;
  const runtimeToolCalls = metricsData?.tools?.total_calls ?? 0;
  const runtimeToolBlocked = metricsData?.tools?.blocked ?? 0;

  // Approvals from GET /api/v1/approvals
  const pendingApprovalsCount = approvals
    ? approvals.filter((a) => a.status === 'PENDING_APPROVAL').length
    : metricsData?.approvals?.approval_requests_created
    ? Math.max(
        0,
        (metricsData.approvals.approval_requests_created || 0) -
          (metricsData.approvals.approval_requests_approved || 0) -
          (metricsData.approvals.approval_requests_denied || 0)
      )
    : 0;

  // Session Latency (explicitly labeled as session only!)
  const sessionLatencies: number[] = [];
  sessionHistory.forEach((h) => {
    if (h.guardResult?.latency_ms) sessionLatencies.push(h.guardResult.latency_ms);
  });
  sessionChatTurns.forEach((t) => {
    if (t.security?.latency_ms) sessionLatencies.push(t.security.latency_ms);
  });

  const avgSessionLatency =
    sessionLatencies.length > 0
      ? (sessionLatencies.reduce((a, b) => a + b, 0) / sessionLatencies.length).toFixed(1)
      : null;

  return (
    <div className="dashboard-overview-container" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '0.875rem' }}>
        
        {/* Card 1: Total Persisted Audit Events */}
        <div className="glass-panel metric-card" style={{ padding: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Persisted Audit Events
            </span>
            <Database size={16} color="var(--color-accent)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
            {totalAuditEvents.toLocaleString()}
          </div>
          <div style={{ marginTop: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <span className="source-tag backend-tag" style={{ fontSize: '0.625rem', padding: '0.1rem 0.4rem', borderRadius: '4px', background: 'rgba(99, 102, 241, 0.1)', color: 'var(--color-accent)', border: '1px solid rgba(99, 102, 241, 0.25)' }}>
              Backend /api/v1/audit/events
            </span>
          </div>
        </div>

        {/* Card 2: In-Process Runtime Requests */}
        <div className="glass-panel metric-card" style={{ padding: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
              In-Process Requests
            </span>
            <Cpu size={16} color="var(--color-accent)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
            {runtimeTotalRequests.toLocaleString()}
          </div>
          <div style={{ marginTop: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <span className="source-tag runtime-tag" style={{ fontSize: '0.625rem', padding: '0.1rem 0.4rem', borderRadius: '4px', background: 'rgba(245, 158, 11, 0.1)', color: 'var(--color-warn)', border: '1px solid rgba(245, 158, 11, 0.25)' }}>
              Runtime /metrics (In-Memory)
            </span>
          </div>
        </div>

        {/* Card 3: Audit Attacks Detected */}
        <div className="glass-panel metric-card" style={{ padding: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Attacks in Loaded Events
            </span>
            <ShieldAlert size={16} color="var(--color-block)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-block)', fontFamily: 'var(--font-mono)' }}>
            {attackDetectionsInAudit}
          </div>
          <div style={{ marginTop: '0.35rem' }}>
            <span className="source-tag backend-tag" style={{ fontSize: '0.625rem', padding: '0.1rem 0.4rem', borderRadius: '4px', background: 'rgba(239, 68, 68, 0.1)', color: 'var(--color-block)', border: '1px solid rgba(239, 68, 68, 0.25)' }}>
              Loaded Audit Sample ({loadedAuditEvents.length})
            </span>
          </div>
        </div>

        {/* Card 4: Tool Authorizations */}
        <div className="glass-panel metric-card" style={{ padding: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Tool Calls (Runtime)
            </span>
            <Wrench size={16} color="var(--color-accent)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
            {runtimeToolCalls}
            {runtimeToolBlocked > 0 && (
              <span style={{ fontSize: '0.875rem', color: 'var(--color-block)', marginLeft: '0.5rem' }}>
                ({runtimeToolBlocked} blocked)
              </span>
            )}
          </div>
          <div style={{ marginTop: '0.35rem' }}>
            <span className="source-tag runtime-tag" style={{ fontSize: '0.625rem', padding: '0.1rem 0.4rem', borderRadius: '4px', background: 'rgba(245, 158, 11, 0.1)', color: 'var(--color-warn)', border: '1px solid rgba(245, 158, 11, 0.25)' }}>
              Runtime /metrics.tools
            </span>
          </div>
        </div>

        {/* Card 5: Human Approvals */}
        <div className="glass-panel metric-card" style={{ padding: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Pending Approvals
            </span>
            <UserCheck size={16} color="var(--color-warn)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: pendingApprovalsCount > 0 ? 'var(--color-warn)' : 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
            {pendingApprovalsCount}
          </div>
          <div style={{ marginTop: '0.35rem' }}>
            <span className="source-tag backend-tag" style={{ fontSize: '0.625rem', padding: '0.1rem 0.4rem', borderRadius: '4px', background: 'rgba(99, 102, 241, 0.1)', color: 'var(--color-accent)', border: '1px solid rgba(99, 102, 241, 0.25)' }}>
              Backend /api/v1/approvals
            </span>
          </div>
        </div>

        {/* Card 6: Session Latency */}
        <div className="glass-panel metric-card" style={{ padding: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Session Latency (Avg)
            </span>
            <Clock size={16} color="var(--text-muted)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
            {avgSessionLatency ? `${avgSessionLatency} ms` : 'N/A'}
          </div>
          <div style={{ marginTop: '0.35rem' }}>
            <span className="source-tag session-tag" style={{ fontSize: '0.625rem', padding: '0.1rem 0.4rem', borderRadius: '4px', background: 'rgba(148, 163, 184, 0.1)', color: 'var(--text-secondary)', border: '1px solid rgba(148, 163, 184, 0.25)' }}>
              Frontend Session ({sessionLatencies.length} samples)
            </span>
          </div>
        </div>

      </div>
    </div>
  );
};
