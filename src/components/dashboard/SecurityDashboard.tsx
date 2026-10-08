import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  HealthResponse,
  ReadyResponse,
  RuntimeMetricsResponse,
  AuditListResponse,
  AuditEventItem,
  ApprovalDetailResponse,
  DashboardFilterState,
  HistoryItem,
  ChatTurn,
} from '../../types/agentguard';
import { agentGuardApi, AgentGuardApiError } from '../../api/agentguard';
import { BackendStatusCard } from './BackendStatusCard';
import { DashboardOverview } from './DashboardOverview';
import { DashboardFilters } from './DashboardFilters';
import { SecurityEventList } from './SecurityEventList';
import { SecurityEventDetails } from './SecurityEventDetails';
import { SecurityFlowMap } from './SecurityFlowMap';
import { DecisionSummary } from './DecisionSummary';
import { AttackSummary } from './AttackSummary';
import { ToolActionSummary } from './ToolActionSummary';
import { ApprovalSummary } from './ApprovalSummary';
import { LatencySummary } from './LatencySummary';
import { RuntimeMetricsCard } from './RuntimeMetricsCard';
import {
  RefreshCw,
  AlertCircle,
  Shield,
  Database,
  Cpu,
  UserCheck,
  History,
  Activity,
} from 'lucide-react';

interface SecurityDashboardProps {
  health: HealthResponse | null;
  isOnline: boolean;
  developerToken: string;
  sessionHistory: HistoryItem[];
  sessionChatTurns: ChatTurn[];
}

export type DashboardSubTab = 'overview' | 'audit' | 'tools-approvals' | 'runtime' | 'session';

export const SecurityDashboard: React.FC<SecurityDashboardProps> = ({
  health,
  isOnline,
  developerToken,
  sessionHistory,
  sessionChatTurns,
}) => {
  // Navigation sub-tab
  const [activeTab, setActiveTab] = useState<DashboardSubTab>('overview');

  // Backend Data
  const [ready, setReady] = useState<ReadyResponse | null>(null);
  const [metrics, setMetrics] = useState<RuntimeMetricsResponse | null>(null);
  const [auditData, setAuditData] = useState<AuditListResponse | null>(null);
  const [approvals, setApprovals] = useState<ApprovalDetailResponse[] | null>(null);

  // Loading & Error States
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [metricsError, setMetricsError] = useState<string | null>(null);

  // Selected Event for Telemetry Drawer
  const [selectedEvent, setSelectedEvent] = useState<AuditEventItem | null>(null);

  // Filters State
  const [filterState, setFilterState] = useState<DashboardFilterState>({
    decision: 'ALL',
    attackType: 'ALL',
    actionCategory: 'ALL',
    searchQuery: '',
  });

  // Fetch all authoritative dashboard data
  const fetchDashboardData = useCallback(async (isManualRefresh: boolean = false) => {
    if (isManualRefresh) {
      setIsRefreshing(true);
    } else {
      setIsLoading(true);
    }

    setAuditError(null);
    setMetricsError(null);

    // 1. Fetch Readiness
    try {
      const readyRes = await agentGuardApi.getReady();
      setReady(readyRes);
    } catch (err) {
      // Graceful degradation: ready might fail if Ollama is disconnected
      console.warn('Readiness check failed:', err);
    }

    // 2. Fetch Runtime Metrics
    try {
      const metricsRes = await agentGuardApi.getMetrics();
      setMetrics(metricsRes);
    } catch (err) {
      setMetricsError('Runtime metrics (/metrics) unavailable.');
    }

    // 3. Fetch Audit Events
    try {
      const auditRes = await agentGuardApi.getAuditEvents(
        { limit: 100 },
        developerToken
      );
      setAuditData(auditRes);
    } catch (err: any) {
      const msg = err instanceof AgentGuardApiError ? err.message : 'Security audit event history unavailable.';
      setAuditError(msg);
    }

    // 4. Fetch Approvals List
    try {
      const approvalsRes = await agentGuardApi.listApprovals(developerToken);
      setApprovals(approvalsRes);
    } catch (err) {
      console.warn('Approvals list check failed:', err);
    }

    setLastUpdated(new Date().toLocaleTimeString());
    setIsLoading(false);
    setIsRefreshing(false);
  }, [developerToken]);

  // Initial load
  useEffect(() => {
    fetchDashboardData(false);
  }, [fetchDashboardData]);

  // Client-side filtering of loaded audit events
  const filteredEvents = useMemo(() => {
    if (!auditData?.events) return [];
    return auditData.events.filter((evt) => {
      // Decision filter
      if (filterState.decision !== 'ALL') {
        const isBlock = evt.decision === 'BLOCK' || evt.action.includes('block') || evt.action.includes('deny');
        if (filterState.decision === 'BLOCK' && !isBlock) return false;
        if (filterState.decision === 'ALLOW' && isBlock) return false;
      }

      // Attack filter
      if (filterState.attackType !== 'ALL') {
        if (evt.attack_type !== filterState.attackType) return false;
      }

      // Action Category filter
      if (filterState.actionCategory !== 'ALL') {
        if (evt.action !== filterState.actionCategory) return false;
      }

      // Search Query filter
      if (filterState.searchQuery.trim()) {
        const q = filterState.searchQuery.trim().toLowerCase();
        const matchesReq = evt.request_id?.toLowerCase().includes(q);
        const matchesEvt = evt.event_id.toLowerCase().includes(q);
        const matchesAction = evt.action.toLowerCase().includes(q);
        if (!matchesReq && !matchesEvt && !matchesAction) return false;
      }

      return true;
    });
  }, [auditData, filterState]);

  return (
    <div className="security-dashboard-wrapper" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      
      {/* Dashboard Top Header Bar */}
      <div className="glass-panel" style={{ padding: '1rem 1.25rem', display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
          <div style={{ padding: '0.5rem', borderRadius: '8px', background: 'rgba(99, 102, 241, 0.15)', color: 'var(--color-accent)' }}>
            <Shield size={22} />
          </div>
          <div>
            <h2 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
              Security Operations Dashboard
            </h2>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Observational telemetry, persisted audit chain & runtime security analytics
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {lastUpdated && (
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Last updated: <strong style={{ color: 'var(--text-secondary)' }}>{lastUpdated}</strong>
            </span>
          )}

          <button
            type="button"
            onClick={() => fetchDashboardData(true)}
            disabled={isRefreshing || isLoading}
            className="action-btn"
            style={{
              padding: '0.4rem 0.85rem',
              fontSize: '0.8125rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              background: 'var(--color-accent)',
              color: '#fff',
              border: 'none',
              borderRadius: '6px',
              cursor: isRefreshing ? 'wait' : 'pointer',
            }}
          >
            <RefreshCw size={14} className={isRefreshing ? 'animate-spin' : ''} />
            <span>{isRefreshing ? 'Refreshing...' : 'Refresh'}</span>
          </button>
        </div>
      </div>

      {/* Backend Status Card (Health & Readiness) */}
      <BackendStatusCard
        health={health}
        ready={ready}
        isOnline={isOnline}
        isLoading={isLoading}
      />

      {/* Partial Error Alerts */}
      {auditError && (
        <div className="alert-box danger" role="alert" style={{ margin: 0 }}>
          <AlertCircle size={18} style={{ flexShrink: 0 }} />
          <div>
            <div style={{ fontWeight: 600 }}>Audit Events Notice</div>
            <div style={{ fontSize: '0.8125rem' }}>{auditError}</div>
          </div>
        </div>
      )}

      {metricsError && (
        <div className="alert-box warning" role="alert" style={{ margin: 0 }}>
          <AlertCircle size={18} style={{ flexShrink: 0 }} />
          <div>
            <div style={{ fontWeight: 600 }}>Runtime Metrics Notice</div>
            <div style={{ fontSize: '0.8125rem' }}>{metricsError}</div>
          </div>
        </div>
      )}

      {/* Dashboard Sub-Tab Navigation */}
      <div
        className="dashboard-tab-bar"
        style={{
          display: 'flex',
          gap: '0.35rem',
          background: 'var(--bg-tertiary)',
          padding: '4px',
          borderRadius: '8px',
          border: '1px solid var(--border-subtle)',
          overflowX: 'auto',
        }}
        role="tablist"
      >
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'overview'}
          className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
          style={{
            background: activeTab === 'overview' ? 'var(--bg-secondary)' : 'transparent',
            color: activeTab === 'overview' ? 'var(--text-primary)' : 'var(--text-secondary)',
            border: activeTab === 'overview' ? '1px solid var(--border-subtle)' : 'none',
            borderRadius: '6px',
            padding: '0.45rem 0.85rem',
            fontSize: '0.8125rem',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
          }}
        >
          <Activity size={14} />
          <span>Overview</span>
        </button>

        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'audit'}
          className={`tab-btn ${activeTab === 'audit' ? 'active' : ''}`}
          onClick={() => setActiveTab('audit')}
          style={{
            background: activeTab === 'audit' ? 'var(--bg-secondary)' : 'transparent',
            color: activeTab === 'audit' ? 'var(--text-primary)' : 'var(--text-secondary)',
            border: activeTab === 'audit' ? '1px solid var(--border-subtle)' : 'none',
            borderRadius: '6px',
            padding: '0.45rem 0.85rem',
            fontSize: '0.8125rem',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
          }}
        >
          <Database size={14} />
          <span>Audit Events</span>
          {auditData?.total !== undefined && (
            <span style={{ fontSize: '0.6875rem', background: 'rgba(99, 102, 241, 0.2)', padding: '0.1rem 0.4rem', borderRadius: '4px', color: 'var(--color-accent)' }}>
              {auditData.total}
            </span>
          )}
        </button>

        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'tools-approvals'}
          className={`tab-btn ${activeTab === 'tools-approvals' ? 'active' : ''}`}
          onClick={() => setActiveTab('tools-approvals')}
          style={{
            background: activeTab === 'tools-approvals' ? 'var(--bg-secondary)' : 'transparent',
            color: activeTab === 'tools-approvals' ? 'var(--text-primary)' : 'var(--text-secondary)',
            border: activeTab === 'tools-approvals' ? '1px solid var(--border-subtle)' : 'none',
            borderRadius: '6px',
            padding: '0.45rem 0.85rem',
            fontSize: '0.8125rem',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
          }}
        >
          <UserCheck size={14} />
          <span>Tools & Approvals</span>
        </button>

        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'runtime'}
          className={`tab-btn ${activeTab === 'runtime' ? 'active' : ''}`}
          onClick={() => setActiveTab('runtime')}
          style={{
            background: activeTab === 'runtime' ? 'var(--bg-secondary)' : 'transparent',
            color: activeTab === 'runtime' ? 'var(--text-primary)' : 'var(--text-secondary)',
            border: activeTab === 'runtime' ? '1px solid var(--border-subtle)' : 'none',
            borderRadius: '6px',
            padding: '0.45rem 0.85rem',
            fontSize: '0.8125rem',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
          }}
        >
          <Cpu size={14} />
          <span>Runtime Metrics</span>
        </button>

        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'session'}
          className={`tab-btn ${activeTab === 'session' ? 'active' : ''}`}
          onClick={() => setActiveTab('session')}
          style={{
            background: activeTab === 'session' ? 'var(--bg-secondary)' : 'transparent',
            color: activeTab === 'session' ? 'var(--text-primary)' : 'var(--text-secondary)',
            border: activeTab === 'session' ? '1px solid var(--border-subtle)' : 'none',
            borderRadius: '6px',
            padding: '0.45rem 0.85rem',
            fontSize: '0.8125rem',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
          }}
        >
          <History size={14} />
          <span>Session Activity</span>
          <span style={{ fontSize: '0.6875rem', background: 'rgba(255, 255, 255, 0.08)', padding: '0.1rem 0.4rem', borderRadius: '4px' }}>
            {sessionHistory.length + sessionChatTurns.length}
          </span>
        </button>
      </div>

      {/* TAB 1: OVERVIEW */}
      {activeTab === 'overview' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <DashboardOverview
            auditData={auditData}
            metricsData={metrics}
            approvals={approvals}
            sessionHistory={sessionHistory}
            sessionChatTurns={sessionChatTurns}
          />

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '1.25rem' }}>
            <DecisionSummary
              events={auditData?.events || []}
              metrics={metrics}
            />
            <AttackSummary
              events={auditData?.events || []}
            />
          </div>

          <LatencySummary
            sessionHistory={sessionHistory}
            sessionChatTurns={sessionChatTurns}
          />
        </div>
      )}

      {/* TAB 2: AUDIT EVENTS */}
      {activeTab === 'audit' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <DashboardFilters
            filterState={filterState}
            onFilterChange={setFilterState}
            loadedEvents={auditData?.events || []}
            totalLoaded={auditData?.events?.length || 0}
            totalFiltered={filteredEvents.length}
          />

          <SecurityFlowMap
            selectedEvent={selectedEvent}
          />

          <SecurityEventList
            events={filteredEvents}
            selectedEventId={selectedEvent?.event_id || null}
            onSelectEvent={setSelectedEvent}
            isLoading={isLoading}
          />
        </div>
      )}

      {/* TAB 3: TOOLS & APPROVALS */}
      {activeTab === 'tools-approvals' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <ToolActionSummary
            events={auditData?.events || []}
            metrics={metrics}
          />
          <ApprovalSummary
            approvals={approvals}
            metrics={metrics}
          />
        </div>
      )}

      {/* TAB 4: RUNTIME METRICS */}
      {activeTab === 'runtime' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <RuntimeMetricsCard
            metrics={metrics}
            isLoading={isLoading}
          />
        </div>
      )}

      {/* TAB 5: SESSION ACTIVITY (IN-MEMORY) */}
      {activeTab === 'session' && (
        <div className="glass-panel" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <div>
              <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                Active Browser Session Activity
              </h3>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Ephemeral in-memory user interactions (Playground & Chat) — Resets on browser refresh
              </p>
            </div>
            <span style={{ fontSize: '0.6875rem', background: 'rgba(148, 163, 184, 0.15)', color: 'var(--text-secondary)', padding: '0.2rem 0.5rem', borderRadius: '4px' }}>
              Zero Browser Storage (No LocalStorage)
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {sessionHistory.length === 0 && sessionChatTurns.length === 0 ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
                No actions taken in this browser session yet.
              </div>
            ) : (
              <>
                {sessionHistory.map((item, i) => (
                  <div key={item.id || i} style={{ background: 'var(--bg-tertiary)', padding: '0.75rem 1rem', borderRadius: '6px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8125rem' }}>
                    <div>
                      <span style={{ color: 'var(--color-accent)', fontWeight: 600, marginRight: '0.5rem' }}>[Playground]</span>
                      <span style={{ color: 'var(--text-secondary)' }}>"{item.prompt.substring(0, 45)}..."</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span className={`status-badge ${item.guardResult.decision === 'BLOCK' ? 'block' : 'allow'}`}>
                        {item.guardResult.decision}
                      </span>
                      <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                        {item.guardResult.latency_ms}ms
                      </span>
                    </div>
                  </div>
                ))}

                {sessionChatTurns.map((turn, i) => (
                  <div key={turn.id || i} style={{ background: 'var(--bg-tertiary)', padding: '0.75rem 1rem', borderRadius: '6px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8125rem' }}>
                    <div>
                      <span style={{ color: 'var(--color-warn)', fontWeight: 600, marginRight: '0.5rem' }}>[Chat Turn]</span>
                      <span style={{ color: 'var(--text-secondary)' }}>"{turn.userMessage ? turn.userMessage.substring(0, 45) : ''}..."</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span className={`status-badge ${turn.security.decision === 'BLOCK' ? 'block' : 'allow'}`}>
                        {turn.security.decision}
                      </span>
                      <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                        {turn.security.latency_ms}ms
                      </span>
                    </div>
                  </div>
                ))}
              </>
            )}
          </div>
        </div>
      )}

      {/* Selected Event Telemetry Drawer Modal */}
      <SecurityEventDetails
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />

    </div>
  );
};
