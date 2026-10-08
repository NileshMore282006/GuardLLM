import React, { useState, useEffect, useCallback } from 'react';
import {
  RotateCw,
  ShieldAlert,
  Clock,
} from 'lucide-react';
import {
  HealthResponse,
  ReadyResponse,
  RuntimeMetricsResponse,
  AuditVerifyResponse,
  ApprovalDetailResponse,
  AuditEventItem,
  SecOpsAlert,
  IncidentInvestigation,
  SecOpsConfirmationState,
} from '../../types/agentguard';
import { agentGuardApi } from '../../api/agentguard';
import { SecurityPostureCard } from './SecurityPostureCard';
import { SecurityAlertsPanel } from './SecurityAlertsPanel';
import { OperationalQueue } from './OperationalQueue';
import { SecurityEventStream } from './SecurityEventStream';
import { IncidentWorkspace } from './IncidentWorkspace';
import { SecurityResponseActions } from './SecurityResponseActions';
import { SecOpsConfirmationDialog } from './SecOpsConfirmationDialog';
import { AuditEventDetails } from '../admin/AuditEventDetails';

interface SecurityOperationsViewProps {
  health: HealthResponse | null;
  developerToken: string;
  setDeveloperToken: (token: string) => void;
}

export const SecurityOperationsView: React.FC<SecurityOperationsViewProps> = ({
  health,
  developerToken,
  setDeveloperToken,
}) => {
  // Posture state
  const [readiness, setReadiness] = useState<ReadyResponse | null>(null);
  const [metrics, setMetrics] = useState<RuntimeMetricsResponse | null>(null);
  const [integrity, setIntegrity] = useState<AuditVerifyResponse | null>(null);

  // Operational Queue (Approvals)
  const [approvals, setApprovals] = useState<ApprovalDetailResponse[]>([]);
  const [isApprovalsLoading, setIsApprovalsLoading] = useState(false);

  // Security Event Stream
  const [auditEvents, setAuditEvents] = useState<AuditEventItem[]>([]);
  const [auditTotal, setAuditTotal] = useState<number>(0);
  const auditLimit = 20;
  const [auditOffset, setAuditOffset] = useState<number>(0);
  const [auditFilters, setAuditFilters] = useState<{
    requestId?: string;
    principalId?: string;
    action?: string;
    decision?: string;
    resourceType?: string;
  }>({});
  const [isAuditLoading, setIsAuditLoading] = useState(false);

  // Alerts
  const [alerts, setAlerts] = useState<SecOpsAlert[]>([]);
  const [alertSeverityFilter, setAlertSeverityFilter] = useState<'all' | 'critical' | 'high' | 'info'>('all');

  // Local Incident Investigation Workspace (session-only, ZERO storage persistence)
  const [investigation, setInvestigation] = useState<IncidentInvestigation>({
    id: `inv-${Date.now().toString(36)}`,
    title: 'Active Security Investigation',
    createdAt: Date.now(),
    selectedEventIds: [],
    correlatedRequestIds: [],
    correlatedPrincipals: [],
    correlatedTenants: [],
    correlatedTools: [],
    correlatedApprovals: [],
    correlatedPolicies: [],
    notes: '',
    status: 'OPEN',
  });

  // Modal / Drawer states
  const [inspectingEvent, setInspectingEvent] = useState<AuditEventItem | null>(null);
  const [confirmState, setConfirmState] = useState<SecOpsConfirmationState>({
    isOpen: false,
    operation: '',
    targetId: '',
    targetType: 'credential',
    securityImpact: '',
    onConfirm: async () => {},
  });
  const [isConfirmExecuting, setIsConfirmExecuting] = useState(false);
  const [confirmError, setConfirmError] = useState<string | null>(null);

  // Sync / Refresh control state
  const [isRefreshingAll, setIsRefreshingAll] = useState(false);
  const [lastRefreshedAt, setLastRefreshedAt] = useState<Date>(new Date());
  const [autoRefreshEnabled, setAutoRefreshEnabled] = useState(false);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);

  // Fetch Posture (Ready, Metrics, Integrity)
  const fetchPosture = useCallback(async () => {
    try {
      const [readyResp, metricsResp] = await Promise.allSettled([
        agentGuardApi.getReady(),
        agentGuardApi.getMetrics(),
      ]);

      if (readyResp.status === 'fulfilled') setReadiness(readyResp.value);
      if (metricsResp.status === 'fulfilled') setMetrics(metricsResp.value);

      // Verify audit integrity
      try {
        const verifyResp = await agentGuardApi.verifyAuditChain(developerToken);
        setIntegrity(verifyResp);
      } catch (err: any) {
        // If 403 or unauthenticated, integrity verification is restricted to admin
        if (err?.status === 403) {
          setIntegrity({
            valid: false,
            status: 'incompatible',
            total_events: 0,
            details: 'Admin authority required for cryptographic audit verification.',
          });
        }
      }
    } catch (err) {
      // safe gateway degradation
    }
  }, [developerToken]);

  // Fetch Approvals
  const fetchApprovals = useCallback(async () => {
    setIsApprovalsLoading(true);
    try {
      const resp = await agentGuardApi.listApprovals(developerToken);
      setApprovals(Array.isArray(resp) ? resp : (resp as any)?.approvals || []);
    } catch {
      // fail closed
    } finally {
      setIsApprovalsLoading(false);
    }
  }, [developerToken]);

  // Fetch Audit Events
  const fetchAuditEvents = useCallback(async () => {
    setIsAuditLoading(true);
    try {
      const resp = await agentGuardApi.getAuditEvents(
        {
          limit: auditLimit,
          offset: auditOffset,
          request_id: auditFilters.requestId || undefined,
          principal_id: auditFilters.principalId || undefined,
          action: auditFilters.action || undefined,
          decision: auditFilters.decision || undefined,
          resource_type: auditFilters.resourceType || undefined,
        },
        developerToken
      );
      setAuditEvents(resp.events || []);
      setAuditTotal(resp.total || 0);
    } catch {
      // Safe error
    } finally {
      setIsAuditLoading(false);
    }
  }, [auditLimit, auditOffset, auditFilters, developerToken]);

  // Derive Alerts from Real Backend Telemetry
  const deriveAlerts = useCallback(() => {
    const derived: SecOpsAlert[] = [];

    // 1. Audit integrity alert
    if (integrity && (!integrity.valid || integrity.status === 'tampered')) {
      derived.push({
        id: 'alert-integrity-tampered',
        severity: 'CRITICAL',
        title: 'Cryptographic Audit Chain Integrity Breach',
        description: `Chain verification detected tampering. First corrupted event: ${integrity.first_invalid_event || 'Unknown'}.`,
        source: 'backend.audit.verify',
        timestamp: Math.floor(Date.now() / 1000),
        rawAction: 'audit_verify',
        rawDecision: 'TAMPERED',
      });
    }

    // 2. Pending high-risk / critical approvals
    const safeApprovals = Array.isArray(approvals) ? approvals : [];
    for (const appr of safeApprovals) {
      if (appr.status === 'PENDING_APPROVAL') {
        const isCritical = appr.risk_level === 'critical';
        const isHigh = appr.risk_level === 'high';
        derived.push({
          id: `alert-appr-${appr.approval_id}`,
          severity: isCritical ? 'CRITICAL' : isHigh ? 'HIGH' : 'INFO',
          title: `Pending Tool Authorization: ${appr.tool_name}`,
          description: `Tool '${appr.tool_name}' proposed by '${appr.principal_id || 'user-demo'}' requires human authorization.`,
          source: 'backend.approvals',
          timestamp: appr.created_at,
          requestId: appr.request_id,
          rawAction: 'approval_create',
          rawDecision: 'PENDING_APPROVAL',
        });
      }
    }

    // 3. High-signal audit events (blocks, auth failures, tenant violations)
    for (const ev of auditEvents) {
      if (ev.action === 'auth_failure') {
        derived.push({
          id: `alert-auth-fail-${ev.event_id}`,
          severity: 'HIGH',
          title: 'Authentication Boundary Failure',
          description: `Authentication failed for principal '${ev.principal_id || 'anonymous'}'. Invalid credential or missing Bearer token.`,
          source: 'backend.auth',
          timestamp: Math.floor(ev.timestamp),
          eventId: ev.event_id,
          requestId: ev.request_id || undefined,
          rawAction: ev.action || undefined,
          rawDecision: ev.decision || undefined,
        });
      } else if (ev.action === 'authz_failure' || ev.error_code === 'FORBIDDEN') {
        derived.push({
          id: `alert-authz-fail-${ev.event_id}`,
          severity: 'CRITICAL',
          title: 'Unauthorized Privileged Action Rejected',
          description: `Principal '${ev.principal_id || 'unknown'}' attempted unauthorized action on resource '${ev.resource_type || 'unknown'}'.`,
          source: 'backend.authz',
          timestamp: Math.floor(ev.timestamp),
          eventId: ev.event_id,
          requestId: ev.request_id || undefined,
          rawAction: ev.action || undefined,
          rawDecision: ev.decision || undefined,
        });
      } else if (ev.decision === 'BLOCK' && (ev.attack_type && ev.attack_type !== 'none')) {
        derived.push({
          id: `alert-guard-block-${ev.event_id}`,
          severity: 'HIGH',
          title: `Threat Blocked: ${ev.attack_type}`,
          description: `Guard perimeter blocked attack type '${ev.attack_type}' on request '${ev.request_id || 'unknown'}'.`,
          source: 'backend.guard',
          timestamp: Math.floor(ev.timestamp),
          eventId: ev.event_id,
          requestId: ev.request_id || undefined,
          rawAction: ev.action || undefined,
          rawDecision: ev.decision || undefined,
        });
      } else if (ev.action === 'tenant_disable' || ev.action === 'credential_revoke') {
        derived.push({
          id: `alert-sec-lifecycle-${ev.event_id}`,
          severity: 'INFO',
          title: `Security Lifecycle Event: ${ev.action}`,
          description: `Administrative lifecycle action executed for resource '${ev.resource_id || 'unknown'}'.`,
          source: 'backend.lifecycle',
          timestamp: Math.floor(ev.timestamp),
          eventId: ev.event_id,
          requestId: ev.request_id || undefined,
          rawAction: ev.action || undefined,
          rawDecision: ev.decision || undefined,
        });
      }
    }

    setAlerts(derived);
  }, [integrity, approvals, auditEvents]);

  // Master Refresh
  const handleRefreshAll = useCallback(async () => {
    setIsRefreshingAll(true);
    setErrorBanner(null);
    try {
      await Promise.all([
        fetchPosture(),
        fetchApprovals(),
        fetchAuditEvents(),
      ]);
      setLastRefreshedAt(new Date());
    } catch (err: any) {
      setErrorBanner('Failed to synchronize one or more security operations endpoints.');
    } finally {
      setIsRefreshingAll(false);
    }
  }, [fetchPosture, fetchApprovals, fetchAuditEvents]);

  // Auto-refresh interval
  useEffect(() => {
    handleRefreshAll();
  }, [handleRefreshAll]);

  useEffect(() => {
    deriveAlerts();
  }, [deriveAlerts]);

  useEffect(() => {
    if (!autoRefreshEnabled) return;
    const interval = setInterval(() => {
      handleRefreshAll();
    }, 15000); // Conservative 15s interval
    return () => clearInterval(interval);
  }, [autoRefreshEnabled, handleRefreshAll]);

  // Investigation Workspace Actions
  const handleAddEventToInvestigation = (event: AuditEventItem) => {
    setInvestigation((prev) => {
      if (prev.selectedEventIds.includes(event.event_id)) return prev;

      const newIds = [...prev.selectedEventIds, event.event_id];
      const newReqs = event.request_id && !prev.correlatedRequestIds.includes(event.request_id)
        ? [...prev.correlatedRequestIds, event.request_id]
        : prev.correlatedRequestIds;
      const newPrincs = event.principal_id && !prev.correlatedPrincipals.includes(event.principal_id)
        ? [...prev.correlatedPrincipals, event.principal_id]
        : prev.correlatedPrincipals;
      const newTenants = event.tenant_id && !prev.correlatedTenants.includes(event.tenant_id)
        ? [...prev.correlatedTenants, event.tenant_id]
        : prev.correlatedTenants;
      const newTools = event.tool_name && !prev.correlatedTools.includes(event.tool_name)
        ? [...prev.correlatedTools, event.tool_name]
        : prev.correlatedTools;
      const newApprovals = event.approval_id && !prev.correlatedApprovals.includes(event.approval_id)
        ? [...prev.correlatedApprovals, event.approval_id]
        : prev.correlatedApprovals;
      const newPolicies = event.policy_id && !prev.correlatedPolicies.includes(event.policy_id)
        ? [...prev.correlatedPolicies, event.policy_id]
        : prev.correlatedPolicies;

      return {
        ...prev,
        selectedEventIds: newIds,
        correlatedRequestIds: newReqs,
        correlatedPrincipals: newPrincs,
        correlatedTenants: newTenants,
        correlatedTools: newTools,
        correlatedApprovals: newApprovals,
        correlatedPolicies: newPolicies,
      };
    });
  };

  const handleRemoveEventFromInvestigation = (eventId: string) => {
    setInvestigation((prev) => ({
      ...prev,
      selectedEventIds: prev.selectedEventIds.filter((id) => id !== eventId),
    }));
  };

  const handleClearInvestigation = () => {
    setInvestigation({
      id: `inv-${Date.now().toString(36)}`,
      title: 'Active Security Investigation',
      createdAt: Date.now(),
      selectedEventIds: [],
      correlatedRequestIds: [],
      correlatedPrincipals: [],
      correlatedTenants: [],
      correlatedTools: [],
      correlatedApprovals: [],
      correlatedPolicies: [],
      notes: '',
      status: 'OPEN',
    });
  };

  const handleInvestigateAlert = (alert: SecOpsAlert) => {
    if (alert.eventId) {
      const match = auditEvents.find((e) => e.event_id === alert.eventId);
      if (match) handleAddEventToInvestigation(match);
    } else if (alert.requestId) {
      setAuditFilters({ requestId: alert.requestId });
      setAuditOffset(0);
    }
  };

  const handleInvestigateApproval = (approval: ApprovalDetailResponse) => {
    if (approval.request_id) {
      setAuditFilters({ requestId: approval.request_id });
      setAuditOffset(0);
    }
  };

  const handleExecuteConfirmation = async () => {
    setIsConfirmExecuting(true);
    setConfirmError(null);
    try {
      await confirmState.onConfirm();
      setConfirmState((prev) => ({ ...prev, isOpen: false }));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Mitigation action failed';
      setConfirmError(msg);
    } finally {
      setIsConfirmExecuting(false);
    }
  };

  const selectedEventsData = auditEvents.filter((e) =>
    investigation.selectedEventIds.includes(e.event_id)
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', width: '100%' }}>
      {/* Top Banner & Refresh Controls */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <h1 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Security Operations & Incident Response
            </h1>
            <span
              className="status-pill"
              style={{
                fontSize: '0.6875rem',
                background: 'rgba(99, 102, 241, 0.15)',
                color: 'var(--color-accent)',
                borderColor: 'rgba(99, 102, 241, 0.3)',
              }}
            >
              Control Console v0.6
            </span>
          </div>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: '0.2rem 0 0 0' }}>
            Unified operator console for boundary posture, high-signal alerts, human authorization, and incident response.
          </p>
        </div>

        {/* Sync Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            <Clock size={13} />
            <span>Updated: {lastRefreshedAt.toLocaleTimeString()}</span>
          </div>

          <label
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
              fontSize: '0.75rem',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
            }}
          >
            <input
              type="checkbox"
              checked={autoRefreshEnabled}
              onChange={(e) => setAutoRefreshEnabled(e.target.checked)}
              style={{ accentColor: 'var(--color-accent)' }}
            />
            <span>Auto-sync (15s)</span>
          </label>

          <button
            type="button"
            className="secondary-btn"
            onClick={handleRefreshAll}
            disabled={isRefreshingAll}
            style={{
              padding: '0.4rem 0.85rem',
              fontSize: '0.75rem',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.4rem',
            }}
          >
            <RotateCw size={13} className={isRefreshingAll ? 'spin' : ''} />
            <span>Refresh All</span>
          </button>
        </div>
      </div>

      {errorBanner && (
        <div className="alert-box danger" role="alert" style={{ margin: 0, padding: '0.75rem 1rem' }}>
          <ShieldAlert size={18} style={{ flexShrink: 0 }} />
          <div style={{ fontSize: '0.8125rem' }}>{errorBanner}</div>
        </div>
      )}

      {/* 1. Security Posture Strip */}
      <SecurityPostureCard
        health={health}
        readiness={readiness}
        metrics={metrics}
        integrity={integrity}
        developerToken={developerToken}
        onClearToken={() => setDeveloperToken('')}
        isRefreshing={isRefreshingAll}
      />

      {/* 2. High-Signal Security Alerts */}
      <SecurityAlertsPanel
        alerts={alerts}
        onInvestigateAlert={handleInvestigateAlert}
        filterSeverity={alertSeverityFilter}
        onFilterChange={setAlertSeverityFilter}
      />

      {/* 3. Operational Queue (Human Approvals) */}
      <OperationalQueue
        approvals={approvals}
        developerToken={developerToken}
        onRefreshApprovals={fetchApprovals}
        onRequestConfirmation={(c) => {
          setConfirmError(null);
          setConfirmState(c);
        }}
        onInvestigateApproval={handleInvestigateApproval}
        isLoading={isApprovalsLoading}
      />

      {/* 4. Incident Investigation Workspace */}
      <IncidentWorkspace
        investigation={investigation}
        selectedEventsData={selectedEventsData}
        onUpdateInvestigation={setInvestigation}
        onRemoveEvent={handleRemoveEventFromInvestigation}
        onClearWorkspace={handleClearInvestigation}
        onInspectEvent={(ev) => setInspectingEvent(ev)}
      />

      {/* 5. Live Security Event Stream */}
      <SecurityEventStream
        events={auditEvents}
        totalEvents={auditTotal}
        limit={auditLimit}
        offset={auditOffset}
        isLoading={isAuditLoading}
        onPageChange={(newOffset) => setAuditOffset(newOffset)}
        onFilterChange={(filters) => {
          setAuditFilters(filters);
          setAuditOffset(0);
        }}
        onInspectEvent={(ev) => setInspectingEvent(ev)}
        onAddToInvestigation={handleAddEventToInvestigation}
        onRefresh={fetchAuditEvents}
      />

      {/* 6. Authoritative Security Mitigation Controls */}
      <SecurityResponseActions
        developerToken={developerToken}
        onRequestConfirmation={(c) => {
          setConfirmError(null);
          setConfirmState(c);
        }}
        onRefreshAll={handleRefreshAll}
      />

      {/* Audit Event Details Modal */}
      <AuditEventDetails
        event={inspectingEvent}
        onClose={() => setInspectingEvent(null)}
      />

      {/* Destructive Action Confirmation Dialog */}
      <SecOpsConfirmationDialog
        state={{
          ...confirmState,
          onConfirm: handleExecuteConfirmation,
        }}
        onClose={() => setConfirmState((prev) => ({ ...prev, isOpen: false }))}
        isExecuting={isConfirmExecuting}
        error={confirmError}
      />
    </div>
  );
};
