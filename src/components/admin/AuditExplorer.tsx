import React, { useState, useEffect, useCallback } from 'react';
import { ScrollText, RefreshCw, ShieldCheck, Filter, ChevronLeft, ChevronRight, Loader2, Eye, ShieldAlert } from 'lucide-react';
import { AuditEventItem, AuditVerifyResponse } from '../../types/agentguard';
import { agentGuardApi, AgentGuardApiError } from '../../api/agentguard';
import { AuditIntegrityBadge } from './AuditIntegrityBadge';
import { AuditEventDetails } from './AuditEventDetails';

interface AuditExplorerProps {
  token?: string;
  isGlobalAdmin?: boolean;
}

export const AuditExplorer: React.FC<AuditExplorerProps> = ({
  token,
  isGlobalAdmin: _isGlobalAdmin = false,
}) => {
  const [events, setEvents] = useState<AuditEventItem[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [filterRequestId, setFilterRequestId] = useState('');
  const [filterPrincipalId, setFilterPrincipalId] = useState('');
  const [filterTenantId, setFilterTenantId] = useState('');
  const [filterDecision, setFilterDecision] = useState<string>('ALL');
  const [filterAction, setFilterAction] = useState<string>('');

  // Pagination
  const [limit] = useState<number>(20);
  const [offset, setOffset] = useState<number>(0);

  // Cryptographic Verification State
  const [verifyResult, setVerifyResult] = useState<AuditVerifyResponse | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);

  // Inspect Event State
  const [selectedEvent, setSelectedEvent] = useState<AuditEventItem | null>(null);

  const fetchAuditEvents = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const resp = await agentGuardApi.getAuditEvents(
        {
          request_id: filterRequestId.trim() || undefined,
          principal_id: filterPrincipalId.trim() || undefined,
          tenant_id: filterTenantId.trim() || undefined,
          decision: filterDecision !== 'ALL' ? filterDecision : undefined,
          action: filterAction.trim() || undefined,
          limit,
          offset,
        },
        token
      );
      setEvents(resp.events || []);
      setTotalCount(resp.total || 0);
    } catch (err: any) {
      if (err instanceof AgentGuardApiError) {
        setError(err.message);
      } else {
        setError('Failed to fetch audit events from the backend.');
      }
    } finally {
      setIsLoading(false);
    }
  }, [filterRequestId, filterPrincipalId, filterTenantId, filterDecision, filterAction, limit, offset, token]);

  useEffect(() => {
    fetchAuditEvents();
  }, [fetchAuditEvents]);

  const handleVerifyChain = async () => {
    setIsVerifying(true);
    setError(null);
    try {
      const res = await agentGuardApi.verifyAuditChain(token);
      setVerifyResult(res);
    } catch (err: any) {
      setError(err?.message || 'Failed to verify cryptographic audit chain.');
    } finally {
      setIsVerifying(false);
    }
  };

  const totalPages = Math.ceil(totalCount / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  const handleNextPage = () => {
    if (offset + limit < totalCount) {
      setOffset(offset + limit);
    }
  };

  const handlePrevPage = () => {
    if (offset >= limit) {
      setOffset(offset - limit);
    }
  };

  const handleResetFilters = () => {
    setFilterRequestId('');
    setFilterPrincipalId('');
    setFilterTenantId('');
    setFilterDecision('ALL');
    setFilterAction('');
    setOffset(0);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <div style={{ padding: '0.45rem', borderRadius: '8px', background: 'rgba(99, 102, 241, 0.15)', color: 'var(--color-accent)' }}>
            <ScrollText size={20} />
          </div>
          <div>
            <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Audit Explorer & Integrity Gate
            </h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Authoritative persistent audit log with SHA-256 hash chaining
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="secondary-btn"
            onClick={fetchAuditEvents}
            disabled={isLoading}
            style={{ fontSize: '0.8125rem', padding: '0.45rem 0.85rem' }}
          >
            <RefreshCw size={14} className={isLoading ? 'spinner' : ''} style={{ marginRight: '0.35rem' }} />
            Refresh
          </button>
          <button
            type="button"
            className="primary-btn"
            onClick={handleVerifyChain}
            disabled={isVerifying}
            style={{ fontSize: '0.8125rem', padding: '0.45rem 1rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <ShieldCheck size={15} />
            <span>{isVerifying ? 'Verifying Chain...' : 'Verify Cryptographic Integrity'}</span>
          </button>
        </div>
      </div>

      {/* Cryptographic Verification Badge */}
      <AuditIntegrityBadge verifyResult={verifyResult} isLoading={isVerifying} />

      {error && (
        <div className="alert-box danger" role="alert" style={{ margin: 0, padding: '0.75rem 1rem' }}>
          <ShieldAlert size={18} style={{ flexShrink: 0 }} />
          <div style={{ fontSize: '0.8125rem' }}>{error}</div>
        </div>
      )}

      {/* Filter Toolbar */}
      <div
        className="glass-panel"
        style={{
          padding: '1rem',
          borderRadius: '10px',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.75rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
            <Filter size={14} />
            <span>Server-Side Filter Parameters (/api/v1/audit/events)</span>
          </div>
          <button
            type="button"
            onClick={handleResetFilters}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--color-accent)',
              cursor: 'pointer',
              fontSize: '0.75rem',
            }}
          >
            Reset Filters
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.65rem' }}>
          <div>
            <label htmlFor="audit-filter-req" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
              Request ID
            </label>
            <input
              id="audit-filter-req"
              type="text"
              value={filterRequestId}
              onChange={(e) => {
                setFilterRequestId(e.target.value);
                setOffset(0);
              }}
              placeholder="e.g. req-..."
              style={{
                width: '100%',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '0.4rem 0.65rem',
                fontSize: '0.75rem',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-mono)',
              }}
            />
          </div>

          <div>
            <label htmlFor="audit-filter-principal" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
              Principal ID
            </label>
            <input
              id="audit-filter-principal"
              type="text"
              value={filterPrincipalId}
              onChange={(e) => {
                setFilterPrincipalId(e.target.value);
                setOffset(0);
              }}
              placeholder="e.g. user-demo"
              style={{
                width: '100%',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '0.4rem 0.65rem',
                fontSize: '0.75rem',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-mono)',
              }}
            />
          </div>

          <div>
            <label htmlFor="audit-filter-decision" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
              Decision
            </label>
            <select
              id="audit-filter-decision"
              value={filterDecision}
              onChange={(e) => {
                setFilterDecision(e.target.value);
                setOffset(0);
              }}
              style={{
                width: '100%',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '0.4rem 0.65rem',
                fontSize: '0.75rem',
                color: 'var(--text-primary)',
              }}
            >
              <option value="ALL">ALL Decisions</option>
              <option value="ALLOW">ALLOW</option>
              <option value="BLOCK">BLOCK</option>
              <option value="ERROR">ERROR</option>
            </select>
          </div>

          <div>
            <label htmlFor="audit-filter-action" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
              Action
            </label>
            <input
              id="audit-filter-action"
              type="text"
              value={filterAction}
              onChange={(e) => {
                setFilterAction(e.target.value);
                setOffset(0);
              }}
              placeholder="e.g. guard_allow, tool_block"
              style={{
                width: '100%',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '0.4rem 0.65rem',
                fontSize: '0.75rem',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-mono)',
              }}
            />
          </div>
        </div>
      </div>

      {/* Audit Events Table */}
      <div className="glass-panel" style={{ overflow: 'hidden', borderRadius: '10px' }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8125rem' }}>
            <thead>
              <tr style={{ background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Timestamp</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Action</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Decision</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Risk</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Principal</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Resource / Tool</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Event Hash</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600, textAlign: 'right' }}>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && events.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
                      <Loader2 size={18} className="spinner" />
                      <span>Querying persistent audit log...</span>
                    </div>
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No audit events match current query parameters.
                  </td>
                </tr>
              ) : (
                events.map((e) => {
                  const isBlock = e.decision === 'BLOCK';
                  const isAllow = e.decision === 'ALLOW';
                  return (
                    <tr
                      key={e.event_id}
                      style={{
                        borderBottom: '1px solid var(--border-subtle)',
                        transition: 'background var(--transition-fast)',
                      }}
                    >
                      <td style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {e.timestamp ? new Date(e.timestamp * 1000).toLocaleTimeString() : '—'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span className="mono-text" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                          {e.action}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        {e.decision ? (
                          <span
                            className={`status-pill ${isAllow ? 'online' : 'offline'}`}
                            style={{
                              fontSize: '0.6875rem',
                              padding: '0.15rem 0.5rem',
                              background: isAllow ? 'var(--color-allow-bg)' : isBlock ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                              color: isAllow ? 'var(--color-allow)' : isBlock ? 'var(--color-block)' : 'var(--color-warn)',
                              borderColor: isAllow ? 'var(--color-allow-border)' : isBlock ? 'rgba(239, 68, 68, 0.4)' : 'rgba(245, 158, 11, 0.4)',
                            }}
                          >
                            {e.decision}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>—</span>
                        )}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span className="mono-text" style={{ color: 'var(--text-secondary)' }}>
                          {e.risk_score !== null && e.risk_score !== undefined ? e.risk_score.toFixed(2) : '—'}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span className="mono-text" style={{ color: 'var(--text-primary)' }}>
                          {e.principal_id || 'anonymous'}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span className="mono-text" style={{ color: 'var(--color-accent)' }}>
                          {e.tool_name || e.resource_type || '—'}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span
                          className="mono-text"
                          title={e.event_hash}
                          style={{
                            fontSize: '0.6875rem',
                            color: 'var(--text-muted)',
                            background: 'var(--bg-tertiary)',
                            padding: '0.15rem 0.4rem',
                            borderRadius: '4px',
                          }}
                        >
                          {e.event_hash.substring(0, 10)}...
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                        <button
                          type="button"
                          className="secondary-btn"
                          onClick={() => setSelectedEvent(e)}
                          title="Inspect Cryptographic Event"
                          style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                        >
                          <Eye size={13} style={{ marginRight: '0.25rem' }} />
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0.75rem 1rem',
            borderTop: '1px solid var(--border-subtle)',
            background: 'var(--bg-tertiary)',
            fontSize: '0.75rem',
            color: 'var(--text-muted)',
          }}
        >
          <div>
            Showing {events.length} of <strong style={{ color: 'var(--text-primary)' }}>{totalCount}</strong> recorded events
            (Page {currentPage} of {totalPages || 1})
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button
              type="button"
              className="secondary-btn"
              onClick={handlePrevPage}
              disabled={offset === 0 || isLoading}
              style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem' }}
            >
              <ChevronLeft size={14} />
              <span>Prev</span>
            </button>
            <button
              type="button"
              className="secondary-btn"
              onClick={handleNextPage}
              disabled={offset + limit >= totalCount || isLoading}
              style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem' }}
            >
              <span>Next</span>
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      </div>

      {/* Inspect Event Modal */}
      {selectedEvent && (
        <AuditEventDetails event={selectedEvent} onClose={() => setSelectedEvent(null)} />
      )}
    </div>
  );
};
