import React, { useState } from 'react';
import {
  Eye,
  Briefcase,
  ChevronLeft,
  ChevronRight,
  RotateCw,
  SlidersHorizontal,
} from 'lucide-react';
import { AuditEventItem } from '../../types/agentguard';

interface SecurityEventStreamProps {
  events: AuditEventItem[];
  totalEvents: number;
  limit: number;
  offset: number;
  isLoading: boolean;
  onPageChange: (newOffset: number) => void;
  onFilterChange: (filters: {
    requestId?: string;
    principalId?: string;
    action?: string;
    decision?: string;
    resourceType?: string;
  }) => void;
  onInspectEvent: (event: AuditEventItem) => void;
  onAddToInvestigation: (event: AuditEventItem) => void;
  onRefresh: () => void;
}

export const SecurityEventStream: React.FC<SecurityEventStreamProps> = ({
  events,
  totalEvents,
  limit,
  offset,
  isLoading,
  onPageChange,
  onFilterChange,
  onInspectEvent,
  onAddToInvestigation,
  onRefresh,
}) => {
  const [filterRequestId, setFilterRequestId] = useState('');
  const [filterPrincipalId, setFilterPrincipalId] = useState('');
  const [filterAction, setFilterAction] = useState('');
  const [filterDecision, setFilterDecision] = useState('');
  const [activePreset, setActivePreset] = useState<'ALL' | 'BLOCKS' | 'AUTH_FAIL' | 'POLICIES' | 'TOOLS'>('ALL');

  const applyFilters = (overrides: Partial<{
    requestId: string;
    principalId: string;
    action: string;
    decision: string;
    resourceType: string;
  }> = {}) => {
    const filters = {
      requestId: overrides.requestId !== undefined ? overrides.requestId : filterRequestId,
      principalId: overrides.principalId !== undefined ? overrides.principalId : filterPrincipalId,
      action: overrides.action !== undefined ? overrides.action : filterAction,
      decision: overrides.decision !== undefined ? overrides.decision : filterDecision,
    };
    onFilterChange(filters);
  };

  const handlePreset = (preset: 'ALL' | 'BLOCKS' | 'AUTH_FAIL' | 'POLICIES' | 'TOOLS') => {
    setActivePreset(preset);
    if (preset === 'ALL') {
      setFilterAction('');
      setFilterDecision('');
      applyFilters({ action: '', decision: '' });
    } else if (preset === 'BLOCKS') {
      setFilterDecision('BLOCK');
      applyFilters({ decision: 'BLOCK', action: '' });
    } else if (preset === 'AUTH_FAIL') {
      setFilterAction('auth_failure');
      setFilterDecision('');
      applyFilters({ action: 'auth_failure', decision: '' });
    } else if (preset === 'POLICIES') {
      setFilterAction('policy_denial');
      setFilterDecision('');
      applyFilters({ action: 'policy_denial', decision: '' });
    } else if (preset === 'TOOLS') {
      setFilterAction('tool_execution');
      setFilterDecision('');
      applyFilters({ action: 'tool_execution', decision: '' });
    }
  };

  const handleResetFilters = () => {
    setFilterRequestId('');
    setFilterPrincipalId('');
    setFilterAction('');
    setFilterDecision('');
    setActivePreset('ALL');
    onFilterChange({});
  };

  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.ceil(totalEvents / limit) || 1;

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
      {/* Stream Header */}
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
              background: 'rgba(99, 102, 241, 0.15)',
              color: 'var(--color-accent)',
            }}
          >
            <SlidersHorizontal size={18} />
          </div>
          <div>
            <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
              Live Security Event Stream
            </h3>
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
              Authoritative Backend Audit Feed ({totalEvents} total logged events)
            </span>
          </div>
        </div>

        {/* Quick Presets & Refresh */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', gap: '0.25rem' }} role="tablist" aria-label="Event Stream Presets">
            <button
              type="button"
              className={`secondary-btn ${activePreset === 'ALL' ? 'active' : ''}`}
              onClick={() => handlePreset('ALL')}
              style={{ padding: '0.2rem 0.5rem', fontSize: '0.6875rem', borderRadius: '5px' }}
            >
              All
            </button>
            <button
              type="button"
              className={`secondary-btn ${activePreset === 'BLOCKS' ? 'active' : ''}`}
              onClick={() => handlePreset('BLOCKS')}
              style={{
                padding: '0.2rem 0.5rem',
                fontSize: '0.6875rem',
                borderRadius: '5px',
                color: activePreset === 'BLOCKS' ? 'var(--color-block)' : 'inherit',
              }}
            >
              Blocks
            </button>
            <button
              type="button"
              className={`secondary-btn ${activePreset === 'AUTH_FAIL' ? 'active' : ''}`}
              onClick={() => handlePreset('AUTH_FAIL')}
              style={{ padding: '0.2rem 0.5rem', fontSize: '0.6875rem', borderRadius: '5px' }}
            >
              Auth Failures
            </button>
            <button
              type="button"
              className={`secondary-btn ${activePreset === 'POLICIES' ? 'active' : ''}`}
              onClick={() => handlePreset('POLICIES')}
              style={{ padding: '0.2rem 0.5rem', fontSize: '0.6875rem', borderRadius: '5px' }}
            >
              Policy Denials
            </button>
          </div>

          <button
            type="button"
            className="secondary-btn"
            onClick={onRefresh}
            disabled={isLoading}
            title="Refresh audit event stream from backend"
            style={{ padding: '0.25rem 0.5rem', fontSize: '0.6875rem', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}
          >
            <RotateCw size={12} className={isLoading ? 'spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div
        style={{
          padding: '0.75rem 1.25rem',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
          gap: '0.65rem',
          background: 'rgba(15, 23, 42, 0.3)',
          alignItems: 'flex-end',
        }}
      >
        <div>
          <label htmlFor="stream-req-id" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>
            Request ID
          </label>
          <input
            id="stream-req-id"
            type="text"
            value={filterRequestId}
            onChange={(e) => {
              setFilterRequestId(e.target.value);
              applyFilters({ requestId: e.target.value });
            }}
            placeholder="e.g. req-abc-123"
            style={{
              width: '100%',
              background: 'var(--bg-input)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '5px',
              padding: '0.35rem 0.6rem',
              fontSize: '0.75rem',
              color: 'var(--text-primary)',
            }}
          />
        </div>

        <div>
          <label htmlFor="stream-principal-id" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>
            Principal ID
          </label>
          <input
            id="stream-principal-id"
            type="text"
            value={filterPrincipalId}
            onChange={(e) => {
              setFilterPrincipalId(e.target.value);
              applyFilters({ principalId: e.target.value });
            }}
            placeholder="e.g. user-demo"
            style={{
              width: '100%',
              background: 'var(--bg-input)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '5px',
              padding: '0.35rem 0.6rem',
              fontSize: '0.75rem',
              color: 'var(--text-primary)',
            }}
          />
        </div>

        <div>
          <label htmlFor="stream-action" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>
            Action
          </label>
          <input
            id="stream-action"
            type="text"
            value={filterAction}
            onChange={(e) => {
              setFilterAction(e.target.value);
              applyFilters({ action: e.target.value });
            }}
            placeholder="e.g. guard_block"
            style={{
              width: '100%',
              background: 'var(--bg-input)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '5px',
              padding: '0.35rem 0.6rem',
              fontSize: '0.75rem',
              color: 'var(--text-primary)',
            }}
          />
        </div>

        <div>
          <label htmlFor="stream-decision" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>
            Decision
          </label>
          <select
            id="stream-decision"
            value={filterDecision}
            onChange={(e) => {
              setFilterDecision(e.target.value);
              applyFilters({ decision: e.target.value });
            }}
            style={{
              width: '100%',
              background: 'var(--bg-input)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '5px',
              padding: '0.35rem 0.6rem',
              fontSize: '0.75rem',
              color: 'var(--text-primary)',
            }}
          >
            <option value="">All Decisions</option>
            <option value="ALLOW">ALLOW</option>
            <option value="BLOCK">BLOCK</option>
            <option value="ERROR">ERROR</option>
          </select>
        </div>

        <div>
          <button
            type="button"
            className="secondary-btn"
            onClick={handleResetFilters}
            style={{ width: '100%', padding: '0.35rem', fontSize: '0.75rem', height: '31px' }}
          >
            Reset Filters
          </button>
        </div>
      </div>

      {/* Events Table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8125rem' }}>
          <thead>
            <tr style={{ background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
              <th style={{ padding: '0.65rem 1rem', fontWeight: 600 }}>Timestamp</th>
              <th style={{ padding: '0.65rem 1rem', fontWeight: 600 }}>Action</th>
              <th style={{ padding: '0.65rem 1rem', fontWeight: 600 }}>Decision</th>
              <th style={{ padding: '0.65rem 1rem', fontWeight: 600 }}>Principal</th>
              <th style={{ padding: '0.65rem 1rem', fontWeight: 600 }}>Tenant</th>
              <th style={{ padding: '0.65rem 1rem', fontWeight: 600 }}>Resource / Tool</th>
              <th style={{ padding: '0.65rem 1rem', fontWeight: 600 }}>SHA-256 Hash</th>
              <th style={{ padding: '0.65rem 1rem', fontWeight: 600, textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {events.length === 0 ? (
              <tr>
                <td colSpan={8} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No audit events found matching current query parameters.
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
                    <td style={{ padding: '0.65rem 1rem', color: 'var(--text-muted)', whiteSpace: 'nowrap', fontSize: '0.75rem' }}>
                      {e.timestamp ? new Date(e.timestamp * 1000).toLocaleTimeString() : '—'}
                    </td>
                    <td style={{ padding: '0.65rem 1rem' }}>
                      <span className="mono-text" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                        {e.action}
                      </span>
                    </td>
                    <td style={{ padding: '0.65rem 1rem' }}>
                      {e.decision ? (
                        <span
                          className={`status-pill ${isAllow ? 'online' : 'offline'}`}
                          style={{
                            fontSize: '0.625rem',
                            padding: '0.1rem 0.45rem',
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
                    <td style={{ padding: '0.65rem 1rem' }}>
                      <span className="mono-text" style={{ fontSize: '0.75rem', color: 'var(--text-primary)' }}>
                        {e.principal_id || 'anonymous'}
                      </span>
                    </td>
                    <td style={{ padding: '0.65rem 1rem' }}>
                      <span className="mono-text" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {e.tenant_id || 'default'}
                      </span>
                    </td>
                    <td style={{ padding: '0.65rem 1rem' }}>
                      <span className="mono-text" style={{ fontSize: '0.75rem', color: 'var(--color-accent)' }}>
                        {e.tool_name || e.resource_type || '—'}
                      </span>
                    </td>
                    <td style={{ padding: '0.65rem 1rem' }}>
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
                        {e.event_hash ? `${e.event_hash.substring(0, 10)}...` : '—'}
                      </span>
                    </td>
                    <td style={{ padding: '0.65rem 1rem', textAlign: 'right', whiteSpace: 'nowrap' }}>
                      <div style={{ display: 'inline-flex', gap: '0.35rem' }}>
                        <button
                          type="button"
                          className="secondary-btn"
                          data-testid={`inspect-event-${e.event_id}`}
                          onClick={() => onInspectEvent(e)}
                          title="Inspect cryptographic event metadata"
                          style={{ padding: '0.2rem 0.45rem', fontSize: '0.6875rem' }}
                        >
                          <Eye size={12} style={{ marginRight: '0.25rem' }} />
                          Inspect
                        </button>
                        <button
                          type="button"
                          className="secondary-btn"
                          data-testid={`add-investigation-${e.event_id}`}
                          onClick={() => onAddToInvestigation(e)}
                          title="Add event to session Incident Workspace"
                          style={{
                            padding: '0.2rem 0.45rem',
                            fontSize: '0.6875rem',
                            color: 'var(--color-accent)',
                            borderColor: 'rgba(99, 102, 241, 0.3)',
                          }}
                        >
                          <Briefcase size={12} style={{ marginRight: '0.25rem' }} />
                          Investigate
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

      {/* Pagination Bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0.75rem 1.25rem',
          borderTop: '1px solid var(--border-subtle)',
          background: 'var(--bg-tertiary)',
          fontSize: '0.75rem',
          color: 'var(--text-muted)',
        }}
      >
        <div>
          Showing {events.length} of <strong style={{ color: 'var(--text-primary)' }}>{totalEvents}</strong> recorded events
          (Page {currentPage} of {totalPages})
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <button
            type="button"
            className="secondary-btn"
            onClick={() => onPageChange(Math.max(0, offset - limit))}
            disabled={offset === 0 || isLoading}
            style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem' }}
          >
            <ChevronLeft size={14} />
            <span>Prev</span>
          </button>
          <button
            type="button"
            className="secondary-btn"
            onClick={() => onPageChange(offset + limit)}
            disabled={offset + limit >= totalEvents || isLoading}
            style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem' }}
          >
            <span>Next</span>
            <ChevronRight size={14} />
          </button>
        </div>
      </div>
    </div>
  );
};
