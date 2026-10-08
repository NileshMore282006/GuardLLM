import React, { useState } from 'react';
import { Briefcase, Trash2, Copy, Check, X } from 'lucide-react';
import {
  IncidentInvestigation,
  AuditEventItem,
} from '../../types/agentguard';
import { PipelineTimeline } from './PipelineTimeline';

interface IncidentWorkspaceProps {
  investigation: IncidentInvestigation;
  selectedEventsData: AuditEventItem[];
  onUpdateInvestigation: (updated: IncidentInvestigation) => void;
  onRemoveEvent: (eventId: string) => void;
  onClearWorkspace: () => void;
  onInspectEvent: (event: AuditEventItem) => void;
}

import { redactSensitiveData } from '../../utils/redaction';

export const IncidentWorkspace: React.FC<IncidentWorkspaceProps> = ({
  investigation,
  selectedEventsData,
  onUpdateInvestigation,
  onRemoveEvent,
  onClearWorkspace,
  onInspectEvent,
}) => {
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'DETAILS' | 'TIMELINE' | 'EXPORT'>('DETAILS');

  const handleTitleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onUpdateInvestigation({
      ...investigation,
      title: e.target.value,
    });
  };

  const handleNotesChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    onUpdateInvestigation({
      ...investigation,
      notes: e.target.value,
    });
  };

  const handleStatusChange = (status: 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'DISMISSED') => {
    onUpdateInvestigation({
      ...investigation,
      status,
    });
  };

  const generateExportSummary = () => {
    const summary = {
      export_schema_version: '1.0',
      export_label: 'Sanitized investigation bundle',
      disclaimer: 'Local investigation — not persisted by AgentGuard',
      exported_at: new Date().toISOString(),
      investigation_id: investigation.id,
      title: redactSensitiveData(investigation.title),
      status: investigation.status,
      storage_tier: 'SESSION_MEMORY_ONLY',
      correlation_keys: {
        event_ids: investigation.selectedEventIds,
        request_ids: investigation.correlatedRequestIds,
        principal_ids: investigation.correlatedPrincipals,
        tenant_ids: investigation.correlatedTenants,
        tool_names: investigation.correlatedTools,
        approval_ids: investigation.correlatedApprovals,
        policy_ids: investigation.correlatedPolicies,
      },
      operator_notes: redactSensitiveData(investigation.notes),
      events: selectedEventsData.map((e) => ({
        event_id: e.event_id,
        timestamp: e.timestamp,
        request_id: e.request_id || null,
        action: e.action,
        decision: e.decision || null,
        risk_score: e.risk_score || null,
        attack_type: e.attack_type || null,
        principal_id: e.principal_id || null,
        tenant_id: e.tenant_id || null,
        tool_name: e.tool_name || null,
        event_hash: e.event_hash,
        previous_event_hash: e.previous_event_hash,
      })),
    };
    return JSON.stringify(summary, null, 2);
  };

  const handleCopySummary = () => {
    navigator.clipboard.writeText(generateExportSummary());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const primaryEvent = selectedEventsData[0] || null;

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
      {/* Header with Session-Only Disclaimer */}
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
            <Briefcase size={18} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                Incident Investigation Workspace
              </h3>
              <span
                className="status-pill"
                style={{
                  fontSize: '0.625rem',
                  padding: '0.1rem 0.45rem',
                  background: 'rgba(245, 158, 11, 0.15)',
                  color: 'var(--color-warn)',
                  borderColor: 'rgba(245, 158, 11, 0.4)',
                }}
              >
                Local investigation — not persisted by AgentGuard
              </span>
            </div>
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
              Session-only correlation plane • Zero browser storage persistence
            </span>
          </div>
        </div>

        {/* Status & Clear Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          <select
            value={investigation.status}
            onChange={(e) => handleStatusChange(e.target.value as any)}
            aria-label="Investigation status"
            style={{
              padding: '0.25rem 0.5rem',
              fontSize: '0.75rem',
              borderRadius: '6px',
              background: 'var(--bg-input)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text-primary)',
            }}
          >
            <option value="OPEN">Status: OPEN</option>
            <option value="INVESTIGATING">Status: INVESTIGATING</option>
            <option value="RESOLVED">Status: RESOLVED</option>
            <option value="DISMISSED">Status: DISMISSED</option>
          </select>

          <button
            type="button"
            className="secondary-btn"
            data-testid="clear-investigation-btn"
            onClick={onClearWorkspace}
            title="Purge current local investigation from memory"
            style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem', color: 'var(--color-block)' }}
          >
            <Trash2 size={13} style={{ marginRight: '0.25rem' }} />
            Clear
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div
        style={{
          display: 'flex',
          borderBottom: '1px solid var(--border-subtle)',
          background: 'rgba(15, 23, 42, 0.4)',
          padding: '0 1.25rem',
          gap: '1rem',
        }}
        role="tablist"
      >
        <button
          type="button"
          className={`tab-btn ${activeTab === 'DETAILS' ? 'active' : ''}`}
          onClick={() => setActiveTab('DETAILS')}
          style={{
            padding: '0.65rem 0',
            fontSize: '0.8125rem',
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'DETAILS' ? '2px solid var(--color-accent)' : '2px solid transparent',
            color: activeTab === 'DETAILS' ? 'var(--text-primary)' : 'var(--text-muted)',
            cursor: 'pointer',
            fontWeight: activeTab === 'DETAILS' ? 600 : 400,
          }}
        >
          Investigation Summary ({selectedEventsData.length} Events)
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'TIMELINE' ? 'active' : ''}`}
          onClick={() => setActiveTab('TIMELINE')}
          style={{
            padding: '0.65rem 0',
            fontSize: '0.8125rem',
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'TIMELINE' ? '2px solid var(--color-accent)' : '2px solid transparent',
            color: activeTab === 'TIMELINE' ? 'var(--text-primary)' : 'var(--text-muted)',
            cursor: 'pointer',
            fontWeight: activeTab === 'TIMELINE' ? 600 : 400,
          }}
        >
          Correlated Pipeline Trajectory
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'EXPORT' ? 'active' : ''}`}
          onClick={() => setActiveTab('EXPORT')}
          style={{
            padding: '0.65rem 0',
            fontSize: '0.8125rem',
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'EXPORT' ? '2px solid var(--color-accent)' : '2px solid transparent',
            color: activeTab === 'EXPORT' ? 'var(--text-primary)' : 'var(--text-muted)',
            cursor: 'pointer',
            fontWeight: activeTab === 'EXPORT' ? 600 : 400,
          }}
        >
          Export Sanitized Package
        </button>
      </div>

      {/* Tab Content */}
      <div style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {activeTab === 'DETAILS' && (
          <>
            {/* Title & Notes Inputs */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
              <div>
                <label
                  htmlFor="inv-title"
                  style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}
                >
                  Investigation Subject / Title
                </label>
                <input
                  id="inv-title"
                  type="text"
                  value={investigation.title}
                  onChange={handleTitleChange}
                  placeholder="e.g. Prompt Injection & Unauthorized Tool Probing"
                  style={{
                    width: '100%',
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    padding: '0.45rem 0.75rem',
                    fontSize: '0.8125rem',
                    color: 'var(--text-primary)',
                  }}
                />
              </div>

              <div>
                <label
                  htmlFor="inv-notes"
                  style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}
                >
                  Operator Notes (In-Memory Session Only)
                </label>
                <textarea
                  id="inv-notes"
                  value={investigation.notes}
                  onChange={handleNotesChange}
                  rows={2}
                  placeholder="Add operational findings, containment steps taken, or threat context..."
                  style={{
                    width: '100%',
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    padding: '0.45rem 0.75rem',
                    fontSize: '0.8125rem',
                    color: 'var(--text-primary)',
                    resize: 'vertical',
                  }}
                />
              </div>
            </div>

            {/* Correlated Entities Summary Bar */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                gap: '0.65rem',
                background: 'var(--bg-tertiary)',
                padding: '0.75rem 1rem',
                borderRadius: '8px',
                border: '1px solid var(--border-subtle)',
                fontSize: '0.75rem',
              }}
            >
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block' }}>Correlated Requests:</span>
                <span className="mono-text" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                  {investigation.correlatedRequestIds.length > 0
                    ? investigation.correlatedRequestIds.join(', ')
                    : 'None'}
                </span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block' }}>Principals:</span>
                <span className="mono-text" style={{ color: 'var(--text-secondary)' }}>
                  {investigation.correlatedPrincipals.length > 0
                    ? investigation.correlatedPrincipals.join(', ')
                    : 'None'}
                </span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block' }}>Tenants:</span>
                <span className="mono-text" style={{ color: 'var(--color-accent)' }}>
                  {investigation.correlatedTenants.length > 0
                    ? investigation.correlatedTenants.join(', ')
                    : 'default'}
                </span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block' }}>Tools Involved:</span>
                <span className="mono-text" style={{ color: 'var(--color-warn)' }}>
                  {investigation.correlatedTools.length > 0
                    ? investigation.correlatedTools.join(', ')
                    : 'None'}
                </span>
              </div>
            </div>

            {/* Selected Events Table */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Selected Investigation Events ({selectedEventsData.length})
                </span>
                <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                  Events captured from authoritative audit stream
                </span>
              </div>

              {selectedEventsData.length === 0 ? (
                <div
                  style={{
                    padding: '2rem',
                    textAlign: 'center',
                    color: 'var(--text-muted)',
                    background: 'var(--bg-tertiary)',
                    borderRadius: '8px',
                    fontSize: '0.8125rem',
                  }}
                >
                  No events added to this workspace yet. Select "Investigate" on an alert or audit event to add it.
                </div>
              ) : (
                <div style={{ overflowX: 'auto', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8125rem' }}>
                    <thead>
                      <tr style={{ background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                        <th style={{ padding: '0.5rem 0.75rem', fontWeight: 600 }}>Event ID</th>
                        <th style={{ padding: '0.5rem 0.75rem', fontWeight: 600 }}>Action</th>
                        <th style={{ padding: '0.5rem 0.75rem', fontWeight: 600 }}>Decision</th>
                        <th style={{ padding: '0.5rem 0.75rem', fontWeight: 600 }}>Risk</th>
                        <th style={{ padding: '0.5rem 0.75rem', fontWeight: 600 }}>Principal</th>
                        <th style={{ padding: '0.5rem 0.75rem', fontWeight: 600 }}>Request ID</th>
                        <th style={{ padding: '0.5rem 0.75rem', fontWeight: 600, textAlign: 'right' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selectedEventsData.map((ev) => (
                        <tr key={ev.event_id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                          <td style={{ padding: '0.5rem 0.75rem' }}>
                            <span className="mono-text" style={{ fontSize: '0.75rem', color: 'var(--text-primary)' }}>
                              {ev.event_id}
                            </span>
                          </td>
                          <td style={{ padding: '0.5rem 0.75rem' }}>
                            <span className="mono-text" style={{ fontWeight: 600 }}>
                              {ev.action}
                            </span>
                          </td>
                          <td style={{ padding: '0.5rem 0.75rem' }}>
                            <span
                              className="status-pill"
                              style={{
                                fontSize: '0.625rem',
                                padding: '0.1rem 0.4rem',
                                background: ev.decision === 'BLOCK' ? 'rgba(239, 68, 68, 0.15)' : 'var(--color-allow-bg)',
                                color: ev.decision === 'BLOCK' ? 'var(--color-block)' : 'var(--color-allow)',
                              }}
                            >
                              {ev.decision}
                            </span>
                          </td>
                          <td style={{ padding: '0.5rem 0.75rem' }}>
                            <span className="mono-text" style={{ color: 'var(--text-secondary)' }}>
                              {ev.risk_score !== null && ev.risk_score !== undefined ? ev.risk_score.toFixed(2) : '—'}
                            </span>
                          </td>
                          <td style={{ padding: '0.5rem 0.75rem' }}>
                            <span className="mono-text" style={{ color: 'var(--text-muted)' }}>
                              {ev.principal_id || 'anonymous'}
                            </span>
                          </td>
                          <td style={{ padding: '0.5rem 0.75rem' }}>
                            <span className="mono-text" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                              {ev.request_id ? `${ev.request_id.substring(0, 10)}...` : '—'}
                            </span>
                          </td>
                          <td style={{ padding: '0.5rem 0.75rem', textAlign: 'right' }}>
                            <div style={{ display: 'inline-flex', gap: '0.35rem' }}>
                              <button
                                type="button"
                                className="secondary-btn"
                                onClick={() => onInspectEvent(ev)}
                                title="Inspect audit event drawer"
                                style={{ padding: '0.15rem 0.45rem', fontSize: '0.6875rem' }}
                              >
                                View
                              </button>
                              <button
                                type="button"
                                className="secondary-btn"
                                onClick={() => onRemoveEvent(ev.event_id)}
                                title="Remove from workspace"
                                style={{ padding: '0.15rem 0.45rem', fontSize: '0.6875rem', color: 'var(--color-block)' }}
                              >
                                <X size={12} />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </>
        )}

        {activeTab === 'TIMELINE' && (
          <PipelineTimeline
            selectedEvent={primaryEvent}
            allCorrelatedEvents={selectedEventsData}
          />
        )}

        {activeTab === 'EXPORT' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                Sanitized investigation bundle — Local investigation — not persisted by AgentGuard backend
              </span>
              <button
                type="button"
                className="secondary-btn"
                onClick={handleCopySummary}
                style={{
                  padding: '0.35rem 0.75rem',
                  fontSize: '0.75rem',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                }}
              >
                {copied ? <Check size={13} style={{ color: 'var(--color-allow)' }} /> : <Copy size={13} />}
                <span>{copied ? 'Copied!' : 'Copy Summary'}</span>
              </button>
            </div>

            <pre
              className="mono-text"
              style={{
                background: 'var(--bg-tertiary)',
                padding: '1rem',
                borderRadius: '8px',
                border: '1px solid var(--border-subtle)',
                fontSize: '0.75rem',
                color: 'var(--text-primary)',
                maxHeight: '320px',
                overflowY: 'auto',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
              }}
            >
              {generateExportSummary()}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};
