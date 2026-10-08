import React from 'react';
import { AuditEventItem, RuntimeMetricsResponse } from '../../types/agentguard';
import { CONFIRMED_BACKEND_TOOLS } from '../agent-security/toolRegistry';
import { Wrench } from 'lucide-react';

interface ToolActionSummaryProps {
  events: AuditEventItem[];
  metrics: RuntimeMetricsResponse | null;
}

export const ToolActionSummary: React.FC<ToolActionSummaryProps> = ({ events, metrics }) => {
  // Filter audit events related to tools
  const toolAuditEvents = events.filter((e) => e.resource_type === 'tool' || Boolean(e.tool_name));

  // Runtime counters from /metrics.tools
  const totalCalls = metrics?.tools?.total_calls ?? toolAuditEvents.length;
  const allowedCalls = metrics?.tools?.allowed ?? toolAuditEvents.filter((e) => e.decision === 'ALLOW').length;
  const blockedCalls = metrics?.tools?.blocked ?? toolAuditEvents.filter((e) => e.decision === 'BLOCK').length;

  return (
    <div className="glass-panel" style={{ padding: '1.25rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Wrench size={18} color="var(--color-accent)" />
          <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Tool Security & Authorization Gate
          </h3>
        </div>
        <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', background: 'var(--bg-tertiary)', padding: '0.15rem 0.5rem', borderRadius: '4px' }}>
          Observational Only — Verified Tools
        </span>
      </div>

      <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
        Status of the 4 verified backend mock tools governed by the Tool Authorization Gate.
      </p>

      {/* Grid of 4 confirmed backend tools */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '0.75rem', marginBottom: '1rem' }}>
        {CONFIRMED_BACKEND_TOOLS.map((t) => {
          const matchingEvents = toolAuditEvents.filter((e) => e.tool_name === t.tool_name);
          const blocks = matchingEvents.filter((e) => e.decision === 'BLOCK').length;

          return (
            <div
              key={t.tool_name}
              style={{
                background: 'var(--bg-tertiary)',
                padding: '0.875rem',
                borderRadius: '8px',
                border: '1px solid var(--border-subtle)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '0.8125rem', color: 'var(--color-accent)' }}>
                  {t.tool_name}
                </span>
                <span
                  style={{
                    fontSize: '0.625rem',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    padding: '0.1rem 0.35rem',
                    borderRadius: '3px',
                    background:
                      t.risk_level === 'critical'
                        ? 'rgba(239, 68, 68, 0.2)'
                        : t.risk_level === 'high'
                        ? 'rgba(245, 158, 11, 0.2)'
                        : 'rgba(16, 185, 129, 0.2)',
                    color:
                      t.risk_level === 'critical'
                        ? 'var(--color-block)'
                        : t.risk_level === 'high'
                        ? 'var(--color-warn)'
                        : 'var(--color-allow)',
                  }}
                >
                  {t.risk_level} risk
                </span>
              </div>

              <p style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: '0.5rem', minHeight: '32px' }}>
                {t.description}
              </p>

              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.6875rem', borderTop: '1px solid var(--border-subtle)', paddingTop: '0.35rem', color: 'var(--text-secondary)' }}>
                <span>Audited Events: <strong>{matchingEvents.length}</strong></span>
                {blocks > 0 && (
                  <span style={{ color: 'var(--color-block)' }}>
                    Blocked: <strong>{blocks}</strong>
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      <div style={{ display: 'flex', gap: '1rem', background: 'var(--bg-tertiary)', padding: '0.75rem 1rem', borderRadius: '6px', fontSize: '0.75rem' }}>
        <div>Total Tool Requests: <strong style={{ color: 'var(--text-primary)' }}>{totalCalls}</strong></div>
        <div>Authorized: <strong style={{ color: 'var(--color-allow)' }}>{allowedCalls}</strong></div>
        <div>Blocked by Guard: <strong style={{ color: 'var(--color-block)' }}>{blockedCalls}</strong></div>
      </div>
    </div>
  );
};
