import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Info } from 'lucide-react';

interface ToolRequestDetailsProps {
  toolName: string;
  argumentsObj: Record<string, any>;
  riskLevel: string | null;
  decision: string | null;
  approvalId: string | null;
  approvalStatus: string | null;
  requestId: string | null;
  executionState: string;
  result: string | null;
  latencyMs?: number | null;
  attackType?: string | null;
}

/**
 * Redacts known sensitive patterns like canary keys, master keys, tokens, or paths.
 */
function redactSensitive(val: string): string {
  if (!val) return val;
  return val
    .replace(/(bearer\s+)[a-zA-Z0-9_\-\.]+/gi, '$1[REDACTED_TOKEN]')
    .replace(/(password|secret|token|credential)["']?\s*[:=]\s*["']?[^,"'}\s]+/gi, '$1: [REDACTED]')
    .replace(/([a-zA-Z0-9_\-\.]+@)([a-zA-Z0-9_\-\.]+)/g, (_m, u, d) => `${u.substring(0, 1)}***@${d}`);
}

export const ToolRequestDetails: React.FC<ToolRequestDetailsProps> = ({
  toolName,
  argumentsObj,
  riskLevel,
  decision,
  approvalId,
  approvalStatus,
  requestId,
  executionState,
  result,
  latencyMs,
  attackType,
}) => {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className="glass-panel" style={{ padding: '0.85rem 1.25rem' }}>
      <button
        type="button"
        id="btn-toggle-tool-details"
        onClick={() => setIsOpen(!isOpen)}
        style={{
          width: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: 'transparent',
          border: 'none',
          color: 'var(--text-primary)',
          cursor: 'pointer',
          padding: 0,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Info size={16} style={{ color: 'var(--color-accent)' }} />
          <span style={{ fontSize: '0.875rem', fontWeight: 600 }}>
            Tool Request Details & Telemetry
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', color: 'var(--text-muted)' }}>
          <span style={{ fontSize: '0.75rem' }}>{isOpen ? 'Collapse' : 'Expand'}</span>
          {isOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        </div>
      </button>

      {isOpen && (
        <div
          id="tool-details-content"
          style={{
            marginTop: '1rem',
            paddingTop: '0.85rem',
            borderTop: '1px solid var(--border-subtle)',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.65rem',
            fontSize: '0.75rem',
          }}
        >
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.65rem' }}>
            <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Tool Name:</span>
              <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                {toolName || 'N/A'}
              </div>
            </div>

            <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Risk Classification:</span>
              <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                {riskLevel ? riskLevel.toUpperCase() : 'N/A'}
              </div>
            </div>

            <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Gateway Decision:</span>
              <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                {decision || 'N/A'}
              </div>
            </div>

            <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Approval State:</span>
              <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                {approvalStatus || 'N/A'}
              </div>
            </div>

            <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Execution State:</span>
              <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                {executionState}
              </div>
            </div>

            <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Execution Result:</span>
              <div style={{ fontFamily: 'var(--font-mono)', color: result ? 'var(--color-allow)' : 'var(--text-muted)', wordBreak: 'break-all' }}>
                {result ? (result.length > 70 ? result.substring(0, 67) + '...' : result) : 'null'}
              </div>
            </div>

            <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Request ID:</span>
              <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
                {requestId || 'N/A'}
              </div>
            </div>

            {approvalId && (
              <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)' }}>
                <span style={{ color: 'var(--text-muted)' }}>Approval ID:</span>
                <div style={{ fontFamily: 'var(--font-mono)', color: '#a5b4fc', wordBreak: 'break-all' }}>
                  {approvalId}
                </div>
              </div>
            )}

            {attackType && attackType !== 'none' && (
              <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)' }}>
                <span style={{ color: 'var(--text-muted)' }}>Attack Classification:</span>
                <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-block)' }}>
                  {attackType}
                </div>
              </div>
            )}

            {latencyMs !== undefined && latencyMs !== null && (
              <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)' }}>
                <span style={{ color: 'var(--text-muted)' }}>Latency:</span>
                <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                  {latencyMs.toFixed(1)} ms
                </div>
              </div>
            )}
          </div>

          <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)' }}>
            <span style={{ color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
              Canonical Arguments (Safe Representation):
            </span>
            <pre
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '0.75rem',
                color: '#cbd5e1',
                whiteSpace: 'pre-wrap',
                margin: 0,
              }}
            >
              {redactSensitive(JSON.stringify(argumentsObj, null, 2))}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
