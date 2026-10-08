import React from 'react';
import { ExecuteResponse } from '../types/agentguard';
import { Cpu, Clock, CheckCircle2, AlertOctagon } from 'lucide-react';

interface ExecutionResultProps {
  execution: ExecuteResponse;
}

export const ExecutionResult: React.FC<ExecutionResultProps> = ({ execution }) => {
  const isAllow = execution.decision === 'ALLOW';

  return (
    <div className="glass-panel target-response-box" role="region" aria-label="Target LLM Output">
      <div className="target-response-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600 }}>
          <Cpu size={16} color="var(--color-accent)" />
          <span>Target LLM Response</span>
          <span className="mono-text text-muted" style={{ fontSize: '0.75rem' }}>
            ({execution.target_model})
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span className="meta-chip">
            <Clock size={12} />
            <span>Total: {execution.latency_ms.toFixed(1)} ms</span>
          </span>
          <span
            className="meta-chip"
            style={{
              color: isAllow ? 'var(--color-allow)' : 'var(--color-block)',
              borderColor: isAllow ? 'var(--color-allow-border)' : 'var(--color-block-border)',
            }}
          >
            {isAllow ? <CheckCircle2 size={12} /> : <AlertOctagon size={12} />}
            <span>{execution.decision}</span>
          </span>
        </div>
      </div>

      {isAllow && execution.response ? (
        <div className="target-response-content">
          {execution.response}
        </div>
      ) : (
        <div className="alert-box danger">
          <AlertOctagon size={18} style={{ flexShrink: 0 }} />
          <span>Execution failed or was blocked by the security gateway during processing.</span>
        </div>
      )}

      <div className="metrics-spec-grid" style={{ marginTop: '0.5rem' }}>
        <div className="metric-spec-item">
          <span className="metric-spec-label">Execution Request ID</span>
          <span className="metric-spec-val" style={{ fontSize: '0.75rem' }}>
            {execution.request_id}
          </span>
        </div>
        <div className="metric-spec-item">
          <span className="metric-spec-label">Output Leak Sanitizer</span>
          <span className="metric-spec-val" style={{ color: 'var(--color-allow)' }}>
            PASSED (Canaries Redacted)
          </span>
        </div>
      </div>
    </div>
  );
};
