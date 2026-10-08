import React from 'react';
import { GuardResponse } from '../types/agentguard';
import {
  CheckCircle,
  XCircle,
  AlertTriangle,
  ArrowRight,
  ShieldAlert,
  Loader2,
  Clock,
} from 'lucide-react';

interface SecurityDecisionProps {
  guardResult: GuardResponse;
  onExecute: () => void;
  isExecuting: boolean;
  hasExecuted: boolean;
}

export const SecurityDecision: React.FC<SecurityDecisionProps> = ({
  guardResult,
  onExecute,
  isExecuting,
  hasExecuted,
}) => {
  const isAllow = guardResult.decision === 'ALLOW';
  const isBlock = guardResult.decision === 'BLOCK';
  const isError = guardResult.decision === 'ERROR';

  return (
    <div
      className={`glass-panel decision-card ${
        isAllow ? 'allow' : isBlock ? 'block' : 'error'
      }`}
      aria-live="polite"
      role="region"
      aria-label="Security Evaluation Decision"
    >
      <div className="decision-badge-row">
        <div
          className={`decision-badge ${
            isAllow ? 'allow' : isBlock ? 'block' : 'error'
          }`}
        >
          {isAllow && (
            <>
              <CheckCircle size={20} />
              <span>✓ REQUEST ALLOWED</span>
            </>
          )}
          {isBlock && (
            <>
              <XCircle size={20} />
              <span>✕ REQUEST BLOCKED</span>
            </>
          )}
          {isError && (
            <>
              <AlertTriangle size={20} />
              <span>⚠ EVALUATION ERROR</span>
            </>
          )}
        </div>

        <div className="telemetry-meta">
          <span className="meta-chip">
            <Clock size={12} />
            <span>{guardResult.latency_ms.toFixed(1)} ms</span>
          </span>
        </div>
      </div>

      <p className="decision-summary-text">
        {isAllow &&
          'The prompt passed all deterministic pre-checks and Guard LLM policy evaluation. It has been validated as safe to forward.'}
        {isBlock &&
          'AgentGuard detected potential adversarial risk. Execution has been short-circuited and the Target LLM was NOT invoked.'}
        {isError &&
          'An error occurred during evaluation. Failing closed to protect backend resources.'}
      </p>

      {/* Structured Telemetry Matrix */}
      <div className="metrics-spec-grid">
        <div className="metric-spec-item">
          <span className="metric-spec-label">Assessed Risk Score</span>
          <span
            className="metric-spec-val"
            style={{
              color:
                guardResult.risk_score > 0.5
                  ? 'var(--color-block)'
                  : 'var(--color-allow)',
            }}
          >
            {guardResult.risk_score.toFixed(2)}
          </span>
        </div>

        <div className="metric-spec-item">
          <span className="metric-spec-label">Attack Classification</span>
          <span className="metric-spec-val">
            {guardResult.attack_type || 'none'}
          </span>
        </div>

        <div className="metric-spec-item">
          <span className="metric-spec-label">Guard Model</span>
          <span className="metric-spec-val">
            {guardResult.guard_model || 'N/A'}
          </span>
        </div>

        <div className="metric-spec-item">
          <span className="metric-spec-label">Correlation Request ID</span>
          <span
            className="metric-spec-val"
            style={{ fontSize: '0.75rem' }}
            title={guardResult.request_id}
          >
            {guardResult.request_id || 'N/A'}
          </span>
        </div>
      </div>

      {/* Action / Protection State */}
      {isAllow && (
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginTop: '0.5rem',
            borderTop: '1px solid var(--border-subtle)',
            paddingTop: '1rem',
          }}
        >
          <span className="text-muted" style={{ fontSize: '0.8125rem' }}>
            {hasExecuted
              ? 'Target LLM has already responded below.'
              : 'Prompt is cleared for guarded downstream execution.'}
          </span>

          {!hasExecuted && (
            <button
              type="button"
              className="btn-primary btn-execute"
              onClick={onExecute}
              disabled={isExecuting}
              aria-busy={isExecuting}
            >
              {isExecuting ? (
                <>
                  <Loader2 size={16} className="spinner-icon" />
                  <span>Invoking Target LLM...</span>
                </>
              ) : (
                <>
                  <span>Send to Target LLM</span>
                  <ArrowRight size={16} />
                </>
              )}
            </button>
          )}
        </div>
      )}

      {isBlock && (
        <div className="alert-box danger" style={{ marginTop: '0.5rem' }}>
          <ShieldAlert size={20} style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <div style={{ fontWeight: 600, color: '#fff' }}>
              Target Protection Active
            </div>
            <div style={{ fontSize: '0.8125rem', marginTop: '2px' }}>
              The target model was completely isolated and never invoked. The prompt
              was neutralized at the security gateway boundary.
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
