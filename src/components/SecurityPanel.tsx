import React, { useState } from 'react';
import {
  ChatTurn,
  SecurityFlowState,
  GuardDecision,
} from '../types/agentguard';
import {
  Shield,
  Layers,
  KeyRound,
} from 'lucide-react';

interface SecurityPanelProps {
  latestTurn: ChatTurn | null;
  turns: ChatTurn[];
  flowState: SecurityFlowState;
  developerToken: string;
  setDeveloperToken: (token: string) => void;
}

export const SecurityPanel: React.FC<SecurityPanelProps> = ({
  latestTurn,
  turns,
  flowState,
  developerToken,
  setDeveloperToken,
}) => {
  const [showAuthSection, setShowAuthSection] = useState(false);

  const decision: GuardDecision = latestTurn?.security.decision || 'ALLOW';
  const isAllow = decision === 'ALLOW' && latestTurn !== null;
  const isBlock = decision === 'BLOCK';
  const isError = decision === 'ERROR';

  const riskScoreText =
    latestTurn?.security.risk_score !== null && latestTurn?.security.risk_score !== undefined
      ? latestTurn.security.risk_score.toFixed(2)
      : 'N/A';

  const targetStatus = !latestTurn
    ? 'IDLE'
    : isBlock
    ? 'NOT INVOKED (Protected)'
    : isError
    ? 'NOT INVOKED (Fail-Closed)'
    : 'Invoked & Sanitized';

  return (
    <aside className="security-panel-sidebar glass-panel" aria-label="Conversation Security Telemetry">
      <div className="sidebar-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Shield size={18} color="var(--color-accent)" />
          <h2 className="sidebar-title">Conversation Security</h2>
        </div>
        <span className="mono-text text-muted" style={{ fontSize: '0.75rem' }}>
          Turns: {turns.length}
        </span>
      </div>

      <div className="security-context-notice">
        <span>🛡 AgentGuard evaluates conversation context, not only the latest message.</span>
      </div>

      {/* 1. Latest Decision Banner */}
      <div className="latest-decision-card glass-panel">
        <div className="decision-header-row">
          <span className="telemetry-label">Current Guard State</span>
          <span className={`status-indicator ${isBlock ? 'block' : isAllow ? 'allow' : 'neutral'}`}>
            <span className="status-pulse-dot" />
            <span>
              {flowState === 'ANALYZING'
                ? 'ANALYZING...'
                : latestTurn
                ? latestTurn.security.decision
                : 'IDLE'}
            </span>
          </span>
        </div>

        <div className="telemetry-grid">
          <div className="telemetry-item">
            <span className="telemetry-item-label">Risk Score</span>
            <span
              className="telemetry-item-val"
              style={{
                color:
                  latestTurn && latestTurn.security.risk_score !== null && latestTurn.security.risk_score > 0.5
                    ? 'var(--color-block)'
                    : 'var(--color-allow)',
              }}
            >
              {riskScoreText}
            </span>
          </div>

          <div className="telemetry-item">
            <span className="telemetry-item-label">Attack Type</span>
            <span className="telemetry-item-val">
              {latestTurn?.security.attack_type || 'none'}
            </span>
          </div>

          <div className="telemetry-item">
            <span className="telemetry-item-label">Target Model</span>
            <span className="telemetry-item-val">
              {isBlock ? 'NOT INVOKED' : latestTurn?.security.target_model || 'N/A'}
            </span>
          </div>

          <div className="telemetry-item">
            <span className="telemetry-item-label">Turn Latency</span>
            <span className="telemetry-item-val">
              {latestTurn ? `${latestTurn.security.latency_ms.toFixed(1)} ms` : 'N/A'}
            </span>
          </div>

          <div className="telemetry-item full-row">
            <span className="telemetry-item-label">Target Invocation</span>
            <span
              className="telemetry-item-val mono-text"
              style={{
                color: isBlock
                  ? 'var(--color-block)'
                  : isAllow
                  ? 'var(--color-allow)'
                  : 'var(--text-secondary)',
              }}
            >
              {targetStatus}
            </span>
          </div>

          <div className="telemetry-item full-row">
            <span className="telemetry-item-label">Request ID</span>
            <span
              className="telemetry-item-val mono-text"
              style={{ fontSize: '0.75rem', wordBreak: 'break-all' }}
              title={latestTurn?.security.request_id || 'N/A'}
            >
              {latestTurn?.security.request_id || 'N/A'}
            </span>
          </div>
        </div>
      </div>

      {/* 2. Conceptual Security Pipeline Flow */}
      <div className="pipeline-flow-card glass-panel">
        <div className="pipeline-flow-title">
          <Layers size={14} />
          <span>Security Pipeline Architecture</span>
        </div>

        <div className="pipeline-steps-stack">
          <div className={`pipeline-step ${turns.length > 0 ? 'active' : ''}`}>
            <div className="pipeline-step-dot" />
            <div className="pipeline-step-text">
              <span className="step-name">1. Context Assembly</span>
              <span className="step-desc">Canonical user/assistant turn sequence</span>
            </div>
          </div>

          <div className={`pipeline-step ${flowState !== 'IDLE' ? 'active' : ''}`}>
            <div className="pipeline-step-dot" />
            <div className="pipeline-step-text">
              <span className="step-name">2. AgentGuard Perimeter</span>
              <span className="step-desc">Pre-checks & context-aware Guard LLM</span>
            </div>
          </div>

          <div className={`pipeline-step ${isBlock ? 'blocked' : isAllow ? 'allowed' : ''}`}>
            <div className={`pipeline-step-dot ${isBlock ? 'blocked-dot' : isAllow ? 'allowed-dot' : ''}`} />
            <div className="pipeline-step-text">
              <span className="step-name">3. Security Decision</span>
              <span className="step-desc">
                {isBlock ? 'BLOCK — Target isolated' : isAllow ? 'ALLOW — Safe to forward' : 'Policy gate'}
              </span>
            </div>
          </div>

          <div className={`pipeline-step ${isAllow ? 'active' : isBlock ? 'disabled' : ''}`}>
            <div className="pipeline-step-dot" />
            <div className="pipeline-step-text">
              <span className="step-name">4. Target LLM Execution</span>
              <span className="step-desc">
                {isBlock ? 'Target NOT invoked' : isAllow ? 'Inference completed' : 'Downstream model'}
              </span>
            </div>
          </div>

          <div className={`pipeline-step ${isAllow ? 'active' : isBlock ? 'disabled' : ''}`}>
            <div className="pipeline-step-dot" />
            <div className="pipeline-step-text">
              <span className="step-name">5. Output Leak Sanitizer</span>
              <span className="step-desc">Redacts protected canary tokens</span>
            </div>
          </div>
        </div>
      </div>

      {/* 3. Turn History Matrix */}
      <div className="turns-matrix-card glass-panel">
        <span className="sidebar-section-title">Session Turn Timeline</span>
        {turns.length === 0 ? (
          <div className="empty-turns-text text-muted">
            No turns evaluated yet. Send a message to start conversation.
          </div>
        ) : (
          <div className="turns-timeline-list">
            {turns.map((t) => (
              <div key={t.id} className="turn-timeline-item">
                <span className="turn-timeline-num">Turn {t.turnNumber}</span>
                <span
                  className={`turn-timeline-decision ${
                    t.security.decision === 'ALLOW' ? 'allow' : 'block'
                  }`}
                >
                  {t.security.decision}
                </span>
                <span className="turn-timeline-risk">
                  Risk: {t.security.risk_score !== null ? t.security.risk_score.toFixed(2) : '0.00'}
                </span>
                <span className="turn-timeline-time text-muted">{t.timestamp}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 4. Development Authentication (Memory-Only) */}
      <div className="dev-auth-section">
        <button
          type="button"
          className="btn-toggle-auth"
          onClick={() => setShowAuthSection(!showAuthSection)}
        >
          <KeyRound size={13} />
          <span>{showAuthSection ? 'Hide Development Token' : 'Development Bearer Token'}</span>
        </button>

        {showAuthSection && (
          <div className="auth-input-container glass-panel">
            <label htmlFor="dev-bearer-token" className="auth-label">
              Bearer Token (In-Memory Only)
            </label>
            <input
              id="dev-bearer-token"
              type="password"
              className="auth-input"
              placeholder="e.g. ag_..."
              value={developerToken}
              onChange={(e) => setDeveloperToken(e.target.value)}
              autoComplete="off"
            />
            <span className="text-muted" style={{ fontSize: '0.6875rem' }}>
              Held only in component memory during this session. Never written to localStorage or logged.
            </span>
          </div>
        )}
      </div>
    </aside>
  );
};
