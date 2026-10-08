import React, { useState } from 'react';
import { ChatTurn } from '../types/agentguard';
import {
  User,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Cpu,
  ChevronDown,
  ChevronUp,
  Clock,
  Hash,
} from 'lucide-react';

interface MessageBubbleProps {
  turn: ChatTurn;
}

export const MessageBubble: React.FC<MessageBubbleProps> = ({ turn }) => {
  const [showDetails, setShowDetails] = useState(false);
  const isAllow = turn.security.decision === 'ALLOW';
  const isBlock = turn.security.decision === 'BLOCK';
  const isError = turn.security.decision === 'ERROR';

  return (
    <div className="chat-turn-container" data-testid={`chat-turn-${turn.turnNumber}`}>
      {/* 1. User Message */}
      <div className="message-row user-row">
        <div className="avatar-badge user-avatar">
          <User size={16} />
        </div>
        <div className="message-content-wrapper">
          <div className="message-meta-bar">
            <span className="author-name">USER</span>
            <span className="turn-number-badge">Turn {turn.turnNumber}</span>
            <span className="message-time text-muted">{turn.timestamp}</span>
          </div>
          <div className="message-bubble user-bubble">
            <p className="message-text">{turn.userMessage}</p>
          </div>
        </div>
      </div>

      {/* 2. Turn Security Evaluation Indicator */}
      <div className="turn-security-indicator">
        <div
          className={`turn-security-pill ${
            isAllow ? 'allow' : isBlock ? 'block' : 'error'
          }`}
          role="status"
          aria-label={`Turn ${turn.turnNumber} Security Decision: ${turn.security.decision}`}
        >
          {isAllow && <ShieldCheck size={14} />}
          {isBlock && <ShieldAlert size={14} />}
          {isError && <AlertTriangle size={14} />}

          <span className="pill-decision">
            {isAllow ? '✓ ALLOWED' : isBlock ? '✕ BLOCKED' : '⚠ ERROR'}
          </span>

          <span className="pill-separator">•</span>
          <span className="pill-metric">
            Risk: {turn.security.risk_score !== null ? turn.security.risk_score.toFixed(2) : 'N/A'}
          </span>

          {turn.security.attack_type && turn.security.attack_type !== 'none' && (
            <>
              <span className="pill-separator">•</span>
              <span className="pill-attack-type">{turn.security.attack_type}</span>
            </>
          )}

          <span className="pill-separator">•</span>
          <span className="pill-metric">
            <Clock size={10} style={{ display: 'inline', marginRight: '3px' }} />
            {turn.security.latency_ms.toFixed(1)}ms
          </span>

          <button
            type="button"
            className="btn-details-toggle"
            onClick={() => setShowDetails(!showDetails)}
            aria-expanded={showDetails}
            title="Toggle security evaluation details"
          >
            {showDetails ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
            <span>{showDetails ? 'Hide' : 'Details'}</span>
          </button>
        </div>

        {/* Expandable Turn Security Metadata Panel */}
        {showDetails && (
          <div className="turn-details-dropdown glass-panel">
            <div className="details-grid-compact">
              <div className="details-item">
                <span className="details-label">Decision</span>
                <span className="details-val mono-text">{turn.security.decision}</span>
              </div>
              <div className="details-item">
                <span className="details-label">Attack Type</span>
                <span className="details-val">{turn.security.attack_type || 'none'}</span>
              </div>
              <div className="details-item">
                <span className="details-label">Guard Model</span>
                <span className="details-val mono-text">{turn.security.guard_model}</span>
              </div>
              <div className="details-item">
                <span className="details-label">Target Model</span>
                <span className="details-val mono-text">
                  {isBlock ? 'NOT INVOKED' : turn.security.target_model}
                </span>
              </div>
              <div className="details-item full-width">
                <span className="details-label">Request ID</span>
                <span className="details-val mono-text" title={turn.security.request_id}>
                  <Hash size={10} style={{ display: 'inline', marginRight: '2px' }} />
                  {turn.security.request_id}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 3. Assistant Response (on ALLOW) OR Prominent Blocked Banner (on BLOCK) */}
      {isAllow && turn.assistantResponse && (
        <div className="message-row assistant-row">
          <div className="avatar-badge assistant-avatar">
            <Cpu size={16} />
          </div>
          <div className="message-content-wrapper">
            <div className="message-meta-bar">
              <span className="author-name">AGENTGUARD</span>
              <span className="meta-chip target-chip" title="Target LLM">
                {turn.security.target_model}
              </span>
              <span className="message-time text-muted">{turn.timestamp}</span>
            </div>
            <div className="message-bubble assistant-bubble">
              {/* Plain-text sanitized output - NEVER dangerouslySetInnerHTML */}
              <p className="message-text">{turn.assistantResponse}</p>
            </div>
          </div>
        </div>
      )}

      {isBlock && (
        <div className="message-row block-interruption-row" role="alert">
          <div className="alert-box danger blocked-turn-card">
            <ShieldAlert size={22} style={{ flexShrink: 0, marginTop: '2px' }} />
            <div className="blocked-turn-content">
              <div className="blocked-turn-title">✕ REQUEST BLOCKED</div>
              <p className="blocked-turn-msg">
                AgentGuard detected a security risk in this conversation turn.
                The prompt was neutralized at the gateway perimeter and the Target LLM was{' '}
                <strong>NOT INVOKED</strong>.
              </p>
              <div className="blocked-metrics-strip">
                <span className="blocked-badge-item">
                  Risk: <strong>{turn.security.risk_score?.toFixed(2) ?? '1.00'}</strong>
                </span>
                <span className="blocked-badge-item">
                  Attack: <strong>{turn.security.attack_type}</strong>
                </span>
                <span className="blocked-badge-item">
                  Target: <strong>NOT INVOKED</strong>
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {isError && (
        <div className="message-row error-row" role="alert">
          <div className="alert-box danger error-turn-card">
            <AlertTriangle size={20} style={{ flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 600 }}>⚠ EVALUATION ERROR</div>
              <div style={{ fontSize: '0.8125rem' }}>
                A gateway error occurred during turn evaluation. Failing closed; Target LLM was NOT invoked.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
