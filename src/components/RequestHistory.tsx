import React from 'react';
import { HistoryItem } from '../types/agentguard';
import { History, CheckCircle, XCircle, AlertTriangle, Clock } from 'lucide-react';

interface RequestHistoryProps {
  history: HistoryItem[];
  onSelect: (item: HistoryItem) => void;
  onClear: () => void;
}

export const RequestHistory: React.FC<RequestHistoryProps> = ({
  history,
  onSelect,
  onClear,
}) => {
  if (history.length === 0) {
    return (
      <div className="glass-panel" style={{ padding: '1.25rem 1.5rem' }}>
        <div className="flow-title">
          <span>Session Request History</span>
        </div>
        <p className="text-muted" style={{ fontSize: '0.8125rem' }}>
          No requests evaluated in this browser session yet. Analyzed prompts will appear here in memory.
        </p>
      </div>
    );
  }

  return (
    <div className="glass-panel history-section" style={{ padding: '1.25rem 1.5rem' }}>
      <div className="flow-title">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <History size={16} />
          <span>Session Request History ({history.length})</span>
        </div>
        <button
          type="button"
          onClick={onClear}
          className="text-muted"
          style={{
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            fontSize: '0.75rem',
            textDecoration: 'underline',
          }}
        >
          Clear
        </button>
      </div>

      <div className="history-list">
        {history.map((item) => {
          const isAllow = item.decision === 'ALLOW';
          const isBlock = item.decision === 'BLOCK';

          return (
            <div
              key={item.id}
              className="history-item-row"
              onClick={() => onSelect(item)}
              title="Click to restore this evaluation in the playground"
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  onSelect(item);
                }
              }}
            >
              <div className="history-item-left">
                <span
                  style={{
                    color: isAllow
                      ? 'var(--color-allow)'
                      : isBlock
                      ? 'var(--color-block)'
                      : 'var(--color-warn)',
                  }}
                >
                  {isAllow ? (
                    <CheckCircle size={16} />
                  ) : isBlock ? (
                    <XCircle size={16} />
                  ) : (
                    <AlertTriangle size={16} />
                  )}
                </span>
                <span className="history-prompt-snippet">
                  {item.prompt}
                </span>
              </div>

              <div className="history-item-right">
                <span className="mono-text" style={{ fontSize: '0.6875rem' }}>
                  Risk: {item.risk_score.toFixed(2)}
                </span>
                <span className="mono-text" style={{ fontSize: '0.6875rem' }}>
                  {item.attack_type || 'none'}
                </span>
                <span className="meta-chip" style={{ fontSize: '0.6875rem' }}>
                  <Clock size={10} />
                  <span>{item.latency_ms.toFixed(0)} ms</span>
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
