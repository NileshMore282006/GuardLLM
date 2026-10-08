import React from 'react';
import { ToolSecurityHistoryItem } from '../../types/agentguard';
import { History, Trash2, ArrowRight } from 'lucide-react';

interface ToolSecurityHistoryProps {
  history: ToolSecurityHistoryItem[];
  onSelect: (item: ToolSecurityHistoryItem) => void;
  onClear: () => void;
}

export const ToolSecurityHistory: React.FC<ToolSecurityHistoryProps> = ({
  history,
  onSelect,
  onClear,
}) => {
  if (history.length === 0) {
    return (
      <div
        className="glass-panel"
        style={{
          padding: '1.25rem',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          textAlign: 'center',
          color: 'var(--text-muted)',
          fontSize: '0.8125rem',
        }}
      >
        <History size={20} style={{ opacity: 0.5, marginBottom: '0.4rem' }} />
        <p>No tool security events in this session yet.</p>
        <span style={{ fontSize: '0.6875rem' }}>Session memory only — never persisted</span>
      </div>
    );
  }

  return (
    <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <History size={16} style={{ color: 'var(--color-accent)' }} />
          <h3 style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Session Event History ({history.length})
          </h3>
        </div>
        <button
          type="button"
          onClick={onClear}
          style={{
            background: 'transparent',
            border: 'none',
            color: 'var(--text-muted)',
            fontSize: '0.75rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.25rem',
          }}
        >
          <Trash2 size={12} /> Clear
        </button>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', maxHeight: '220px', overflowY: 'auto' }}>
        {history.map((item) => (
          <button
            key={item.id}
            type="button"
            onClick={() => onSelect(item)}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '0.5rem 0.65rem',
              borderRadius: 'var(--radius-sm)',
              background: 'rgba(0, 0, 0, 0.25)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              fontSize: '0.75rem',
              textAlign: 'left',
              transition: 'border-color 0.15s ease',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                {item.timestamp}
              </span>
              <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                {item.tool_name}
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <span
                style={{
                  fontSize: '0.65rem',
                  fontWeight: 700,
                  padding: '0.1rem 0.4rem',
                  borderRadius: 'var(--radius-sm)',
                  background:
                    item.decision === 'ALLOW'
                      ? 'var(--color-allow-bg)'
                      : item.decision === 'BLOCK'
                      ? 'var(--color-block-bg)'
                      : 'rgba(245, 158, 11, 0.15)',
                  color:
                    item.decision === 'ALLOW'
                      ? 'var(--color-allow)'
                      : item.decision === 'BLOCK'
                      ? 'var(--color-block)'
                      : '#f59e0b',
                }}
              >
                {item.decision}
              </span>

              {item.risk_level && (
                <span
                  style={{
                    fontSize: '0.65rem',
                    textTransform: 'uppercase',
                    color: 'var(--text-muted)',
                  }}
                >
                  {item.risk_level}
                </span>
              )}

              <ArrowRight size={12} style={{ opacity: 0.5 }} />
            </div>
          </button>
        ))}
      </div>
    </div>
  );
};
