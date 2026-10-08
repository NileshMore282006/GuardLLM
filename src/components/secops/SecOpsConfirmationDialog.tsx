import React from 'react';
import { AlertTriangle, X, ShieldAlert, Loader2 } from 'lucide-react';
import { SecOpsConfirmationState } from '../../types/agentguard';

interface SecOpsConfirmationDialogProps {
  state: SecOpsConfirmationState;
  onClose: () => void;
  isExecuting?: boolean;
  error?: string | null;
}

export const SecOpsConfirmationDialog: React.FC<SecOpsConfirmationDialogProps> = ({
  state,
  onClose,
  isExecuting = false,
  error = null,
}) => {
  if (!state.isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="dialog-title"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(5, 8, 16, 0.85)',
        backdropFilter: 'blur(8px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
        padding: '1rem',
      }}
    >
      <div
        className="glass-panel"
        style={{
          width: '100%',
          maxWidth: '520px',
          padding: '1.75rem',
          borderRadius: '12px',
          background: 'var(--bg-secondary)',
          display: 'flex',
          flexDirection: 'column',
          gap: '1.25rem',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7)',
          border: '1px solid rgba(239, 68, 68, 0.35)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <div
              style={{
                padding: '0.5rem',
                borderRadius: '8px',
                background: 'rgba(239, 68, 68, 0.2)',
                color: 'var(--color-block)',
              }}
            >
              <AlertTriangle size={20} />
            </div>
            <div>
              <h3 id="dialog-title" style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                Confirm Security Mitigation Action
              </h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Administrative Incident Response Control
              </span>
            </div>
          </div>
          <button
            type="button"
            className="secondary-btn"
            onClick={onClose}
            disabled={isExecuting}
            style={{ padding: '0.35rem', borderRadius: '6px' }}
            aria-label="Close dialog"
          >
            <X size={16} />
          </button>
        </div>

        {error && (
          <div className="alert-box danger" role="alert" style={{ margin: 0, padding: '0.75rem 1rem' }}>
            <ShieldAlert size={18} style={{ flexShrink: 0 }} />
            <div style={{ fontSize: '0.8125rem' }}>{error}</div>
          </div>
        )}

        <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          <p style={{ marginBottom: '0.75rem' }}>
            You are about to execute the following authoritative security action:
          </p>
          <div
            style={{
              padding: '0.75rem 1rem',
              background: 'var(--bg-tertiary)',
              borderRadius: '6px',
              border: '1px solid var(--border-subtle)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.8125rem',
              color: 'var(--text-primary)',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.35rem',
            }}
          >
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Operation: </span>
              <strong style={{ color: 'var(--color-block)' }}>{state.operation}</strong>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Target: </span>
              <span style={{ color: 'var(--color-accent)' }}>{state.targetId}</span>
              <span style={{ color: 'var(--text-muted)', marginLeft: '0.35rem' }}>({state.targetType})</span>
            </div>
          </div>
        </div>

        <div
          style={{
            padding: '0.85rem 1rem',
            background: 'rgba(239, 68, 68, 0.08)',
            borderLeft: '3px solid var(--color-block)',
            borderRadius: '4px',
            fontSize: '0.8125rem',
            color: 'var(--text-secondary)',
            lineHeight: 1.45,
          }}
        >
          <strong style={{ color: 'var(--color-block)', display: 'block', marginBottom: '0.25rem' }}>
            Security Consequence:
          </strong>
          {state.securityImpact}
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
          <button
            type="button"
            className="secondary-btn"
            onClick={onClose}
            disabled={isExecuting}
            style={{ padding: '0.5rem 1rem', fontSize: '0.8125rem' }}
          >
            Cancel
          </button>
          <button
            type="button"
            className="primary-btn"
            onClick={state.onConfirm}
            disabled={isExecuting}
            style={{
              padding: '0.5rem 1.25rem',
              fontSize: '0.8125rem',
              background: 'var(--color-block)',
              borderColor: 'var(--color-block)',
              color: '#ffffff',
              fontWeight: 600,
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.5rem',
            }}
          >
            {isExecuting ? (
              <>
                <Loader2 size={14} className="spin" />
                <span>Executing...</span>
              </>
            ) : (
              <span>Confirm: {state.operation}</span>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
