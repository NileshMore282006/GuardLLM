import React, { useState } from 'react';
import { AlertTriangle, X, Loader2 } from 'lucide-react';
import { AdminConfirmationState } from '../../types/agentguard';

interface AdminConfirmationDialogProps {
  state: AdminConfirmationState;
  onClose: () => void;
}

export const AdminConfirmationDialog: React.FC<AdminConfirmationDialogProps> = ({
  state,
  onClose,
}) => {
  const [isExecuting, setIsExecuting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!state.isOpen) return null;

  const handleConfirm = async () => {
    setError(null);
    setIsExecuting(true);
    try {
      await state.onConfirm();
      onClose();
    } catch (err: any) {
      setError(err?.message || 'Operation failed on the security gateway.');
    } finally {
      setIsExecuting(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirm-dialog-title"
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
          border: '1px solid rgba(239, 68, 68, 0.4)',
          boxShadow: '0 20px 40px rgba(0, 0, 0, 0.8)',
          padding: '1.5rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '1.25rem',
          borderRadius: '12px',
          background: 'var(--bg-secondary)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div
              style={{
                padding: '0.5rem',
                borderRadius: '8px',
                background: 'rgba(239, 68, 68, 0.15)',
                color: 'var(--color-block)',
              }}
            >
              <AlertTriangle size={22} />
            </div>
            <div>
              <h3 id="confirm-dialog-title" style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                Confirm {state.operation}
              </h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Security-sensitive destructive operation
              </span>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={isExecuting}
            aria-label="Close confirmation dialog"
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: '0.25rem',
            }}
          >
            <X size={18} />
          </button>
        </div>

        <div style={{ background: 'var(--bg-tertiary)', padding: '0.85rem 1rem', borderRadius: '8px', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8125rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>Target {state.targetType}:</span>
            <span className="mono-text" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
              {state.targetId}
            </span>
          </div>
          <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.5, borderTop: '1px solid var(--border-subtle)', paddingTop: '0.5rem' }}>
            <strong style={{ color: 'var(--color-warn)' }}>Security Impact: </strong>
            {state.securityImpact}
          </div>
        </div>

        {error && (
          <div className="alert-box danger" role="alert" style={{ margin: 0, padding: '0.75rem' }}>
            <div style={{ fontSize: '0.8125rem' }}>{error}</div>
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
          <button
            type="button"
            className="secondary-btn"
            onClick={onClose}
            disabled={isExecuting}
            style={{ padding: '0.5rem 1rem', fontSize: '0.875rem' }}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleConfirm}
            disabled={isExecuting}
            style={{
              padding: '0.5rem 1.25rem',
              fontSize: '0.875rem',
              fontWeight: 600,
              background: 'rgba(239, 68, 68, 0.2)',
              color: 'var(--color-block)',
              border: '1px solid rgba(239, 68, 68, 0.5)',
              borderRadius: '6px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
            }}
          >
            {isExecuting && <Loader2 size={15} className="spinner" />}
            <span>Confirm: {state.operation}</span>
          </button>
        </div>
      </div>
    </div>
  );
};
