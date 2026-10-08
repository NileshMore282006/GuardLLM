/**
 * AgentGuard Destructive Action Dialog (Frontend v0.7)
 * Implements high-assurance impact disclosure and intentional confirmation
 * before dispatching privileged or destructive mutations to the gateway.
 */

import React, { useState } from 'react';
import { AlertTriangle, X, Loader2, CheckCircle2 } from 'lucide-react';
import { DestructiveActionSpec } from '../../types/agentguard';

interface DestructiveActionDialogProps {
  spec: DestructiveActionSpec | null;
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: () => void;
}

export const DestructiveActionDialog: React.FC<DestructiveActionDialogProps> = ({
  spec,
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmedChecked, setConfirmedChecked] = useState(false);

  if (!isOpen || !spec) {
    return null;
  }

  const handleConfirm = async () => {
    setIsSubmitting(true);
    setError(null);
    try {
      await spec.onExecute();
      if (onSuccess) {
        onSuccess();
      }
      onClose();
    } catch (err: any) {
      if (err?.status === 409) {
        setError('Resource conflict: The item has already been modified or consumed by another operator.');
      } else if (err?.status === 403) {
        setError('Access denied: AgentGuard backend rejected this privileged operation (Forbidden).');
      } else {
        setError(err?.message || 'The privileged operation failed on the backend.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancel = () => {
    if (isSubmitting) return;
    setError(null);
    setConfirmedChecked(false);
    onClose();
  };

  return (
    <div
      className="modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="destructive-dialog-title"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.75)',
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
          maxWidth: '540px',
          background: 'var(--bg-secondary)',
          borderRadius: '12px',
          border: '1px solid rgba(239, 68, 68, 0.4)',
          overflow: 'hidden',
          boxShadow: '0 20px 40px rgba(0, 0, 0, 0.6)',
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: '1rem 1.25rem',
            borderBottom: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'rgba(239, 68, 68, 0.1)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <div
              style={{
                color: 'var(--color-danger)',
                display: 'flex',
                alignItems: 'center',
              }}
            >
              <AlertTriangle size={20} />
            </div>
            <h3
              id="destructive-dialog-title"
              style={{
                fontSize: '1rem',
                fontWeight: 600,
                color: 'var(--text-primary)',
                margin: 0,
              }}
            >
              Confirm Privileged Security Action
            </h3>
          </div>
          <button
            type="button"
            className="action-icon-btn"
            onClick={handleCancel}
            disabled={isSubmitting}
            aria-label="Close dialog"
            style={{ color: 'var(--text-muted)' }}
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {error && (
            <div
              className="alert-box danger"
              role="alert"
              style={{ fontSize: '0.8125rem' }}
            >
              {error}
            </div>
          )}

          {/* Action Details Card */}
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '0.6rem',
              background: 'var(--bg-tertiary)',
              padding: '0.85rem 1rem',
              borderRadius: '8px',
              border: '1px solid var(--border-subtle)',
              fontSize: '0.8125rem',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Action:</span>
              <strong style={{ color: 'var(--color-danger)' }}>{spec.action}</strong>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Target Resource:</span>
              <code style={{ fontSize: '0.75rem', color: 'var(--text-primary)' }}>
                {spec.resourceId}
              </code>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Resource Type:</span>
              <span style={{ textTransform: 'uppercase', fontSize: '0.75rem', fontWeight: 600 }}>
                {spec.resourceType}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Current Server State:</span>
              <span className="status-pill info" style={{ fontSize: '0.7rem' }}>
                {spec.currentServerState}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Reversible:</span>
              <span
                style={{
                  color: spec.reversible ? 'var(--color-success)' : 'var(--color-danger)',
                  fontWeight: 600,
                  fontSize: '0.75rem',
                }}
              >
                {spec.reversible ? 'Yes (Can be re-enabled)' : 'No (Irreversible)'}
              </span>
            </div>
          </div>

          {/* Security Impact Disclosure */}
          <div
            style={{
              padding: '0.75rem 1rem',
              borderRadius: '8px',
              background: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid rgba(245, 158, 11, 0.3)',
              fontSize: '0.8125rem',
              color: 'var(--text-secondary)',
            }}
          >
            <div style={{ fontWeight: 600, color: 'var(--color-warn)', marginBottom: '0.25rem' }}>
              Security Impact:
            </div>
            <div>{spec.impact}</div>
          </div>

          {/* Intentional Confirmation Checkbox */}
          <label
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '0.6rem',
              fontSize: '0.8125rem',
              color: 'var(--text-primary)',
              cursor: 'pointer',
              userSelect: 'none',
              marginTop: '0.25rem',
            }}
          >
            <input
              type="checkbox"
              id="confirm-destructive-action-checkbox"
              checked={confirmedChecked}
              onChange={(e) => setConfirmedChecked(e.target.checked)}
              disabled={isSubmitting}
              style={{ marginTop: '0.15rem' }}
            />
            <span>
              I understand the operational impact and confirm execution of this authoritative action.
            </span>
          </label>
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '1rem 1.25rem',
            borderTop: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'flex-end',
            gap: '0.75rem',
            background: 'var(--bg-tertiary)',
          }}
        >
          <button
            type="button"
            className="secondary-btn"
            onClick={handleCancel}
            disabled={isSubmitting}
            style={{ fontSize: '0.8125rem', padding: '0.5rem 1rem' }}
          >
            Cancel
          </button>

          <button
            type="button"
            className="danger-btn"
            onClick={handleConfirm}
            disabled={isSubmitting || !confirmedChecked}
            data-testid="confirm-destructive-action-btn"
            style={{
              fontSize: '0.8125rem',
              padding: '0.5rem 1.25rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              opacity: !confirmedChecked ? 0.6 : 1,
            }}
          >
            {isSubmitting ? (
              <>
                <Loader2 size={14} className="spin" />
                <span>Executing on Gateway...</span>
              </>
            ) : (
              <>
                <CheckCircle2 size={14} />
                <span>Execute Authoritative Action</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
