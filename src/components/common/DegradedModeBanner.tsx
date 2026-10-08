/**
 * AgentGuard Backend Degraded Mode Banner (Frontend v0.7)
 * Informs operators when the gateway is unreachable or unhealthy.
 * Locks down destructive mutations and displays last-known-state warnings.
 */

import React from 'react';
import { AlertOctagon, RefreshCw, Lock } from 'lucide-react';

interface DegradedModeBannerProps {
  isOnline: boolean;
  onRetry: () => void;
  isRetrying?: boolean;
}

export const DegradedModeBanner: React.FC<DegradedModeBannerProps> = ({
  isOnline,
  onRetry,
  isRetrying = false,
}) => {
  if (isOnline) {
    return null;
  }

  return (
    <div
      className="degraded-mode-banner"
      role="alert"
      style={{
        background: 'linear-gradient(90deg, rgba(239, 68, 68, 0.95), rgba(185, 28, 28, 0.95))',
        color: '#ffffff',
        padding: '0.65rem 1.25rem',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '0.75rem',
        fontSize: '0.8125rem',
        boxShadow: '0 4px 12px rgba(239, 68, 68, 0.3)',
        zIndex: 100,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
        <AlertOctagon size={18} />
        <div>
          <strong style={{ marginRight: '0.5rem' }}>GATEWAY OFFLINE / DEGRADED:</strong>
          <span>
            Unable to connect to AgentGuard gateway. Privileged mutations and destructive actions are locked to prevent state desynchronization.
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <span
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.3rem',
            background: 'rgba(0, 0, 0, 0.25)',
            padding: '0.2rem 0.5rem',
            borderRadius: '4px',
            fontSize: '0.75rem',
          }}
        >
          <Lock size={12} />
          <span>Mutations Locked</span>
        </span>

        <button
          type="button"
          onClick={onRetry}
          disabled={isRetrying}
          style={{
            background: '#ffffff',
            color: '#b91c1c',
            border: 'none',
            borderRadius: '4px',
            padding: '0.25rem 0.75rem',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.35rem',
            fontSize: '0.75rem',
          }}
        >
          <RefreshCw size={12} className={isRetrying ? 'spin' : ''} />
          <span>{isRetrying ? 'Retrying…' : 'Retry Gateway Connection'}</span>
        </button>
      </div>
    </div>
  );
};
