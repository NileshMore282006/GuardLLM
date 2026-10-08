/**
 * AgentGuard Data Freshness Badge (Frontend v0.7)
 * Renders explicit operational freshness states for security panels:
 * LIVE, REFRESHING, STALE, DEGRADED, NOT_AVAILABLE.
 * Prevents operators from misinterpreting cached or stale telemetry as live.
 */

import React from 'react';
import { RefreshCw, Clock, AlertTriangle, Database } from 'lucide-react';
import { SecurityFreshness } from '../../types/agentguard';

interface DataFreshnessBadgeProps {
  freshness: SecurityFreshness;
  lastUpdatedTimestamp?: number | null;
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export const DataFreshnessBadge: React.FC<DataFreshnessBadgeProps> = ({
  freshness,
  lastUpdatedTimestamp,
  onRefresh,
  isRefreshing = false,
}) => {
  const getSecondsAgo = (): number | null => {
    if (!lastUpdatedTimestamp) return null;
    return Math.max(0, Math.floor((Date.now() - lastUpdatedTimestamp) / 1000));
  };

  const secondsAgo = getSecondsAgo();

  if (freshness === 'REFRESHING' || isRefreshing) {
    return (
      <div
        className="freshness-badge refreshing"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.35rem',
          fontSize: '0.6875rem',
          padding: '0.2rem 0.55rem',
          borderRadius: '999px',
          background: 'rgba(59, 130, 246, 0.15)',
          color: 'var(--color-accent)',
          border: '1px solid rgba(59, 130, 246, 0.3)',
        }}
      >
        <RefreshCw size={11} className="spin" />
        <span>Refreshing…</span>
      </div>
    );
  }

  if (freshness === 'DEGRADED') {
    return (
      <div
        className="freshness-badge degraded"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.35rem',
          fontSize: '0.6875rem',
          padding: '0.2rem 0.55rem',
          borderRadius: '999px',
          background: 'rgba(239, 68, 68, 0.15)',
          color: 'var(--color-danger)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
        }}
      >
        <AlertTriangle size={11} />
        <span>Backend unavailable — showing last known data</span>
        {onRefresh && (
          <button
            type="button"
            onClick={onRefresh}
            style={{
              background: 'none',
              border: 'none',
              color: 'inherit',
              cursor: 'pointer',
              padding: 0,
              display: 'flex',
            }}
            title="Retry refresh"
          >
            <RefreshCw size={11} />
          </button>
        )}
      </div>
    );
  }

  if (freshness === 'STALE') {
    return (
      <div
        className="freshness-badge stale"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.35rem',
          fontSize: '0.6875rem',
          padding: '0.2rem 0.55rem',
          borderRadius: '999px',
          background: 'rgba(245, 158, 11, 0.15)',
          color: 'var(--color-warn)',
          border: '1px solid rgba(245, 158, 11, 0.3)',
        }}
      >
        <Clock size={11} />
        <span>
          {secondsAgo !== null ? `Stale — updated ${secondsAgo}s ago` : 'Stale data'}
        </span>
        {onRefresh && (
          <button
            type="button"
            onClick={onRefresh}
            style={{
              background: 'none',
              border: 'none',
              color: 'inherit',
              cursor: 'pointer',
              padding: 0,
              display: 'flex',
            }}
            title="Refresh now"
          >
            <RefreshCw size={11} />
          </button>
        )}
      </div>
    );
  }

  if (freshness === 'NOT_AVAILABLE') {
    return (
      <div
        className="freshness-badge not-available"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.35rem',
          fontSize: '0.6875rem',
          padding: '0.2rem 0.55rem',
          borderRadius: '999px',
          background: 'rgba(100, 116, 139, 0.15)',
          color: 'var(--text-muted)',
          border: '1px solid var(--border-subtle)',
        }}
      >
        <Database size={11} />
        <span>Data unavailable</span>
      </div>
    );
  }

  // Default: LIVE
  return (
    <div
      className="freshness-badge live"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.35rem',
        fontSize: '0.6875rem',
        padding: '0.2rem 0.55rem',
        borderRadius: '999px',
        background: 'rgba(16, 185, 129, 0.15)',
        color: 'var(--color-success)',
        border: '1px solid rgba(16, 185, 129, 0.3)',
      }}
    >
      <span
        style={{
          width: '6px',
          height: '6px',
          borderRadius: '50%',
          backgroundColor: 'var(--color-success)',
          display: 'inline-block',
        }}
      />
      <span>
        {secondsAgo !== null && secondsAgo > 0
          ? `Live — updated ${secondsAgo}s ago`
          : 'Live — updated just now'}
      </span>
      {onRefresh && (
        <button
          type="button"
          onClick={onRefresh}
          style={{
            background: 'none',
            border: 'none',
            color: 'inherit',
            cursor: 'pointer',
            padding: 0,
            display: 'flex',
            opacity: 0.7,
          }}
          title="Refresh now"
        >
          <RefreshCw size={10} />
        </button>
      )}
    </div>
  );
};
