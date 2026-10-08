import React from 'react';
import { HealthResponse } from '../types/agentguard';
import { Cpu, ShieldCheck, ShieldAlert } from 'lucide-react';

interface SystemStatusProps {
  health: HealthResponse | null;
  isOnline: boolean;
  isLoading: boolean;
}

export const SystemStatus: React.FC<SystemStatusProps> = ({
  health,
  isOnline,
  isLoading,
}) => {
  if (isLoading && !health) {
    return (
      <div className="status-indicator" style={{ opacity: 0.7 }}>
        <span className="status-pulse-dot" />
        <span>CONNECTING...</span>
      </div>
    );
  }

  return (
    <div className="header-status-group">
      {isOnline && health && (
        <div className="telemetry-meta">
          <span className="meta-chip" title="Guard LLM Model">
            <Cpu size={12} />
            <span>Guard: {health.guard_model}</span>
          </span>
          <span className="meta-chip" title="Target LLM Model">
            <Cpu size={12} />
            <span>Target: {health.target_model}</span>
          </span>
        </div>
      )}

      <div
        className={`status-indicator ${isOnline ? 'online' : 'offline'}`}
        role="status"
        aria-live="polite"
      >
        <span className="status-pulse-dot" />
        {isOnline ? (
          <>
            <ShieldCheck size={14} />
            <span>PROTECTED</span>
          </>
        ) : (
          <>
            <ShieldAlert size={14} />
            <span>OFFLINE</span>
          </>
        )}
      </div>
    </div>
  );
};
