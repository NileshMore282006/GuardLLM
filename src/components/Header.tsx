import React from 'react';
import { HealthResponse, AppMode } from '../types/agentguard';
import { SystemStatus } from './SystemStatus';
import { Shield, MessageSquare, Terminal, Wrench, LayoutDashboard, Sliders, Activity } from 'lucide-react';
import { useSession } from '../context/SessionContext';

interface HeaderProps {
  health: HealthResponse | null;
  isOnline: boolean;
  isLoading: boolean;
  mode: AppMode;
  onModeChange: (mode: AppMode) => void;
}

export const Header: React.FC<HeaderProps> = ({
  health,
  isOnline,
  isLoading,
  mode,
  onModeChange,
}) => {
  const { tokenPresent, maskedToken, isGlobalAdmin, roles, logout } = useSession();
  return (
    <header className="header-wrapper">
      <div className="brand-container">
        <div className="brand-logo-badge">
          <Shield size={24} />
        </div>
        <div className="brand-titles">
          <h1>
            AGENTGUARD
            <span className="brand-version-pill">
              v{health?.version || '1.0.0'} RC
            </span>
          </h1>
          <p className="brand-subtitle">AI Security Gateway & Guard Perimeter</p>
        </div>
      </div>

      <nav className="header-mode-nav" aria-label="Application View Mode">
        <button
          type="button"
          id="nav-tab-secops"
          data-testid="nav-tab-secops"
          className={`nav-tab-btn ${mode === 'secops' ? 'active' : ''}`}
          onClick={() => onModeChange('secops')}
          aria-pressed={mode === 'secops'}
        >
          <Activity size={15} />
          <span>Security Operations</span>
          <span className="nav-tag">v0.6</span>
        </button>
        <button
          type="button"
          id="nav-tab-admin"
          className={`nav-tab-btn ${mode === 'admin' ? 'active' : ''}`}
          onClick={() => onModeChange('admin')}
          aria-pressed={mode === 'admin'}
        >
          <Sliders size={15} />
          <span>Administration</span>
          <span className="nav-tag">v0.5</span>
        </button>
        <button
          type="button"
          id="nav-tab-dashboard"
          className={`nav-tab-btn ${mode === 'dashboard' ? 'active' : ''}`}
          onClick={() => onModeChange('dashboard')}
          aria-pressed={mode === 'dashboard'}
        >
          <LayoutDashboard size={15} />
          <span>Security Dashboard</span>
          <span className="nav-tag">v0.4</span>
        </button>
        <button
          type="button"
          id="nav-tab-agent-security"
          className={`nav-tab-btn ${mode === 'agent-security' ? 'active' : ''}`}
          onClick={() => onModeChange('agent-security')}
          aria-pressed={mode === 'agent-security'}
        >
          <Wrench size={15} />
          <span>Agent Security</span>
          <span className="nav-tag">v0.3</span>
        </button>
        <button
          type="button"
          id="nav-tab-chat"
          className={`nav-tab-btn ${mode === 'chat' ? 'active' : ''}`}
          onClick={() => onModeChange('chat')}
          aria-pressed={mode === 'chat'}
        >
          <MessageSquare size={15} />
          <span>Multi-Turn Chat</span>
          <span className="nav-tag">v0.2</span>
        </button>
        <button
          type="button"
          id="nav-tab-playground"
          className={`nav-tab-btn ${mode === 'playground' ? 'active' : ''}`}
          onClick={() => onModeChange('playground')}
          aria-pressed={mode === 'playground'}
        >
          <Terminal size={15} />
          <span>Security Playground</span>
          <span className="nav-tag">v0.1</span>
        </button>
      </nav>

      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        {tokenPresent && (
          <div
            className="session-header-badge"
            data-testid="header-session-badge"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.25rem 0.65rem',
              borderRadius: '999px',
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border-subtle)',
              fontSize: '0.75rem',
            }}
          >
            <span
              style={{
                fontSize: '0.65rem',
                fontWeight: 700,
                textTransform: 'uppercase',
                padding: '0.1rem 0.35rem',
                borderRadius: '4px',
                background: isGlobalAdmin
                  ? 'rgba(168, 85, 247, 0.2)'
                  : roles.includes('admin')
                  ? 'rgba(59, 130, 246, 0.2)'
                  : 'rgba(16, 185, 129, 0.2)',
                color: isGlobalAdmin
                  ? '#c084fc'
                  : roles.includes('admin')
                  ? 'var(--color-accent)'
                  : 'var(--color-success)',
              }}
            >
              {isGlobalAdmin ? 'GLOBAL ADMIN' : roles[0] || 'USER'}
            </span>

            <code
              data-testid="header-masked-token"
              style={{
                fontFamily: 'monospace',
                fontSize: '0.75rem',
                color: 'var(--text-secondary)',
              }}
            >
              {maskedToken}
            </code>

            <button
              type="button"
              onClick={logout}
              data-testid="header-logout-btn"
              title="Clear session and remove token from memory"
              style={{
                background: 'none',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                padding: '0 0.2rem',
                fontSize: '0.7rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.2rem',
              }}
            >
              <span>Logout</span>
            </button>
          </div>
        )}

        <SystemStatus health={health} isOnline={isOnline} isLoading={isLoading} />
      </div>
    </header>
  );
};
