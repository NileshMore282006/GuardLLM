import React, { useState } from 'react';
import { ShieldCheck, UserCheck, Key, CheckCircle2, ShieldAlert } from 'lucide-react';

interface SecurityContextCardProps {
  token: string;
  onTokenChange: (token: string) => void;
  callerPrincipalId?: string;
  callerTenantId?: string;
  callerRoles?: string[];
  isGlobalAdmin?: boolean;
}

export const SecurityContextCard: React.FC<SecurityContextCardProps> = ({
  token,
  onTokenChange,
  callerPrincipalId = 'anonymous',
  callerTenantId = 'default',
  callerRoles = ['user'],
  isGlobalAdmin = false,
}) => {
  const [localToken, setLocalToken] = useState(token);
  const [showTokenInput, setShowTokenInput] = useState(false);

  const handleApplyToken = (e: React.FormEvent) => {
    e.preventDefault();
    onTokenChange(localToken.trim());
  };

  const handleClearToken = () => {
    setLocalToken('');
    onTokenChange('');
  };

  const hasActiveToken = Boolean(token && token.trim());

  return (
    <div
      className="glass-panel"
      style={{
        padding: '1.25rem 1.5rem',
        borderRadius: '12px',
        display: 'flex',
        flexDirection: 'column',
        gap: '1rem',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div
            style={{
              padding: '0.5rem',
              borderRadius: '8px',
              background: hasActiveToken ? 'rgba(16, 185, 129, 0.15)' : 'rgba(99, 102, 241, 0.15)',
              color: hasActiveToken ? 'var(--color-allow)' : 'var(--color-accent)',
            }}
          >
            {hasActiveToken ? <ShieldCheck size={20} /> : <UserCheck size={20} />}
          </div>
          <div>
            <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Security & Authorization Context
            </h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Authoritative backend identity bound to executing requests
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div
            className={`status-pill ${hasActiveToken ? 'online' : 'offline'}`}
            style={{ fontSize: '0.75rem', padding: '0.2rem 0.65rem' }}
          >
            {hasActiveToken ? (
              <>
                <CheckCircle2 size={12} />
                <span>Bearer Authenticated</span>
              </>
            ) : (
              <>
                <ShieldAlert size={12} />
                <span>Unauthenticated / Dev Default</span>
              </>
            )}
          </div>

          <button
            type="button"
            className="secondary-btn"
            onClick={() => setShowTokenInput(!showTokenInput)}
            style={{ fontSize: '0.75rem', padding: '0.25rem 0.65rem' }}
          >
            <Key size={13} style={{ marginRight: '0.35rem' }} />
            {showTokenInput ? 'Hide Auth Controls' : 'Configure Bearer Token'}
          </button>
        </div>
      </div>

      {/* Security Context Metadata Pills */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '0.75rem',
          background: 'var(--bg-tertiary)',
          padding: '0.75rem 1rem',
          borderRadius: '8px',
        }}
      >
        <div>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Bound Principal
          </div>
          <div className="mono-text" style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            {callerPrincipalId}
          </div>
        </div>

        <div>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Tenant Scope
          </div>
          <div className="mono-text" style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--color-accent)' }}>
            {callerTenantId}
          </div>
        </div>

        <div>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Effective Roles
          </div>
          <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--color-allow)', display: 'flex', gap: '0.35rem' }}>
            {callerRoles.map((r) => (
              <span
                key={r}
                style={{
                  background: 'var(--color-allow-bg)',
                  border: '1px solid var(--color-allow-border)',
                  borderRadius: '4px',
                  padding: '0.1rem 0.4rem',
                  fontSize: '0.6875rem',
                }}
              >
                {r}
              </span>
            ))}
            {isGlobalAdmin && (
              <span
                style={{
                  background: 'rgba(239, 68, 68, 0.15)',
                  border: '1px solid rgba(239, 68, 68, 0.4)',
                  color: 'var(--color-block)',
                  borderRadius: '4px',
                  padding: '0.1rem 0.4rem',
                  fontSize: '0.6875rem',
                }}
              >
                GLOBAL_ADMIN
              </span>
            )}
          </div>
        </div>

        <div>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Authority Source
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
            Server-side Verification
          </div>
        </div>
      </div>

      {/* Ephemeral In-Memory Token Configuration Form */}
      {showTokenInput && (
        <form
          onSubmit={handleApplyToken}
          style={{
            borderTop: '1px solid var(--border-subtle)',
            paddingTop: '0.85rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.5rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <label htmlFor="admin-token-input" style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
              In-Memory Admin Bearer Token (Never stored in localStorage / sessionStorage):
            </label>
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
              Ephemeral React state only
            </span>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <input
              id="admin-token-input"
              type="password"
              value={localToken}
              onChange={(e) => setLocalToken(e.target.value)}
              placeholder="Paste Bearer token (e.g. ag_sec_...)"
              autoComplete="off"
              style={{
                flex: 1,
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '0.45rem 0.75rem',
                fontSize: '0.8125rem',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-mono)',
              }}
            />
            <button
              type="submit"
              className="primary-btn"
              style={{ padding: '0.45rem 1rem', fontSize: '0.8125rem', whiteSpace: 'nowrap' }}
            >
              Apply Token
            </button>
            {hasActiveToken && (
              <button
                type="button"
                className="secondary-btn"
                onClick={handleClearToken}
                style={{ padding: '0.45rem 0.85rem', fontSize: '0.8125rem', whiteSpace: 'nowrap' }}
              >
                Clear
              </button>
            )}
          </div>
        </form>
      )}
    </div>
  );
};
