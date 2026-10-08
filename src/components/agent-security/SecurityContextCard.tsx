import React, { useState } from 'react';
import { UserCheck, Key } from 'lucide-react';

interface SecurityContextCardProps {
  developerToken: string;
  setDeveloperToken: (token: string) => void;
  policyStatus?: string;
}

export const SecurityContextCard: React.FC<SecurityContextCardProps> = ({
  developerToken,
  setDeveloperToken,
  policyStatus = 'managed by AgentGuard',
}) => {
  const [showTokenInput, setShowTokenInput] = useState(false);

  // Derive display context: server is authoritative
  const isTokenSet = Boolean(developerToken.trim());
  const displayPrincipal = isTokenSet ? 'operator-authenticated' : 'user-demo';
  const displayRole = isTokenSet ? 'operator / admin' : 'user';
  const displayTenant = 'default';

  return (
    <div className="glass-panel" style={{ padding: '1rem 1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <UserCheck size={16} style={{ color: 'var(--color-accent)' }} />
          <h3 style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Security Context & Identity
          </h3>
        </div>

        <button
          type="button"
          onClick={() => setShowTokenInput(!showTokenInput)}
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
          <Key size={12} /> {showTokenInput ? 'Hide Dev Auth' : 'Set Dev Token'}
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.5rem', fontSize: '0.75rem' }}>
        <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.45rem 0.6rem', borderRadius: 'var(--radius-sm)' }}>
          <span style={{ color: 'var(--text-muted)' }}>Tenant:</span>
          <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
            {displayTenant}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.45rem 0.6rem', borderRadius: 'var(--radius-sm)' }}>
          <span style={{ color: 'var(--text-muted)' }}>Principal:</span>
          <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
            {displayPrincipal}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.45rem 0.6rem', borderRadius: 'var(--radius-sm)' }}>
          <span style={{ color: 'var(--text-muted)' }}>Assigned Role:</span>
          <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
            {displayRole}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.45rem 0.6rem', borderRadius: 'var(--radius-sm)' }}>
          <span style={{ color: 'var(--text-muted)' }}>Policy Engine:</span>
          <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#a5b4fc' }}>
            {policyStatus}
          </div>
        </div>
      </div>

      {showTokenInput && (
        <div
          style={{
            marginTop: '0.25rem',
            paddingTop: '0.5rem',
            borderTop: '1px solid var(--border-subtle)',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.35rem',
          }}
        >
          <label htmlFor="dev-token-input" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Development Bearer Token (In-memory only; never persisted to localStorage):
          </label>
          <input
            id="dev-token-input"
            type="password"
            value={developerToken}
            onChange={(e) => setDeveloperToken(e.target.value)}
            placeholder="Optional operator/admin token for RBAC testing..."
            autoComplete="off"
            style={{
              background: 'var(--bg-input)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              padding: '0.45rem 0.65rem',
              color: 'var(--text-primary)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.75rem',
              outline: 'none',
            }}
          />
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-dim)' }}>
            Server is authoritative for authentication. Headers are validated strictly by the FastAPI backend.
          </div>
        </div>
      )}
    </div>
  );
};
