/**
 * AgentGuard Privileged Route Guard (Frontend v0.7)
 * Enforces authentication and role verification before rendering privileged interfaces
 * (Administration, Security Operations, Audit Explorer, Policy Manager).
 * 
 * Prevents unauthorized viewing of sensitive controls when a user directly navigates to a tab.
 */

import React, { useState } from 'react';
import { ShieldAlert, KeyRound, ArrowLeft, Loader2 } from 'lucide-react';
import { useSession } from '../../context/SessionContext';
import { UserRole } from '../../types/agentguard';
import { checkPermission, getPermissionExplanation } from '../../utils/authorization';

interface RouteGuardProps {
  requiredCapability?: string;
  requiredRole?: UserRole;
  fallbackModeName?: string;
  onNavigateHome?: () => void;
  children: React.ReactNode;
}

export const RouteGuard: React.FC<RouteGuardProps> = ({
  requiredCapability,
  requiredRole,
  fallbackModeName = 'Security Playground',
  onNavigateHome,
  children,
}) => {
  const { sessionState, tokenPresent, roles, principalId, setToken } = useSession();
  const [tokenInput, setTokenInput] = useState('');
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);

  const handleAuthenticate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tokenInput.trim()) return;

    setIsAuthenticating(true);
    setAuthError(null);
    try {
      await setToken(tokenInput.trim());
      setTokenInput('');
    } catch (err: any) {
      setAuthError(err?.message || 'Authentication failed. Please verify token.');
    } finally {
      setIsAuthenticating(false);
    }
  };

  // Case 1: Unauthenticated
  if (!tokenPresent || sessionState === 'UNAUTHENTICATED') {
    return (
      <div
        className="glass-panel"
        style={{
          maxWidth: '540px',
          margin: '3rem auto',
          padding: '2rem',
          borderRadius: '12px',
          textAlign: 'center',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '1.25rem',
        }}
        data-testid="route-guard-unauthenticated"
      >
        <div
          style={{
            width: '48px',
            height: '48px',
            borderRadius: '50%',
            background: 'rgba(239, 68, 68, 0.15)',
            color: 'var(--color-danger)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <KeyRound size={24} />
        </div>

        <div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
            Authentication Required
          </h2>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', maxWidth: '420px', margin: '0 auto' }}>
            This section provides privileged security operations and administrative controls. Please supply an authorized AgentGuard API token to proceed.
          </p>
        </div>

        {authError && (
          <div className="alert-box danger" role="alert" style={{ fontSize: '0.8125rem', width: '100%' }}>
            {authError}
          </div>
        )}

        <form onSubmit={handleAuthenticate} style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <input
            type="password"
            placeholder="ag_c_...••••••••"
            value={tokenInput}
            onChange={(e) => setTokenInput(e.target.value)}
            disabled={isAuthenticating}
            className="text-input"
            data-testid="route-guard-token-input"
            style={{ fontFamily: 'monospace', fontSize: '0.8125rem' }}
          />

          <button
            type="submit"
            className="primary-btn"
            disabled={isAuthenticating || !tokenInput.trim()}
            data-testid="route-guard-authenticate-btn"
            style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
          >
            {isAuthenticating ? (
              <>
                <Loader2 size={16} className="spin" />
                <span>Authenticating with Gateway…</span>
              </>
            ) : (
              <span>Authenticate Operator Session</span>
            )}
          </button>
        </form>

        {onNavigateHome && (
          <button
            type="button"
            className="secondary-btn"
            onClick={onNavigateHome}
            style={{ fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <ArrowLeft size={14} />
            <span>Return to {fallbackModeName}</span>
          </button>
        )}
      </div>
    );
  }

  // Case 2: Check capability authorization if specified
  const hasCapability = requiredCapability ? checkPermission(requiredCapability, roles) : true;
  const hasRolePermission = requiredRole ? roles.includes(requiredRole) : true;

  if (!hasCapability || !hasRolePermission) {
    const explanation = requiredCapability ? getPermissionExplanation(requiredCapability, roles) : 'Requires elevated role.';

    return (
      <div
        className="glass-panel"
        style={{
          maxWidth: '540px',
          margin: '3rem auto',
          padding: '2rem',
          borderRadius: '12px',
          textAlign: 'center',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '1.25rem',
        }}
        data-testid="route-guard-forbidden"
      >
        <div
          style={{
            width: '48px',
            height: '48px',
            borderRadius: '50%',
            background: 'rgba(245, 158, 11, 0.15)',
            color: 'var(--color-warn)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <ShieldAlert size={24} />
        </div>

        <div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
            Elevated Authorization Required
          </h2>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', maxWidth: '420px', margin: '0 auto' }}>
            Your current authenticated session for principal <strong>'{principalId}'</strong> (roles: [{roles.join(', ')}]) does not hold sufficient privileges for this section.
          </p>
        </div>

        <div
          style={{
            padding: '0.75rem 1rem',
            background: 'var(--bg-tertiary)',
            borderRadius: '8px',
            fontSize: '0.8125rem',
            color: 'var(--color-warn)',
            width: '100%',
          }}
        >
          {explanation}
        </div>

        {onNavigateHome && (
          <button
            type="button"
            className="secondary-btn"
            onClick={onNavigateHome}
            style={{ fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <ArrowLeft size={14} />
            <span>Return to {fallbackModeName}</span>
          </button>
        )}
      </div>
    );
  }

  // Permitted: render children
  return <>{children}</>;
};
