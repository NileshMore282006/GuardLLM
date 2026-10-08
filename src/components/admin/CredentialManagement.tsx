import React, { useState, useEffect, useCallback } from 'react';
import { KeyRound, Plus, RefreshCw, PowerOff, ShieldAlert, Loader2, RotateCw } from 'lucide-react';
import { CredentialResponse, AdminConfirmationState } from '../../types/agentguard';
import { agentGuardApi, AgentGuardApiError } from '../../api/agentguard';
import { CredentialSecretReveal } from './CredentialSecretReveal';
import { AdminConfirmationDialog } from './AdminConfirmationDialog';

interface CredentialManagementProps {
  token?: string;
  isGlobalAdmin?: boolean;
}

export const CredentialManagement: React.FC<CredentialManagementProps> = ({
  token,
  isGlobalAdmin: _isGlobalAdmin = false,
}) => {
  const [credentials, setCredentials] = useState<CredentialResponse[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Create Modal State
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [targetPrincipalId, setTargetPrincipalId] = useState('');
  const [targetTenantId, setTargetTenantId] = useState('');
  const [description, setDescription] = useState('');
  const [expiresInSeconds, setExpiresInSeconds] = useState<number>(2592000); // 30 days default
  const [isCreating, setIsCreating] = useState(false);

  // One-Time Secret Reveal State (In-Memory React state only)
  const [revealedSecretData, setRevealedSecretData] = useState<{
    credentialId: string;
    secret: string;
    principalId: string;
    tenantId: string;
  } | null>(null);

  // Confirmation Dialog State
  const [confirmState, setConfirmState] = useState<AdminConfirmationState>({
    isOpen: false,
    operation: '',
    targetId: '',
    targetType: 'credential',
    securityImpact: '',
    onConfirm: async () => {},
  });

  const fetchCredentials = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const resp = await agentGuardApi.listCredentials(undefined, token);
      setCredentials(resp.credentials || []);
    } catch (err: any) {
      if (err instanceof AgentGuardApiError) {
        setError(err.message);
      } else {
        setError('Failed to fetch credentials from the backend.');
      }
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchCredentials();
  }, [fetchCredentials]);

  const handleCreateCredential = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetPrincipalId.trim()) return;

    setIsCreating(true);
    setError(null);
    setNotice(null);
    try {
      const created = await agentGuardApi.createCredential(
        {
          principal_id: targetPrincipalId.trim(),
          tenant_id: targetTenantId.trim() || undefined,
          description: description.trim() || undefined,
          expires_in_seconds: expiresInSeconds > 0 ? expiresInSeconds : undefined,
        },
        token
      );

      // Trigger one-time reveal
      setRevealedSecretData({
        credentialId: created.credential_id,
        secret: created.credential_secret || created.token,
        principalId: created.principal_id,
        tenantId: created.tenant_id,
      });

      setNotice(`Credential '${created.credential_id}' generated successfully.`);
      setShowCreateModal(false);
      setTargetPrincipalId('');
      setDescription('');
      fetchCredentials();
    } catch (err: any) {
      setError(err?.message || 'Failed to create credential.');
    } finally {
      setIsCreating(false);
    }
  };

  const promptRotateCredential = (c: CredentialResponse) => {
    setConfirmState({
      isOpen: true,
      operation: 'Rotate credential',
      targetId: c.credential_id,
      targetType: 'credential',
      securityImpact: `The current secret for credential '${c.credential_id}' will be revoked immediately and replaced by a newly issued secret. Applications using the previous token will fail closed.`,
      onConfirm: async () => {
        const rotated = await agentGuardApi.rotateCredential(c.credential_id, token);
        // Trigger one-time reveal for rotated secret
        setRevealedSecretData({
          credentialId: rotated.new_credential_id,
          secret: rotated.credential_secret || rotated.token,
          principalId: rotated.principal_id,
          tenantId: rotated.tenant_id,
        });
        setNotice(`Credential rotated successfully. New ID: '${rotated.new_credential_id}'.`);
        fetchCredentials();
      },
    });
  };

  const promptRevokeCredential = (c: CredentialResponse) => {
    setConfirmState({
      isOpen: true,
      operation: 'Revoke credential',
      targetId: c.credential_id,
      targetType: 'credential',
      securityImpact: `Credential '${c.credential_id}' will be permanently invalidated immediately. Any API request presenting this Bearer token will be rejected with 401 Unauthorized.`,
      onConfirm: async () => {
        await agentGuardApi.revokeCredential(c.credential_id, token);
        setNotice(`Credential '${c.credential_id}' revoked immediately.`);
        fetchCredentials();
      },
    });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <div style={{ padding: '0.45rem', borderRadius: '8px', background: 'rgba(245, 158, 11, 0.15)', color: 'var(--color-warn)' }}>
            <KeyRound size={20} />
          </div>
          <div>
            <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              API Credential Management
            </h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Cryptographically random Bearer tokens with constant-time verification. Secrets shown exactly once.
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            type="button"
            className="secondary-btn"
            onClick={fetchCredentials}
            disabled={isLoading}
            style={{ fontSize: '0.8125rem', padding: '0.45rem 0.85rem' }}
          >
            <RefreshCw size={14} className={isLoading ? 'spinner' : ''} style={{ marginRight: '0.35rem' }} />
            Refresh
          </button>
          <button
            type="button"
            className="primary-btn"
            onClick={() => setShowCreateModal(true)}
            style={{ fontSize: '0.8125rem', padding: '0.45rem 1rem' }}
          >
            <Plus size={15} style={{ marginRight: '0.35rem' }} />
            Issue Credential
          </button>
        </div>
      </div>

      {/* Notifications */}
      {notice && (
        <div className="alert-box success" role="status" style={{ margin: 0, padding: '0.75rem 1rem' }}>
          <div style={{ fontSize: '0.8125rem' }}>{notice}</div>
        </div>
      )}

      {error && (
        <div className="alert-box danger" role="alert" style={{ margin: 0, padding: '0.75rem 1rem' }}>
          <ShieldAlert size={18} style={{ flexShrink: 0 }} />
          <div style={{ fontSize: '0.8125rem' }}>{error}</div>
        </div>
      )}

      {/* Credentials Table */}
      <div className="glass-panel" style={{ overflow: 'hidden', borderRadius: '10px' }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8125rem' }}>
            <thead>
              <tr style={{ background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Credential ID</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Principal</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Tenant</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Status</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Description</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Created</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Expires</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600, textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && credentials.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
                      <Loader2 size={18} className="spinner" />
                      <span>Loading credentials from backend...</span>
                    </div>
                  </td>
                </tr>
              ) : credentials.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No credentials found in caller scope.
                  </td>
                </tr>
              ) : (
                credentials.map((c) => {
                  const isActive = c.status === 'ACTIVE';
                  const isRevoked = c.status === 'REVOKED';
                  return (
                    <tr
                      key={c.credential_id}
                      style={{
                        borderBottom: '1px solid var(--border-subtle)',
                        transition: 'background var(--transition-fast)',
                      }}
                    >
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span className="mono-text" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                          {c.credential_id}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span className="mono-text" style={{ color: 'var(--text-primary)' }}>
                          {c.principal_id}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span className="mono-text" style={{ color: 'var(--color-accent)' }}>
                          {c.tenant_id}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span
                          className={`status-pill ${isActive ? 'online' : 'offline'}`}
                          style={{
                            fontSize: '0.6875rem',
                            padding: '0.15rem 0.5rem',
                            background: isActive
                              ? 'var(--color-allow-bg)'
                              : isRevoked
                              ? 'rgba(239, 68, 68, 0.15)'
                              : 'rgba(245, 158, 11, 0.15)',
                            color: isActive
                              ? 'var(--color-allow)'
                              : isRevoked
                              ? 'var(--color-block)'
                              : 'var(--color-warn)',
                            borderColor: isActive
                              ? 'var(--color-allow-border)'
                              : isRevoked
                              ? 'rgba(239, 68, 68, 0.4)'
                              : 'rgba(245, 158, 11, 0.4)',
                          }}
                        >
                          {c.status}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)' }}>
                        {c.description || '—'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)' }}>
                        {c.created_at ? new Date(c.created_at * 1000).toLocaleDateString() : '—'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)' }}>
                        {c.expires_at ? new Date(c.expires_at * 1000).toLocaleDateString() : 'Never'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                        {isActive && (
                          <div style={{ display: 'inline-flex', gap: '0.35rem' }}>
                            <button
                              type="button"
                              className="secondary-btn"
                              title="Rotate Credential"
                              onClick={() => promptRotateCredential(c)}
                              style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                            >
                              <RotateCw size={13} style={{ marginRight: '0.25rem' }} />
                              Rotate
                            </button>
                            <button
                              type="button"
                              className="secondary-btn"
                              title="Revoke Credential"
                              onClick={() => promptRevokeCredential(c)}
                              style={{
                                padding: '0.25rem 0.5rem',
                                fontSize: '0.75rem',
                                color: 'var(--color-block)',
                                borderColor: 'rgba(239, 68, 68, 0.3)',
                              }}
                            >
                              <PowerOff size={13} style={{ marginRight: '0.25rem' }} />
                              Revoke
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Issue Credential Modal */}
      {showCreateModal && (
        <div
          role="dialog"
          aria-modal="true"
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
              padding: '1.5rem',
              borderRadius: '12px',
              background: 'var(--bg-secondary)',
              display: 'flex',
              flexDirection: 'column',
              gap: '1rem',
            }}
          >
            <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Issue New API Bearer Credential
            </h3>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
              A high-entropy secret will be generated server-side and returned exactly once. Secrets are hashed with PBKDF2/SHA-256.
            </p>

            <form onSubmit={handleCreateCredential} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label htmlFor="cred-principal-id" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                  Target Principal ID
                </label>
                <input
                  id="cred-principal-id"
                  type="text"
                  value={targetPrincipalId}
                  onChange={(e) => setTargetPrincipalId(e.target.value)}
                  placeholder="e.g. user-demo or service-demo"
                  required
                  style={{
                    width: '100%',
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    padding: '0.45rem 0.75rem',
                    fontSize: '0.8125rem',
                    color: 'var(--text-primary)',
                    fontFamily: 'var(--font-mono)',
                  }}
                />
              </div>

              <div>
                <label htmlFor="cred-tenant-id" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                  Tenant ID (Optional)
                </label>
                <input
                  id="cred-tenant-id"
                  type="text"
                  value={targetTenantId}
                  onChange={(e) => setTargetTenantId(e.target.value)}
                  placeholder="Defaults to caller tenant scope"
                  style={{
                    width: '100%',
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    padding: '0.45rem 0.75rem',
                    fontSize: '0.8125rem',
                    color: 'var(--text-primary)',
                    fontFamily: 'var(--font-mono)',
                  }}
                />
              </div>

              <div>
                <label htmlFor="cred-description" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                  Description / Label
                </label>
                <input
                  id="cred-description"
                  type="text"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="e.g. Automated CI/CD Agent Key"
                  style={{
                    width: '100%',
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    padding: '0.45rem 0.75rem',
                    fontSize: '0.8125rem',
                    color: 'var(--text-primary)',
                  }}
                />
              </div>

              <div>
                <label htmlFor="cred-expires-seconds" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                  Expiration TTL
                </label>
                <select
                  id="cred-expires-seconds"
                  value={expiresInSeconds}
                  onChange={(e) => setExpiresInSeconds(Number(e.target.value))}
                  style={{
                    width: '100%',
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    padding: '0.45rem 0.75rem',
                    fontSize: '0.8125rem',
                    color: 'var(--text-primary)',
                  }}
                >
                  <option value={86400}>1 Day (86,400s)</option>
                  <option value={604800}>7 Days (604,800s)</option>
                  <option value={2592000}>30 Days (2,592,000s)</option>
                  <option value={7776000}>90 Days (7,776,000s)</option>
                  <option value={0}>No Expiration</option>
                </select>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button
                  type="button"
                  className="secondary-btn"
                  onClick={() => setShowCreateModal(false)}
                  disabled={isCreating}
                  style={{ padding: '0.45rem 0.85rem', fontSize: '0.8125rem' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="primary-btn"
                  disabled={isCreating}
                  style={{ padding: '0.45rem 1.25rem', fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
                >
                  {isCreating && <Loader2 size={14} className="spinner" />}
                  <span>Generate Credential</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* One-Time Secret Reveal Modal */}
      {revealedSecretData && (
        <CredentialSecretReveal
          credentialId={revealedSecretData.credentialId}
          secret={revealedSecretData.secret}
          principalId={revealedSecretData.principalId}
          tenantId={revealedSecretData.tenantId}
          onDismiss={() => setRevealedSecretData(null)}
        />
      )}

      {/* Confirmation Dialog */}
      <AdminConfirmationDialog
        state={confirmState}
        onClose={() => setConfirmState((prev) => ({ ...prev, isOpen: false }))}
      />
    </div>
  );
};
