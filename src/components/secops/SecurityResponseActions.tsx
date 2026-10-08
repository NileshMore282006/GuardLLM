import React, { useState } from 'react';
import {
  ShieldAlert,
  PowerOff,
  CheckCircle2,
} from 'lucide-react';
import { SecOpsConfirmationState } from '../../types/agentguard';
import { agentGuardApi } from '../../api/agentguard';

interface SecurityResponseActionsProps {
  developerToken: string;
  onRequestConfirmation: (confirmState: SecOpsConfirmationState) => void;
  onRefreshAll: () => void;
}

export const SecurityResponseActions: React.FC<SecurityResponseActionsProps> = ({
  developerToken,
  onRequestConfirmation,
  onRefreshAll,
}) => {
  const [targetId, setTargetId] = useState('');
  const [actionType, setActionType] = useState<'CREDENTIAL_REVOKE' | 'PRINCIPAL_DISABLE' | 'TENANT_DISABLE' | 'POLICY_DELETE'>('CREDENTIAL_REVOKE');
  const [statusNotice, setStatusNotice] = useState<string | null>(null);
  const [errorNotice, setErrorNotice] = useState<string | null>(null);
  const [isBusy, setIsBusy] = useState(false);

  const handleTriggerAction = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetId.trim()) return;

    setStatusNotice(null);
    setErrorNotice(null);

    const trimmed = targetId.trim();

    if (actionType === 'CREDENTIAL_REVOKE') {
      onRequestConfirmation({
        isOpen: true,
        operation: 'Revoke API Credential',
        targetId: trimmed,
        targetType: 'credential',
        securityImpact: `Credential '${trimmed}' will be immediately and permanently revoked. Any caller presenting this token will fail closed with HTTP 401.`,
        onConfirm: async () => {
          setIsBusy(true);
          try {
            await agentGuardApi.revokeCredential(trimmed, developerToken);
            setStatusNotice(`Credential '${trimmed}' revoked successfully.`);
            setTargetId('');
            onRefreshAll();
          } catch (err: any) {
            setErrorNotice(err?.message || 'Failed to revoke credential.');
          } finally {
            setIsBusy(false);
          }
        },
      });
    } else if (actionType === 'PRINCIPAL_DISABLE') {
      onRequestConfirmation({
        isOpen: true,
        operation: 'Disable Security Principal',
        targetId: trimmed,
        targetType: 'principal',
        securityImpact: `Principal '${trimmed}' will be deactivated immediately. All API requests and approval actions associated with this principal will be rejected with HTTP 403.`,
        onConfirm: async () => {
          setIsBusy(true);
          try {
            await agentGuardApi.disablePrincipal(trimmed, developerToken);
            setStatusNotice(`Principal '${trimmed}' deactivated successfully.`);
            setTargetId('');
            onRefreshAll();
          } catch (err: any) {
            setErrorNotice(err?.message || 'Failed to disable principal.');
          } finally {
            setIsBusy(false);
          }
        },
      });
    } else if (actionType === 'TENANT_DISABLE') {
      onRequestConfirmation({
        isOpen: true,
        operation: 'Disable Security Tenant',
        targetId: trimmed,
        targetType: 'tenant',
        securityImpact: `Tenant '${trimmed}' will be deactivated immediately. All principals and API keys bound to this tenant will be blocked at the gateway boundary.`,
        onConfirm: async () => {
          setIsBusy(true);
          try {
            await agentGuardApi.disableTenant(trimmed, developerToken);
            setStatusNotice(`Tenant '${trimmed}' disabled successfully.`);
            setTargetId('');
            onRefreshAll();
          } catch (err: any) {
            setErrorNotice(err?.message || 'Failed to disable tenant.');
          } finally {
            setIsBusy(false);
          }
        },
      });
    } else if (actionType === 'POLICY_DELETE') {
      onRequestConfirmation({
        isOpen: true,
        operation: 'Delete Security Policy',
        targetId: trimmed,
        targetType: 'policy',
        securityImpact: `Policy '${trimmed}' will be marked as deleted in the authoritative policy registry. It will no longer be evaluated by Tool Guard or policy engines.`,
        onConfirm: async () => {
          setIsBusy(true);
          try {
            await agentGuardApi.deletePolicy(trimmed, developerToken);
            setStatusNotice(`Policy '${trimmed}' deleted successfully.`);
            setTargetId('');
            onRefreshAll();
          } catch (err: any) {
            setErrorNotice(err?.message || 'Failed to delete policy.');
          } finally {
            setIsBusy(false);
          }
        },
      });
    }
  };

  return (
    <div
      className="glass-panel"
      style={{
        borderRadius: '12px',
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      <div
        style={{
          padding: '1rem 1.25rem',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: 'var(--bg-tertiary)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <div
            style={{
              padding: '0.4rem',
              borderRadius: '8px',
              background: 'rgba(239, 68, 68, 0.15)',
              color: 'var(--color-block)',
            }}
          >
            <ShieldAlert size={18} />
          </div>
          <div>
            <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
              Authoritative Security Mitigation Controls
            </h3>
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
              Execute Real Backend-Authorized Incident Response Actions
            </span>
          </div>
        </div>
      </div>

      <div style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {statusNotice && (
          <div className="alert-box success" role="status" style={{ margin: 0, padding: '0.65rem 1rem' }}>
            <CheckCircle2 size={16} style={{ flexShrink: 0 }} />
            <div style={{ fontSize: '0.75rem' }}>{statusNotice}</div>
          </div>
        )}

        {errorNotice && (
          <div className="alert-box danger" role="alert" style={{ margin: 0, padding: '0.65rem 1rem' }}>
            <ShieldAlert size={16} style={{ flexShrink: 0 }} />
            <div style={{ fontSize: '0.75rem' }}>{errorNotice}</div>
          </div>
        )}

        <form onSubmit={handleTriggerAction} style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.75rem' }}>
            <div>
              <label htmlFor="sec-action-type" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
                Action Type
              </label>
              <select
                id="sec-action-type"
                value={actionType}
                onChange={(e) => setActionType(e.target.value as any)}
                style={{
                  width: '100%',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  padding: '0.45rem 0.65rem',
                  fontSize: '0.8125rem',
                  color: 'var(--text-primary)',
                }}
              >
                <option value="CREDENTIAL_REVOKE">Revoke API Credential (Invalidate Token)</option>
                <option value="PRINCIPAL_DISABLE">Disable Principal (Block User/Service)</option>
                <option value="TENANT_DISABLE">Disable Tenant (Isolate Organization)</option>
                <option value="POLICY_DELETE">Delete Security Policy (Remove Rule)</option>
              </select>
            </div>

            <div>
              <label htmlFor="sec-target-id" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>
                Target Identifier (Exact ID)
              </label>
              <input
                id="sec-target-id"
                type="text"
                value={targetId}
                onChange={(e) => setTargetId(e.target.value)}
                placeholder={
                  actionType === 'CREDENTIAL_REVOKE'
                    ? 'e.g. c_17c37eada3f37bd9'
                    : actionType === 'PRINCIPAL_DISABLE'
                    ? 'e.g. suspicious-user-id'
                    : actionType === 'TENANT_DISABLE'
                    ? 'e.g. compromised-tenant-id'
                    : 'e.g. pol_deny_destructive_02'
                }
                required
                style={{
                  width: '100%',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  padding: '0.45rem 0.65rem',
                  fontSize: '0.8125rem',
                  color: 'var(--text-primary)',
                  fontFamily: 'var(--font-mono)',
                }}
              />
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.25rem' }}>
            <button
              type="submit"
              className="primary-btn"
              disabled={isBusy || !targetId.trim()}
              style={{
                padding: '0.5rem 1.25rem',
                fontSize: '0.8125rem',
                background: 'var(--color-block)',
                borderColor: 'var(--color-block)',
                color: '#ffffff',
                fontWeight: 600,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.5rem',
              }}
            >
              <PowerOff size={14} />
              <span>Initiate Authoritative Mitigation</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
