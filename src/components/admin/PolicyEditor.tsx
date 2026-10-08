import React, { useState } from 'react';
import { FileCode2, X, Loader2, AlertCircle } from 'lucide-react';
import { PolicyResponse, PolicyCreateRequest, PolicyUpdateRequest, PolicyAction } from '../../types/agentguard';
import { agentGuardApi } from '../../api/agentguard';

interface PolicyEditorProps {
  initialPolicy?: PolicyResponse | null;
  token?: string;
  isGlobalAdmin?: boolean;
  onSave: (policy: PolicyResponse) => void;
  onClose: () => void;
}

export const PolicyEditor: React.FC<PolicyEditorProps> = ({
  initialPolicy,
  token,
  isGlobalAdmin: _isGlobalAdmin = false,
  onSave,
  onClose,
}) => {
  const isEditing = Boolean(initialPolicy);

  const [name, setName] = useState(initialPolicy?.name || '');
  const [description, setDescription] = useState(initialPolicy?.description || '');
  const [action, setAction] = useState<PolicyAction>(initialPolicy?.action || 'REQUIRE_APPROVAL');
  const [principalScopeRaw, setPrincipalScopeRaw] = useState(
    (initialPolicy?.principal_scope || ['*']).join(', ')
  );
  const [toolScopeRaw, setToolScopeRaw] = useState(
    (initialPolicy?.tool_scope || ['*']).join(', ')
  );
  const [riskLevelsRaw, setRiskLevelsRaw] = useState(
    (initialPolicy?.risk_levels || ['*']).join(', ')
  );
  const [priority, setPriority] = useState<number>(initialPolicy?.priority ?? 100);
  const [enabled, setEnabled] = useState<boolean>(initialPolicy?.enabled ?? true);
  const [tenantId, setTenantId] = useState(initialPolicy?.tenant_id || '');

  const [serverVersion, setServerVersion] = useState<number>(initialPolicy?.version ?? 1);
  const [hasConflict, setHasConflict] = useState<boolean>(false);
  const [latestServerPolicy, setLatestServerPolicy] = useState<PolicyResponse | null>(null);

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const parseCommaList = (raw: string): string[] => {
    const items = raw
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    return items.length > 0 ? items : ['*'];
  };

  const handleReloadServer = async () => {
    if (!initialPolicy?.policy_id) return;
    try {
      const latest = await agentGuardApi.getPolicy(initialPolicy.policy_id, token);
      setLatestServerPolicy(latest);
      setServerVersion(latest.version);
    } catch {
      // ignore
    }
  };

  const handleApplyServerVersion = () => {
    if (latestServerPolicy) {
      setName(latestServerPolicy.name);
      setDescription(latestServerPolicy.description);
      setAction(latestServerPolicy.action as PolicyAction);
      setPrincipalScopeRaw((latestServerPolicy.principal_scope || ['*']).join(', '));
      setToolScopeRaw((latestServerPolicy.tool_scope || ['*']).join(', '));
      setRiskLevelsRaw((latestServerPolicy.risk_levels || ['*']).join(', '));
      setPriority(latestServerPolicy.priority);
      setEnabled(latestServerPolicy.enabled);
      setServerVersion(latestServerPolicy.version);
      setHasConflict(false);
      setError(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    setIsSubmitting(true);
    setError(null);

    const principalScope = parseCommaList(principalScopeRaw);
    const toolScope = parseCommaList(toolScopeRaw);
    const riskLevels = parseCommaList(riskLevelsRaw);

    try {
      if (isEditing && initialPolicy) {
        // Update existing policy
        const payload: PolicyUpdateRequest = {
          name: name.trim(),
          description: description.trim(),
          action,
          principal_scope: principalScope,
          tool_scope: toolScope,
          risk_levels: riskLevels,
          priority: Number(priority),
          enabled,
        };
        const updated = await agentGuardApi.updatePolicy(initialPolicy.policy_id, payload, token);
        onSave(updated);
      } else {
        // Create new policy
        const payload: PolicyCreateRequest = {
          name: name.trim(),
          description: description.trim(),
          action,
          principal_scope: principalScope,
          tool_scope: toolScope,
          risk_levels: riskLevels,
          priority: Number(priority),
          enabled,
          tenant_id: tenantId.trim() || undefined,
        };
        const created = await agentGuardApi.createPolicy(payload, token);
        onSave(created);
      }
    } catch (err: any) {
      if (err?.status === 409) {
        setHasConflict(true);
        setError('Policy conflict detected. A newer version exists on the server. Your draft has been preserved.');
        handleReloadServer();
      } else {
        setError(err?.message || 'Failed to persist security policy.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
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
          maxWidth: '580px',
          maxHeight: '90vh',
          overflowY: 'auto',
          padding: '1.5rem',
          borderRadius: '12px',
          background: 'var(--bg-secondary)',
          display: 'flex',
          flexDirection: 'column',
          gap: '1rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <div style={{ padding: '0.45rem', borderRadius: '8px', background: 'rgba(99, 102, 241, 0.15)', color: 'var(--color-accent)' }}>
              <FileCode2 size={20} />
            </div>
            <div>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                {isEditing ? `Edit Policy: ${initialPolicy?.name}` : 'Author Security Policy'}
              </h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                {isEditing ? `Current Version: ${initialPolicy?.version}` : 'Version 1 will be registered'}
              </span>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close policy editor"
            style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
          >
            <X size={18} />
          </button>
        </div>

        {/* Precedence Banner */}
        <div
          style={{
            background: 'var(--bg-tertiary)',
            padding: '0.6rem 0.85rem',
            borderRadius: '6px',
            fontSize: '0.75rem',
            color: 'var(--text-secondary)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <span>Evaluation Precedence:</span>
          <span className="mono-text" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
            <strong style={{ color: 'var(--color-block)' }}>DENY</strong> &gt;{' '}
            <strong style={{ color: 'var(--color-warn)' }}>REQUIRE_APPROVAL</strong> &gt;{' '}
            <strong style={{ color: 'var(--color-allow)' }}>ALLOW</strong> &gt; DEFAULT
          </span>
        </div>

        {error && (
          <div className="alert-box danger" role="alert" style={{ margin: 0, padding: '0.75rem' }}>
            <AlertCircle size={16} style={{ flexShrink: 0 }} />
            <div style={{ fontSize: '0.8125rem' }}>{error}</div>
          </div>
        )}

        {hasConflict && (
          <div
            style={{
              padding: '0.75rem 1rem',
              borderRadius: '8px',
              background: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid rgba(245, 158, 11, 0.4)',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.5rem',
              fontSize: '0.8125rem',
            }}
          >
            <div style={{ fontWeight: 600, color: 'var(--color-warn)' }}>
              Server Conflict Resolution (v{serverVersion})
            </div>
            <div style={{ color: 'var(--text-secondary)' }}>
              Another administrator committed changes while you were editing. You can inspect/apply the latest server version or modify your draft to re-attempt.
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.25rem' }}>
              <button
                type="button"
                className="secondary-btn"
                onClick={handleApplyServerVersion}
                style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}
              >
                Load Server Version (v{serverVersion})
              </button>
              <button
                type="button"
                className="secondary-btn"
                onClick={() => setHasConflict(false)}
                style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}
              >
                Dismiss & Keep Draft
              </button>
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          <div>
            <label htmlFor="policy-name" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
              Policy Name
            </label>
            <input
              id="policy-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Block High-Risk Financial Tools"
              required
              maxLength={100}
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
            <label htmlFor="policy-description" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
              Description
            </label>
            <input
              id="policy-description"
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="e.g. Enforces human review on send_email and delete_record tools"
              maxLength={500}
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

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div>
              <label htmlFor="policy-action" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                Enforcement Action
              </label>
              <select
                id="policy-action"
                value={action}
                onChange={(e) => setAction(e.target.value as PolicyAction)}
                style={{
                  width: '100%',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  padding: '0.45rem 0.75rem',
                  fontSize: '0.8125rem',
                  color: 'var(--text-primary)',
                  fontWeight: 600,
                }}
              >
                <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL</option>
                <option value="DENY">DENY</option>
                <option value="ALLOW">ALLOW</option>
              </select>
            </div>

            <div>
              <label htmlFor="policy-priority" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                Priority (0 - 10000, higher wins)
              </label>
              <input
                id="policy-priority"
                type="number"
                min={0}
                max={10000}
                value={priority}
                onChange={(e) => setPriority(Number(e.target.value))}
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
          </div>

          <div>
            <label htmlFor="policy-tool-scope" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
              Tool Scope (comma-separated tool names or * for all)
            </label>
            <input
              id="policy-tool-scope"
              type="text"
              value={toolScopeRaw}
              onChange={(e) => setToolScopeRaw(e.target.value)}
              placeholder="e.g. send_email, delete_record or *"
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

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div>
              <label htmlFor="policy-principal-scope" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                Principal Scope (comma-separated or *)
              </label>
              <input
                id="policy-principal-scope"
                type="text"
                value={principalScopeRaw}
                onChange={(e) => setPrincipalScopeRaw(e.target.value)}
                placeholder="e.g. user-demo, * "
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
              <label htmlFor="policy-risk-levels" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                Risk Levels (low, medium, high, critical, or *)
              </label>
              <input
                id="policy-risk-levels"
                type="text"
                value={riskLevelsRaw}
                onChange={(e) => setRiskLevelsRaw(e.target.value)}
                placeholder="e.g. high, critical or *"
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
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginTop: '0.25rem' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem', cursor: 'pointer', color: 'var(--text-secondary)' }}>
              <input
                type="checkbox"
                checked={enabled}
                onChange={(e) => setEnabled(e.target.checked)}
                style={{ cursor: 'pointer' }}
              />
              <span>Policy Enabled</span>
            </label>

            {!isEditing && (
              <div style={{ flex: 1 }}>
                <input
                  type="text"
                  value={tenantId}
                  onChange={(e) => setTenantId(e.target.value)}
                  placeholder="Target tenant (optional)"
                  style={{
                    width: '100%',
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    padding: '0.35rem 0.6rem',
                    fontSize: '0.75rem',
                    color: 'var(--text-primary)',
                    fontFamily: 'var(--font-mono)',
                  }}
                />
              </div>
            )}
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.75rem' }}>
            <button
              type="button"
              className="secondary-btn"
              onClick={onClose}
              disabled={isSubmitting}
              style={{ padding: '0.45rem 0.85rem', fontSize: '0.8125rem' }}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="primary-btn"
              disabled={isSubmitting}
              style={{ padding: '0.45rem 1.25rem', fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
            >
              {isSubmitting && <Loader2 size={14} className="spinner" />}
              <span>{isEditing ? 'Save Policy Changes' : 'Create Policy'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
