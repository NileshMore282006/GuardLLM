import React, { useState, useEffect, useCallback } from 'react';
import { FileCode2, Plus, RefreshCw, Trash2, Edit3, ShieldAlert, Loader2 } from 'lucide-react';
import { PolicyResponse, AdminConfirmationState } from '../../types/agentguard';
import { agentGuardApi, AgentGuardApiError } from '../../api/agentguard';
import { PolicyEditor } from './PolicyEditor';
import { AdminConfirmationDialog } from './AdminConfirmationDialog';

interface PolicyManagementProps {
  token?: string;
  isGlobalAdmin?: boolean;
}

export const PolicyManagement: React.FC<PolicyManagementProps> = ({
  token,
  isGlobalAdmin = false,
}) => {
  const [policies, setPolicies] = useState<PolicyResponse[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Policy Editor State
  const [isEditorOpen, setIsEditorOpen] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<PolicyResponse | null>(null);

  // Confirmation Dialog State
  const [confirmState, setConfirmState] = useState<AdminConfirmationState>({
    isOpen: false,
    operation: '',
    targetId: '',
    targetType: 'policy',
    securityImpact: '',
    onConfirm: async () => {},
  });

  const fetchPolicies = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const resp = await agentGuardApi.listPolicies(true, token);
      setPolicies(resp.policies || []);
    } catch (err: any) {
      if (err instanceof AgentGuardApiError) {
        setError(err.message);
      } else {
        setError('Failed to fetch security policies from backend.');
      }
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchPolicies();
  }, [fetchPolicies]);

  const handleOpenCreate = () => {
    setEditingPolicy(null);
    setIsEditorOpen(true);
  };

  const handleOpenEdit = (p: PolicyResponse) => {
    setEditingPolicy(p);
    setIsEditorOpen(true);
  };

  const promptDeletePolicy = (p: PolicyResponse) => {
    setConfirmState({
      isOpen: true,
      operation: 'Delete policy',
      targetId: p.name,
      targetType: 'policy',
      securityImpact: `Policy '${p.name}' (ID: ${p.policy_id}) will be soft-deleted. It will no longer participate in evaluation, but its audit record is preserved.`,
      onConfirm: async () => {
        await agentGuardApi.deletePolicy(p.policy_id, token);
        setNotice(`Policy '${p.name}' soft-deleted successfully.`);
        fetchPolicies();
      },
    });
  };

  const handlePolicySaved = (saved: PolicyResponse) => {
    setIsEditorOpen(false);
    setNotice(`Policy '${saved.name}' persisted successfully (Version: ${saved.version}).`);
    fetchPolicies();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <div style={{ padding: '0.45rem', borderRadius: '8px', background: 'rgba(99, 102, 241, 0.15)', color: 'var(--color-accent)' }}>
            <FileCode2 size={20} />
          </div>
          <div>
            <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Security Policy Administration
            </h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Deterministic authorization rules for agent tools, principals, and risk tiers
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            type="button"
            className="secondary-btn"
            onClick={fetchPolicies}
            disabled={isLoading}
            style={{ fontSize: '0.8125rem', padding: '0.45rem 0.85rem' }}
          >
            <RefreshCw size={14} className={isLoading ? 'spinner' : ''} style={{ marginRight: '0.35rem' }} />
            Refresh
          </button>
          <button
            type="button"
            className="primary-btn"
            onClick={handleOpenCreate}
            style={{ fontSize: '0.8125rem', padding: '0.45rem 1rem' }}
          >
            <Plus size={15} style={{ marginRight: '0.35rem' }} />
            New Policy Rule
          </button>
        </div>
      </div>

      {/* Precedence Banner */}
      <div
        className="glass-panel"
        style={{
          padding: '0.75rem 1rem',
          borderRadius: '8px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '0.5rem',
          background: 'var(--bg-tertiary)',
        }}
      >
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
          Backend Evaluation Precedence:
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem' }}>
          <span
            style={{
              padding: '0.15rem 0.45rem',
              borderRadius: '4px',
              background: 'rgba(239, 68, 68, 0.2)',
              color: 'var(--color-block)',
              fontWeight: 700,
            }}
          >
            DENY
          </span>
          <span style={{ color: 'var(--text-muted)' }}>&gt;</span>
          <span
            style={{
              padding: '0.15rem 0.45rem',
              borderRadius: '4px',
              background: 'rgba(245, 158, 11, 0.2)',
              color: 'var(--color-warn)',
              fontWeight: 700,
            }}
          >
            REQUIRE_APPROVAL
          </span>
          <span style={{ color: 'var(--text-muted)' }}>&gt;</span>
          <span
            style={{
              padding: '0.15rem 0.45rem',
              borderRadius: '4px',
              background: 'var(--color-allow-bg)',
              color: 'var(--color-allow)',
              fontWeight: 700,
            }}
          >
            ALLOW
          </span>
          <span style={{ color: 'var(--text-muted)' }}>&gt;</span>
          <span style={{ color: 'var(--text-secondary)', fontStyle: 'italic' }}>DEFAULT</span>
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

      {/* Policies Table */}
      <div className="glass-panel" style={{ overflow: 'hidden', borderRadius: '10px' }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8125rem' }}>
            <thead>
              <tr style={{ background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Policy Name</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Action</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Priority</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Tool Scope</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Risk Levels</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Ver</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Status</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600, textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && policies.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
                      <Loader2 size={18} className="spinner" />
                      <span>Loading policies from backend...</span>
                    </div>
                  </td>
                </tr>
              ) : policies.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No security policies configured in caller scope.
                  </td>
                </tr>
              ) : (
                policies.map((p) => {
                  const isDeny = p.action === 'DENY';
                  const isRequireAppr = p.action === 'REQUIRE_APPROVAL';
                  const isDeleted = p.deleted;

                  return (
                    <tr
                      key={p.policy_id}
                      style={{
                        borderBottom: '1px solid var(--border-subtle)',
                        opacity: isDeleted ? 0.5 : 1,
                        transition: 'background var(--transition-fast)',
                      }}
                    >
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{p.name}</div>
                        {p.description && (
                          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>{p.description}</div>
                        )}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span
                          className="mono-text"
                          style={{
                            fontWeight: 700,
                            fontSize: '0.75rem',
                            padding: '0.15rem 0.45rem',
                            borderRadius: '4px',
                            background: isDeny
                              ? 'rgba(239, 68, 68, 0.2)'
                              : isRequireAppr
                              ? 'rgba(245, 158, 11, 0.2)'
                              : 'var(--color-allow-bg)',
                            color: isDeny
                              ? 'var(--color-block)'
                              : isRequireAppr
                              ? 'var(--color-warn)'
                              : 'var(--color-allow)',
                            border: `1px solid ${
                              isDeny
                                ? 'rgba(239, 68, 68, 0.4)'
                                : isRequireAppr
                                ? 'rgba(245, 158, 11, 0.4)'
                                : 'var(--color-allow-border)'
                            }`,
                          }}
                        >
                          {p.action}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span className="mono-text" style={{ color: 'var(--text-secondary)' }}>
                          {p.priority}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
                          {(p.tool_scope || ['*']).map((ts, idx) => (
                            <span
                              key={idx}
                              className="mono-text"
                              style={{
                                fontSize: '0.6875rem',
                                padding: '0.1rem 0.35rem',
                                background: 'var(--bg-tertiary)',
                                borderRadius: '4px',
                                color: 'var(--color-accent)',
                              }}
                            >
                              {ts}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
                          {(p.risk_levels || ['*']).map((rl, idx) => (
                            <span
                              key={idx}
                              className="mono-text"
                              style={{
                                fontSize: '0.6875rem',
                                padding: '0.1rem 0.35rem',
                                background: 'var(--bg-tertiary)',
                                borderRadius: '4px',
                                color: 'var(--text-secondary)',
                              }}
                            >
                              {rl}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span className="mono-text" style={{ color: 'var(--text-muted)' }}>
                          v{p.version}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        {isDeleted ? (
                          <span
                            className="status-pill offline"
                            style={{ fontSize: '0.6875rem', padding: '0.15rem 0.5rem' }}
                          >
                            DELETED
                          </span>
                        ) : p.enabled ? (
                          <span
                            className="status-pill online"
                            style={{ fontSize: '0.6875rem', padding: '0.15rem 0.5rem' }}
                          >
                            ENABLED
                          </span>
                        ) : (
                          <span
                            className="status-pill offline"
                            style={{ fontSize: '0.6875rem', padding: '0.15rem 0.5rem' }}
                          >
                            DISABLED
                          </span>
                        )}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                        {!isDeleted && (
                          <div style={{ display: 'inline-flex', gap: '0.35rem' }}>
                            <button
                              type="button"
                              className="secondary-btn"
                              title="Edit Policy"
                              onClick={() => handleOpenEdit(p)}
                              style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                            >
                              <Edit3 size={13} />
                            </button>
                            <button
                              type="button"
                              className="secondary-btn"
                              title="Delete Policy"
                              onClick={() => promptDeletePolicy(p)}
                              style={{
                                padding: '0.25rem 0.5rem',
                                fontSize: '0.75rem',
                                color: 'var(--color-block)',
                                borderColor: 'rgba(239, 68, 68, 0.3)',
                              }}
                            >
                              <Trash2 size={13} />
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

      {/* Policy Editor Modal */}
      {isEditorOpen && (
        <PolicyEditor
          initialPolicy={editingPolicy}
          token={token}
          isGlobalAdmin={isGlobalAdmin}
          onSave={handlePolicySaved}
          onClose={() => setIsEditorOpen(false)}
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
