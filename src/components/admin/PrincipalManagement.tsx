import React, { useState, useEffect, useCallback } from 'react';
import { Users, Plus, RefreshCw, PowerOff, CheckCircle, ShieldAlert, Loader2, Edit3 } from 'lucide-react';
import { PrincipalResponse, PrincipalRole, PrincipalType, AdminConfirmationState } from '../../types/agentguard';
import { agentGuardApi, AgentGuardApiError } from '../../api/agentguard';
import { AdminConfirmationDialog } from './AdminConfirmationDialog';

interface PrincipalManagementProps {
  token?: string;
  isGlobalAdmin?: boolean;
}

export const PrincipalManagement: React.FC<PrincipalManagementProps> = ({
  token,
  isGlobalAdmin: _isGlobalAdmin = false,
}) => {
  const [principals, setPrincipals] = useState<PrincipalResponse[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Create Modal State
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newPrincipalId, setNewPrincipalId] = useState('');
  const [newPrincipalType, setNewPrincipalType] = useState<PrincipalType>('user');
  const [newTenantId, setNewTenantId] = useState('');
  const [newRoles, setNewRoles] = useState<PrincipalRole[]>(['user']);
  const [isCreating, setIsCreating] = useState(false);

  // Edit Modal State
  const [editingPrincipal, setEditingPrincipal] = useState<PrincipalResponse | null>(null);
  const [editRoles, setEditRoles] = useState<PrincipalRole[]>([]);
  const [editType, setEditType] = useState<PrincipalType>('user');
  const [editStatus, setEditStatus] = useState<'ACTIVE' | 'DISABLED'>('ACTIVE');
  const [isUpdating, setIsUpdating] = useState(false);

  // Confirmation Dialog State
  const [confirmState, setConfirmState] = useState<AdminConfirmationState>({
    isOpen: false,
    operation: '',
    targetId: '',
    targetType: 'principal',
    securityImpact: '',
    onConfirm: async () => {},
  });

  const availableRoles: PrincipalRole[] = ['user', 'operator', 'admin', 'global_admin'];
  const availableTypes: PrincipalType[] = ['user', 'service', 'admin', 'global_admin'];

  const fetchPrincipals = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const resp = await agentGuardApi.listPrincipals(undefined, token);
      setPrincipals(resp.principals || []);
    } catch (err: any) {
      if (err instanceof AgentGuardApiError) {
        setError(err.message);
      } else {
        setError('Failed to fetch principals from the backend.');
      }
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchPrincipals();
  }, [fetchPrincipals]);

  const handleCreatePrincipal = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPrincipalId.trim()) return;

    setIsCreating(true);
    setError(null);
    setNotice(null);
    try {
      const created = await agentGuardApi.createPrincipal(
        {
          principal_id: newPrincipalId.trim(),
          principal_type: newPrincipalType,
          tenant_id: newTenantId.trim() || undefined,
          roles: newRoles,
        },
        token
      );
      setNotice(`Principal '${created.principal_id}' created successfully.`);
      setShowCreateModal(false);
      setNewPrincipalId('');
      setNewRoles(['user']);
      setNewTenantId('');
      fetchPrincipals();
    } catch (err: any) {
      setError(err?.message || 'Failed to create principal.');
    } finally {
      setIsCreating(false);
    }
  };

  const handleUpdatePrincipal = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingPrincipal) return;

    setIsUpdating(true);
    setError(null);
    setNotice(null);
    try {
      const updated = await agentGuardApi.updatePrincipal(
        editingPrincipal.principal_id,
        {
          principal_type: editType,
          roles: editRoles,
          status: editStatus,
        },
        token
      );
      setNotice(`Principal '${updated.principal_id}' updated successfully.`);
      setEditingPrincipal(null);
      fetchPrincipals();
    } catch (err: any) {
      setError(err?.message || 'Failed to update principal.');
    } finally {
      setIsUpdating(false);
    }
  };

  const promptDisablePrincipal = (p: PrincipalResponse) => {
    setConfirmState({
      isOpen: true,
      operation: 'Disable principal',
      targetId: p.principal_id,
      targetType: 'principal',
      securityImpact: `Principal '${p.principal_id}' will immediately be prohibited from authenticating. All associated credentials will fail closed.`,
      onConfirm: async () => {
        await agentGuardApi.disablePrincipal(p.principal_id, token);
        setNotice(`Principal '${p.principal_id}' disabled successfully.`);
        fetchPrincipals();
      },
    });
  };

  const promptEnablePrincipal = (p: PrincipalResponse) => {
    setConfirmState({
      isOpen: true,
      operation: 'Enable principal',
      targetId: p.principal_id,
      targetType: 'principal',
      securityImpact: `Principal '${p.principal_id}' account will be restored to active status.`,
      onConfirm: async () => {
        await agentGuardApi.enablePrincipal(p.principal_id, token);
        setNotice(`Principal '${p.principal_id}' enabled successfully.`);
        fetchPrincipals();
      },
    });
  };

  const toggleRoleSelection = (role: PrincipalRole, current: PrincipalRole[], setter: (r: PrincipalRole[]) => void) => {
    if (current.includes(role)) {
      if (current.length === 1) return; // Must have at least 1 role
      setter(current.filter((r) => r !== role));
    } else {
      setter([...current, role]);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <div style={{ padding: '0.45rem', borderRadius: '8px', background: 'rgba(99, 102, 241, 0.15)', color: 'var(--color-accent)' }}>
            <Users size={20} />
          </div>
          <div>
            <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Principal & Identity Management
            </h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Security principals, type categories, and role assignment
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            type="button"
            className="secondary-btn"
            onClick={fetchPrincipals}
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
            Register Principal
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

      {/* Principals Table */}
      <div className="glass-panel" style={{ overflow: 'hidden', borderRadius: '10px' }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8125rem' }}>
            <thead>
              <tr style={{ background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Principal ID</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Type</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Tenant</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Assigned Roles</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Status</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Created</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600, textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && principals.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
                      <Loader2 size={18} className="spinner" />
                      <span>Loading principals from backend...</span>
                    </div>
                  </td>
                </tr>
              ) : principals.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No principals found in caller scope.
                  </td>
                </tr>
              ) : (
                principals.map((p) => {
                  const isActive = p.status === 'ACTIVE';
                  return (
                    <tr
                      key={p.principal_id}
                      style={{
                        borderBottom: '1px solid var(--border-subtle)',
                        transition: 'background var(--transition-fast)',
                      }}
                    >
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span className="mono-text" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                          {p.principal_id}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span
                          style={{
                            padding: '0.15rem 0.45rem',
                            borderRadius: '4px',
                            background: 'var(--bg-tertiary)',
                            fontSize: '0.6875rem',
                            color: 'var(--text-secondary)',
                          }}
                        >
                          {p.principal_type}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span className="mono-text" style={{ color: 'var(--color-accent)' }}>
                          {p.tenant_id}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
                          {(p.roles || []).map((r) => (
                            <span
                              key={r}
                              className="mono-text"
                              style={{
                                padding: '0.1rem 0.4rem',
                                borderRadius: '4px',
                                fontSize: '0.6875rem',
                                background: r === 'global_admin' ? 'rgba(239, 68, 68, 0.15)' : 'var(--color-allow-bg)',
                                color: r === 'global_admin' ? 'var(--color-block)' : 'var(--color-allow)',
                                border: `1px solid ${r === 'global_admin' ? 'rgba(239, 68, 68, 0.4)' : 'var(--color-allow-border)'}`,
                              }}
                            >
                              {r}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span
                          className={`status-pill ${isActive ? 'online' : 'offline'}`}
                          style={{ fontSize: '0.6875rem', padding: '0.15rem 0.5rem' }}
                        >
                          {p.status}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)' }}>
                        {p.created_at ? new Date(p.created_at * 1000).toLocaleString() : '—'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: '0.35rem' }}>
                          <button
                            type="button"
                            className="secondary-btn"
                            title="Edit Principal"
                            onClick={() => {
                              setEditingPrincipal(p);
                              setEditRoles(p.roles as PrincipalRole[]);
                              setEditType(p.principal_type as PrincipalType);
                              setEditStatus(p.status as 'ACTIVE' | 'DISABLED');
                            }}
                            style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                          >
                            <Edit3 size={13} />
                          </button>
                          {isActive ? (
                            <button
                              type="button"
                              className="secondary-btn"
                              title="Disable Principal"
                              onClick={() => promptDisablePrincipal(p)}
                              style={{
                                padding: '0.25rem 0.5rem',
                                fontSize: '0.75rem',
                                color: 'var(--color-block)',
                                borderColor: 'rgba(239, 68, 68, 0.3)',
                              }}
                            >
                              <PowerOff size={13} />
                            </button>
                          ) : (
                            <button
                              type="button"
                              className="secondary-btn"
                              title="Enable Principal"
                              onClick={() => promptEnablePrincipal(p)}
                              style={{
                                padding: '0.25rem 0.5rem',
                                fontSize: '0.75rem',
                                color: 'var(--color-allow)',
                                borderColor: 'rgba(16, 185, 129, 0.3)',
                              }}
                            >
                              <CheckCircle size={13} />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Register Principal Modal */}
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
              Register Security Principal
            </h3>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
              Creates an immutable identity record bound to a tenant. Roles are enforced server-side.
            </p>

            <form onSubmit={handleCreatePrincipal} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label htmlFor="create-principal-id" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                  Principal ID
                </label>
                <input
                  id="create-principal-id"
                  type="text"
                  value={newPrincipalId}
                  onChange={(e) => setNewPrincipalId(e.target.value)}
                  placeholder="e.g. sec-analyst-01"
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

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div>
                  <label htmlFor="create-principal-type" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                    Principal Type
                  </label>
                  <select
                    id="create-principal-type"
                    value={newPrincipalType}
                    onChange={(e) => setNewPrincipalType(e.target.value as PrincipalType)}
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
                    {availableTypes.map((t) => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label htmlFor="create-tenant-id" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                    Tenant ID (Optional)
                  </label>
                  <input
                    id="create-tenant-id"
                    type="text"
                    value={newTenantId}
                    onChange={(e) => setNewTenantId(e.target.value)}
                    placeholder="Defaults to caller tenant"
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
                <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                  Assign Roles (Select at least one)
                </label>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  {availableRoles.map((r) => {
                    const isSelected = newRoles.includes(r);
                    return (
                      <button
                        type="button"
                        key={r}
                        onClick={() => toggleRoleSelection(r, newRoles, setNewRoles)}
                        style={{
                          padding: '0.3rem 0.65rem',
                          borderRadius: '6px',
                          fontSize: '0.75rem',
                          fontFamily: 'var(--font-mono)',
                          cursor: 'pointer',
                          background: isSelected ? 'var(--color-accent)' : 'var(--bg-tertiary)',
                          color: isSelected ? '#ffffff' : 'var(--text-secondary)',
                          border: `1px solid ${isSelected ? 'var(--color-accent)' : 'var(--border-subtle)'}`,
                        }}
                      >
                        {r}
                      </button>
                    );
                  })}
                </div>
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
                  <span>Register Principal</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Principal Modal */}
      {editingPrincipal && (
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
              Edit Principal: <span className="mono-text">{editingPrincipal.principal_id}</span>
            </h3>

            <form onSubmit={handleUpdatePrincipal} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div>
                  <label htmlFor="edit-principal-type" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                    Type
                  </label>
                  <select
                    id="edit-principal-type"
                    value={editType}
                    onChange={(e) => setEditType(e.target.value as PrincipalType)}
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
                    {availableTypes.map((t) => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label htmlFor="edit-principal-status" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                    Status
                  </label>
                  <select
                    id="edit-principal-status"
                    value={editStatus}
                    onChange={(e) => setEditStatus(e.target.value as 'ACTIVE' | 'DISABLED')}
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
                    <option value="ACTIVE">ACTIVE</option>
                    <option value="DISABLED">DISABLED</option>
                  </select>
                </div>
              </div>

              <div>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                  Assigned Roles
                </label>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  {availableRoles.map((r) => {
                    const isSelected = editRoles.includes(r);
                    return (
                      <button
                        type="button"
                        key={r}
                        onClick={() => toggleRoleSelection(r, editRoles, setEditRoles)}
                        style={{
                          padding: '0.3rem 0.65rem',
                          borderRadius: '6px',
                          fontSize: '0.75rem',
                          fontFamily: 'var(--font-mono)',
                          cursor: 'pointer',
                          background: isSelected ? 'var(--color-accent)' : 'var(--bg-tertiary)',
                          color: isSelected ? '#ffffff' : 'var(--text-secondary)',
                          border: `1px solid ${isSelected ? 'var(--color-accent)' : 'var(--border-subtle)'}`,
                        }}
                      >
                        {r}
                      </button>
                    );
                  })}
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button
                  type="button"
                  className="secondary-btn"
                  onClick={() => setEditingPrincipal(null)}
                  disabled={isUpdating}
                  style={{ padding: '0.45rem 0.85rem', fontSize: '0.8125rem' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="primary-btn"
                  disabled={isUpdating}
                  style={{ padding: '0.45rem 1.25rem', fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
                >
                  {isUpdating && <Loader2 size={14} className="spinner" />}
                  <span>Save Changes</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Confirmation Dialog */}
      <AdminConfirmationDialog
        state={confirmState}
        onClose={() => setConfirmState((prev) => ({ ...prev, isOpen: false }))}
      />
    </div>
  );
};
