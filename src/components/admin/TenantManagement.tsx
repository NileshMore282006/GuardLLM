import React, { useState, useEffect, useCallback } from 'react';
import { Building2, Plus, RefreshCw, PowerOff, CheckCircle, ShieldAlert, Loader2, Edit3 } from 'lucide-react';
import { TenantResponse, AdminConfirmationState } from '../../types/agentguard';
import { agentGuardApi, AgentGuardApiError } from '../../api/agentguard';
import { AdminConfirmationDialog } from './AdminConfirmationDialog';

interface TenantManagementProps {
  token?: string;
  isGlobalAdmin?: boolean;
}

export const TenantManagement: React.FC<TenantManagementProps> = ({
  token,
  isGlobalAdmin: _isGlobalAdmin = false,
}) => {
  const [tenants, setTenants] = useState<TenantResponse[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Create Modal State
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTenantId, setNewTenantId] = useState('');
  const [newTenantName, setNewTenantName] = useState('');
  const [isCreating, setIsCreating] = useState(false);

  // Edit Modal State
  const [editingTenant, setEditingTenant] = useState<TenantResponse | null>(null);
  const [editName, setEditName] = useState('');
  const [editStatus, setEditStatus] = useState<'ACTIVE' | 'DISABLED'>('ACTIVE');
  const [isUpdating, setIsUpdating] = useState(false);

  // Confirmation Dialog State
  const [confirmState, setConfirmState] = useState<AdminConfirmationState>({
    isOpen: false,
    operation: '',
    targetId: '',
    targetType: 'tenant',
    securityImpact: '',
    onConfirm: async () => {},
  });

  const fetchTenants = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const resp = await agentGuardApi.listTenants(token);
      setTenants(resp.tenants || []);
    } catch (err: any) {
      if (err instanceof AgentGuardApiError) {
        setError(err.message);
      } else {
        setError('Failed to fetch tenants from the backend.');
      }
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchTenants();
  }, [fetchTenants]);

  const handleCreateTenant = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTenantId.trim() || !newTenantName.trim()) return;

    setIsCreating(true);
    setError(null);
    setNotice(null);
    try {
      const created = await agentGuardApi.createTenant(
        { tenant_id: newTenantId.trim(), name: newTenantName.trim() },
        token
      );
      setNotice(`Tenant '${created.tenant_id}' created successfully.`);
      setShowCreateModal(false);
      setNewTenantId('');
      setNewTenantName('');
      fetchTenants();
    } catch (err: any) {
      setError(err?.message || 'Failed to create tenant.');
    } finally {
      setIsCreating(false);
    }
  };

  const handleUpdateTenant = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingTenant) return;

    setIsUpdating(true);
    setError(null);
    setNotice(null);
    try {
      const updated = await agentGuardApi.updateTenant(
        editingTenant.tenant_id,
        { name: editName.trim(), status: editStatus },
        token
      );
      setNotice(`Tenant '${updated.tenant_id}' updated successfully.`);
      setEditingTenant(null);
      fetchTenants();
    } catch (err: any) {
      setError(err?.message || 'Failed to update tenant.');
    } finally {
      setIsUpdating(false);
    }
  };

  const promptDisableTenant = (tenant: TenantResponse) => {
    setConfirmState({
      isOpen: true,
      operation: 'Disable tenant',
      targetId: tenant.tenant_id,
      targetType: 'tenant',
      securityImpact: `All incoming requests bound to tenant '${tenant.tenant_id}' will immediately fail closed with 403 Forbidden.`,
      onConfirm: async () => {
        await agentGuardApi.disableTenant(tenant.tenant_id, token);
        setNotice(`Tenant '${tenant.tenant_id}' disabled successfully.`);
        fetchTenants();
      },
    });
  };

  const promptEnableTenant = (tenant: TenantResponse) => {
    setConfirmState({
      isOpen: true,
      operation: 'Enable tenant',
      targetId: tenant.tenant_id,
      targetType: 'tenant',
      securityImpact: `Requests bound to tenant '${tenant.tenant_id}' will once again be permitted to evaluate security controls.`,
      onConfirm: async () => {
        await agentGuardApi.enableTenant(tenant.tenant_id, token);
        setNotice(`Tenant '${tenant.tenant_id}' enabled successfully.`);
        fetchTenants();
      },
    });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <div style={{ padding: '0.45rem', borderRadius: '8px', background: 'rgba(99, 102, 241, 0.15)', color: 'var(--color-accent)' }}>
            <Building2 size={20} />
          </div>
          <div>
            <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Tenant Administration
            </h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Isolated security boundaries. Global Admin required for provisioning.
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            type="button"
            className="secondary-btn"
            onClick={fetchTenants}
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
            Provision Tenant
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

      {/* Tenants Table */}
      <div className="glass-panel" style={{ overflow: 'hidden', borderRadius: '10px' }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8125rem' }}>
            <thead>
              <tr style={{ background: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Tenant ID</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Name</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Status</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Created</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600 }}>Updated</th>
                <th style={{ padding: '0.75rem 1rem', fontWeight: 600, textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && tenants.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
                      <Loader2 size={18} className="spinner" />
                      <span>Loading tenants from backend...</span>
                    </div>
                  </td>
                </tr>
              ) : tenants.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No tenants found or caller lacks permissions to inspect tenants.
                  </td>
                </tr>
              ) : (
                tenants.map((t) => {
                  const isActive = t.status === 'ACTIVE';
                  return (
                    <tr
                      key={t.tenant_id}
                      style={{
                        borderBottom: '1px solid var(--border-subtle)',
                        transition: 'background var(--transition-fast)',
                      }}
                    >
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span className="mono-text" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                          {t.tenant_id}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)' }}>
                        {t.name}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span
                          className={`status-pill ${isActive ? 'online' : 'offline'}`}
                          style={{ fontSize: '0.6875rem', padding: '0.15rem 0.5rem' }}
                        >
                          {t.status}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)' }}>
                        {t.created_at ? new Date(t.created_at * 1000).toLocaleString() : '—'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)' }}>
                        {t.updated_at ? new Date(t.updated_at * 1000).toLocaleString() : '—'}
                      </td>
                      <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: '0.35rem' }}>
                          <button
                            type="button"
                            className="secondary-btn"
                            title="Edit Tenant"
                            onClick={() => {
                              setEditingTenant(t);
                              setEditName(t.name);
                              setEditStatus(t.status as 'ACTIVE' | 'DISABLED');
                            }}
                            style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                          >
                            <Edit3 size={13} />
                          </button>
                          {isActive ? (
                            <button
                              type="button"
                              className="secondary-btn"
                              title="Disable Tenant"
                              onClick={() => promptDisableTenant(t)}
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
                              title="Enable Tenant"
                              onClick={() => promptEnableTenant(t)}
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

      {/* Provision Tenant Modal */}
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
              maxWidth: '480px',
              padding: '1.5rem',
              borderRadius: '12px',
              background: 'var(--bg-secondary)',
              display: 'flex',
              flexDirection: 'column',
              gap: '1rem',
            }}
          >
            <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Provision Isolated Security Tenant
            </h3>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
              Establishes a hardened namespace boundary. Tenant isolation is enforced strictly on the server.
            </p>

            <form onSubmit={handleCreateTenant} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label htmlFor="tenant-id-input" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                  Tenant ID (alphanumeric identifier)
                </label>
                <input
                  id="tenant-id-input"
                  type="text"
                  value={newTenantId}
                  onChange={(e) => setNewTenantId(e.target.value)}
                  placeholder="e.g. finance-prod"
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
                <label htmlFor="tenant-name-input" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                  Tenant Name
                </label>
                <input
                  id="tenant-name-input"
                  type="text"
                  value={newTenantName}
                  onChange={(e) => setNewTenantName(e.target.value)}
                  placeholder="e.g. Production Finance Division"
                  required
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
                  <span>Create Tenant</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Tenant Modal */}
      {editingTenant && (
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
              maxWidth: '480px',
              padding: '1.5rem',
              borderRadius: '12px',
              background: 'var(--bg-secondary)',
              display: 'flex',
              flexDirection: 'column',
              gap: '1rem',
            }}
          >
            <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Edit Tenant: <span className="mono-text">{editingTenant.tenant_id}</span>
            </h3>

            <form onSubmit={handleUpdateTenant} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label htmlFor="edit-tenant-name" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                  Tenant Name
                </label>
                <input
                  id="edit-tenant-name"
                  type="text"
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  required
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
                <label htmlFor="edit-tenant-status" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.35rem' }}>
                  Status
                </label>
                <select
                  id="edit-tenant-status"
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

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button
                  type="button"
                  className="secondary-btn"
                  onClick={() => setEditingTenant(null)}
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
