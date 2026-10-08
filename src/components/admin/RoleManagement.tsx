import React from 'react';
import { Shield, Building2 } from 'lucide-react';
import { PrincipalRole } from '../../types/agentguard';

export const RoleManagement: React.FC = () => {
  const roles: {
    role: PrincipalRole;
    badgeColor: string;
    description: string;
    permissions: string[];
  }[] = [
    {
      role: 'global_admin',
      badgeColor: 'rgba(239, 68, 68, 0.2)',
      description: 'Superuser authority across all isolated tenants and gateway infrastructure.',
      permissions: [
        'Provision, update, enable, and disable isolated tenants',
        'Cross-tenant principal management & assignment of global_admin role',
        'Cross-tenant credential creation, rotation, and revocation',
        'Cross-tenant security policy authoring and soft-deletion',
        'Global cryptographic audit chain verification & cross-tenant audit inspection',
      ],
    },
    {
      role: 'admin',
      badgeColor: 'rgba(99, 102, 241, 0.2)',
      description: 'Tenant-scoped administrative authority. Restricted to caller bound tenant.',
      permissions: [
        'View bound tenant metadata (cannot administer other tenants)',
        'Register, update, enable, and disable principals within bound tenant',
        'Generate, rotate, and revoke API credentials within bound tenant',
        'Create, update, and soft-delete security policies within bound tenant',
        'Inspect bound tenant audit history & verify cryptographic audit chain',
      ],
    },
    {
      role: 'operator',
      badgeColor: 'rgba(245, 158, 11, 0.2)',
      description: 'Operational and inspection privileges. Read-only control plane access.',
      permissions: [
        'Read-only inspection of security policies within tenant scope',
        'Read-only inspection of audit events within tenant scope',
        'Inspect approval requests and approve/deny actions if delegated',
        'Zero permission to create credentials, modify principals, or mutate policies',
      ],
    },
    {
      role: 'user',
      badgeColor: 'rgba(16, 185, 129, 0.15)',
      description: 'Standard AI consumer principal. Strictly bounded to execution perimeter.',
      permissions: [
        'Invoke Guard prompt evaluation (/api/v1/guard)',
        'Send multi-turn chat turns (/api/v1/chat)',
        'Execute allowed agent tools (/api/v1/tool/execute)',
        'Inspect ONLY own security audit events (ownership-scoped)',
        'Forbidden (403) from accessing all administrative endpoints',
      ],
    },
  ];

  return (
    <div className="glass-panel" style={{ padding: '1.5rem', borderRadius: '12px', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
        <div style={{ padding: '0.45rem', borderRadius: '8px', background: 'rgba(99, 102, 241, 0.15)', color: 'var(--color-accent)' }}>
          <Shield size={20} />
        </div>
        <div>
          <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            AgentGuard Authoritative RBAC Taxonomy
          </h3>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Strictly defined by backend identity & policy engines. No frontend role spoofing.
          </span>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1rem' }}>
        {roles.map((r) => (
          <div
            key={r.role}
            style={{
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              padding: '1.1rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.75rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span
                className="mono-text"
                style={{
                  fontWeight: 700,
                  fontSize: '0.875rem',
                  padding: '0.2rem 0.55rem',
                  borderRadius: '4px',
                  background: r.badgeColor,
                  color: 'var(--text-primary)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                {r.role}
              </span>
            </div>

            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
              {r.description}
            </p>

            <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '0.5rem' }}>
              <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Privileges Matrix:
              </span>
              <ul style={{ margin: '0.35rem 0 0 1rem', padding: 0, fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                {r.permissions.map((p, idx) => (
                  <li key={idx} style={{ marginBottom: '0.25rem' }}>
                    {p}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        ))}
      </div>

      <div
        style={{
          background: 'rgba(99, 102, 241, 0.08)',
          border: '1px solid rgba(99, 102, 241, 0.25)',
          borderRadius: '8px',
          padding: '0.75rem 1rem',
          fontSize: '0.8125rem',
          color: 'var(--text-secondary)',
          display: 'flex',
          alignItems: 'center',
          gap: '0.65rem',
        }}
      >
        <Building2 size={16} style={{ color: 'var(--color-accent)', flexShrink: 0 }} />
        <div>
          <strong style={{ color: 'var(--text-primary)' }}>Multi-Tenant Isolation Notice: </strong>
          Headers such as <code className="mono-text" style={{ fontSize: '0.75rem' }}>X-AgentGuard-Role</code> or <code className="mono-text" style={{ fontSize: '0.75rem' }}>X-AgentGuard-Tenant</code> are strictly disregarded by the backend gateway. Authorization is bound to cryptographically verified Bearer credentials or server-side store records.
        </div>
      </div>
    </div>
  );
};
