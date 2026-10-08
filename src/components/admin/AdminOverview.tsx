import React from 'react';
import { Building2, Users, KeyRound, FileCode2, ScrollText, ArrowRight } from 'lucide-react';
import { AdminTab, TenantResponse, PrincipalResponse, CredentialResponse, PolicyResponse } from '../../types/agentguard';
import { RoleManagement } from './RoleManagement';

interface AdminOverviewProps {
  tenants: TenantResponse[];
  principals: PrincipalResponse[];
  credentials: CredentialResponse[];
  policies: PolicyResponse[];
  auditTotal: number;
  onNavigateTab: (tab: AdminTab) => void;
}

export const AdminOverview: React.FC<AdminOverviewProps> = ({
  tenants,
  principals,
  credentials,
  policies,
  auditTotal,
  onNavigateTab,
}) => {
  const activeTenants = tenants.filter((t) => t.status === 'ACTIVE').length;
  const activePrincipals = principals.filter((p) => p.status === 'ACTIVE').length;
  const activeCredentials = credentials.filter((c) => c.status === 'ACTIVE').length;
  const revokedCredentials = credentials.filter((c) => c.status === 'REVOKED').length;
  const activePolicies = policies.filter((p) => p.enabled && !p.deleted).length;

  const kpis = [
    {
      title: 'Tenants',
      count: tenants.length,
      detail: `${activeTenants} active namespace boundaries`,
      source: 'Backend /api/v1/tenants',
      icon: <Building2 size={20} />,
      color: 'var(--color-accent)',
      tab: 'tenants' as AdminTab,
    },
    {
      title: 'Security Principals',
      count: principals.length,
      detail: `${activePrincipals} active identity records`,
      source: 'Backend /api/v1/principals',
      icon: <Users size={20} />,
      color: '#3b82f6',
      tab: 'principals' as AdminTab,
    },
    {
      title: 'Active API Credentials',
      count: activeCredentials,
      detail: `${revokedCredentials} revoked immediately`,
      source: 'Backend /api/v1/credentials',
      icon: <KeyRound size={20} />,
      color: 'var(--color-warn)',
      tab: 'credentials' as AdminTab,
    },
    {
      title: 'Active Security Policies',
      count: activePolicies,
      detail: `${policies.length} total registered rules`,
      source: 'Backend /api/v1/policies',
      icon: <FileCode2 size={20} />,
      color: 'var(--color-allow)',
      tab: 'policies' as AdminTab,
    },
    {
      title: 'Chained Audit Records',
      count: auditTotal,
      detail: 'SHA-256 cryptographic chain',
      source: 'Backend /api/v1/audit/events',
      icon: <ScrollText size={20} />,
      color: '#a855f7',
      tab: 'audit' as AdminTab,
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Top Overview Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '1rem' }}>
        {kpis.map((k) => (
          <div
            key={k.title}
            className="glass-panel"
            onClick={() => onNavigateTab(k.tab)}
            style={{
              padding: '1.25rem',
              borderRadius: '12px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              gap: '0.75rem',
              cursor: 'pointer',
              transition: 'transform var(--transition-fast), border-color var(--transition-fast)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div
                style={{
                  padding: '0.45rem',
                  borderRadius: '8px',
                  background: 'var(--bg-tertiary)',
                  color: k.color,
                }}
              >
                {k.icon}
              </div>
              <ArrowRight size={15} style={{ color: 'var(--text-muted)' }} />
            </div>

            <div>
              <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.1 }}>
                {k.count}
              </div>
              <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                {k.title}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
                {k.detail}
              </div>
            </div>

            <div
              style={{
                fontSize: '0.6875rem',
                color: 'var(--text-dim)',
                borderTop: '1px solid var(--border-subtle)',
                paddingTop: '0.4rem',
              }}
            >
              Source: <span className="mono-text">{k.source}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Role Management Taxonomy Reference */}
      <RoleManagement />
    </div>
  );
};
