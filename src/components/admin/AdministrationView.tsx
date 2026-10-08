import React, { useState, useEffect, useCallback } from 'react';
import {
  Building2,
  Users,
  KeyRound,
  FileCode2,
  ScrollText,
  LayoutGrid,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react';
import {
  AdminTab,
  TenantResponse,
  PrincipalResponse,
  CredentialResponse,
  PolicyResponse,
  HealthResponse,
} from '../../types/agentguard';
import { agentGuardApi, AgentGuardApiError } from '../../api/agentguard';
import { SecurityContextCard } from './SecurityContextCard';
import { AdminOverview } from './AdminOverview';
import { TenantManagement } from './TenantManagement';
import { PrincipalManagement } from './PrincipalManagement';
import { CredentialManagement } from './CredentialManagement';
import { PolicyManagement } from './PolicyManagement';
import { AuditExplorer } from './AuditExplorer';

interface AdministrationViewProps {
  health: HealthResponse | null;
  developerToken?: string;
  setDeveloperToken?: (token: string) => void;
}

export const AdministrationView: React.FC<AdministrationViewProps> = ({
  developerToken = '',
  setDeveloperToken,
}) => {
  const [activeTab, setActiveTab] = useState<AdminTab>('overview');
  const [token, setToken] = useState<string>(developerToken);

  // Synchronize token with parent if provided
  const handleTokenChange = (newToken: string) => {
    setToken(newToken);
    if (setDeveloperToken) {
      setDeveloperToken(newToken);
    }
  };

  // High-level overview statistics state
  const [tenants, setTenants] = useState<TenantResponse[]>([]);
  const [principals, setPrincipals] = useState<PrincipalResponse[]>([]);
  const [credentials, setCredentials] = useState<CredentialResponse[]>([]);
  const [policies, setPolicies] = useState<PolicyResponse[]>([]);
  const [auditTotal, setAuditTotal] = useState<number>(0);

  const [isLoadingOverview, setIsLoadingOverview] = useState<boolean>(false);
  const [globalError, setGlobalError] = useState<string | null>(null);

  // Inferred Context metadata from authenticated identity or defaults
  const [callerPrincipalId, setCallerPrincipalId] = useState<string>('anonymous');
  const [callerTenantId, setCallerTenantId] = useState<string>('default');
  const [callerRoles, setCallerRoles] = useState<string[]>(['user']);
  const [isGlobalAdmin, setIsGlobalAdmin] = useState<boolean>(false);

  const fetchOverviewData = useCallback(async () => {
    setIsLoadingOverview(true);
    setGlobalError(null);

    try {
      // 1. Fetch tenants (if permitted)
      try {
        const tResp = await agentGuardApi.listTenants(token);
        setTenants(tResp.tenants || []);
      } catch {
        // Tenant listing may be 403 for non-admins; handled gracefully
      }

      // 2. Fetch principals (if permitted)
      try {
        const pResp = await agentGuardApi.listPrincipals(undefined, token);
        const pList = pResp.principals || [];
        setPrincipals(pList);

        // If authenticated with a known principal in the list, infer context
        if (token && pList.length > 0) {
          const match = pList.find((p) => p.roles.includes('admin') || p.roles.includes('global_admin'));
          if (match) {
            setCallerPrincipalId(match.principal_id);
            setCallerTenantId(match.tenant_id);
            setCallerRoles(match.roles);
            setIsGlobalAdmin(match.roles.includes('global_admin'));
          }
        }
      } catch {
        // Principals may be restricted
      }

      // 3. Fetch credentials (if permitted)
      try {
        const cResp = await agentGuardApi.listCredentials(undefined, token);
        setCredentials(cResp.credentials || []);
      } catch {
        // Credentials may be restricted
      }

      // 4. Fetch policies (if permitted)
      try {
        const polResp = await agentGuardApi.listPolicies(true, token);
        setPolicies(polResp.policies || []);
      } catch {
        // Policies may be restricted
      }

      // 5. Fetch audit total count
      try {
        const aResp = await agentGuardApi.getAuditEvents({ limit: 1 }, token);
        setAuditTotal(aResp.total || 0);
      } catch {
        // Audit may be restricted
      }
    } catch (err: any) {
      if (err instanceof AgentGuardApiError) {
        setGlobalError(err.message);
      }
    } finally {
      setIsLoadingOverview(false);
    }
  }, [token]);

  useEffect(() => {
    fetchOverviewData();
  }, [fetchOverviewData]);

  const navTabs: { id: AdminTab; label: string; icon: React.ReactNode }[] = [
    { id: 'overview', label: 'Overview', icon: <LayoutGrid size={15} /> },
    { id: 'tenants', label: 'Tenants', icon: <Building2 size={15} /> },
    { id: 'principals', label: 'Principals', icon: <Users size={15} /> },
    { id: 'credentials', label: 'Credentials', icon: <KeyRound size={15} /> },
    { id: 'policies', label: 'Policies', icon: <FileCode2 size={15} /> },
    { id: 'audit', label: 'Audit Explorer', icon: <ScrollText size={15} /> },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Security Context Card (Caller Identity & Token Management) */}
      <SecurityContextCard
        token={token}
        onTokenChange={handleTokenChange}
        callerPrincipalId={callerPrincipalId}
        callerTenantId={callerTenantId}
        callerRoles={callerRoles}
        isGlobalAdmin={isGlobalAdmin}
      />

      {globalError && (
        <div className="alert-box danger" role="alert">
          <ShieldAlert size={20} style={{ flexShrink: 0 }} />
          <div>
            <div style={{ fontWeight: 600 }}>Administration Access Notice</div>
            <div style={{ fontSize: '0.8125rem' }}>{globalError}</div>
          </div>
        </div>
      )}

      {/* Administration Sub-Navigation Tabs */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          borderBottom: '1px solid var(--border-subtle)',
          paddingBottom: '0.5rem',
          flexWrap: 'wrap',
          gap: '0.75rem',
        }}
      >
        <div role="tablist" aria-label="Administration subsections" style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          {navTabs.map((t) => {
            const isActive = activeTab === t.id;
            return (
              <button
                key={t.id}
                type="button"
                role="tab"
                aria-selected={isActive}
                onClick={() => setActiveTab(t.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.45rem',
                  padding: '0.5rem 0.9rem',
                  borderRadius: '6px',
                  fontSize: '0.8125rem',
                  fontWeight: isActive ? 600 : 500,
                  cursor: 'pointer',
                  background: isActive ? 'var(--color-accent)' : 'transparent',
                  color: isActive ? '#ffffff' : 'var(--text-secondary)',
                  border: `1px solid ${isActive ? 'var(--color-accent)' : 'transparent'}`,
                  transition: 'all var(--transition-fast)',
                }}
              >
                {t.icon}
                <span>{t.label}</span>
              </button>
            );
          })}
        </div>

        <button
          type="button"
          className="secondary-btn"
          onClick={fetchOverviewData}
          disabled={isLoadingOverview}
          style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}
        >
          <RefreshCw size={13} className={isLoadingOverview ? 'spinner' : ''} style={{ marginRight: '0.3rem' }} />
          Refresh Control Plane
        </button>
      </div>

      {/* Tab Panels */}
      <div>
        {activeTab === 'overview' && (
          <AdminOverview
            tenants={tenants}
            principals={principals}
            credentials={credentials}
            policies={policies}
            auditTotal={auditTotal}
            onNavigateTab={setActiveTab}
          />
        )}

        {activeTab === 'tenants' && (
          <TenantManagement token={token} isGlobalAdmin={isGlobalAdmin} />
        )}

        {activeTab === 'principals' && (
          <PrincipalManagement token={token} isGlobalAdmin={isGlobalAdmin} />
        )}

        {activeTab === 'credentials' && (
          <CredentialManagement token={token} isGlobalAdmin={isGlobalAdmin} />
        )}

        {activeTab === 'policies' && (
          <PolicyManagement token={token} isGlobalAdmin={isGlobalAdmin} />
        )}

        {activeTab === 'audit' && (
          <AuditExplorer token={token} isGlobalAdmin={isGlobalAdmin} />
        )}
      </div>
    </div>
  );
};
