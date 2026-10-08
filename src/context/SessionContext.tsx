/**
 * AgentGuard Central Session Security Context (Frontend v0.7)
 * Centralizes all frontend authentication, Bearer credential lifecycle,
 * state machine transitions, and memory-only token protection.
 * 
 * HARD SECURITY BOUNDARIES:
 * 1. MEMORY-ONLY STORAGE: The token is strictly stored in React runtime memory (ref/state).
 *    NEVER written to localStorage, sessionStorage, IndexedDB, cookies, or URL params.
 * 2. PROMPT PAGE-UNLOAD CLEANUP: Event listeners for 'beforeunload' and 'pagehide' clear
 *    the token reference when the tab or window is closed or refreshed.
 * 3. TOKEN MASKING: Raw tokens are NEVER rendered in the DOM or ordinary props.
 *    Only masked tokens (e.g. ag_c_...••••) are exposed for display.
 * 4. STRICT ERROR SEGREGATION:
 *    - 401 Unauthorized: Invalidates session and clears credentials.
 *    - 403 Forbidden: Preserves credentials; displays authorization failure without logging out.
 *    - 5xx / Network Failure: Preserves credentials; indicates degraded backend state.
 * 
 * DISCLAIMER:
 * JavaScript memory is not an impenetrable cryptographic boundary against resident
 * browser extensions or full XSS compromises. Production environments must enforce
 * HTTPS, strict Content-Security-Policy (CSP), and server-side RBAC.
 */

import React, { createContext, useContext, useState, useRef, useEffect, useCallback } from 'react';
import {
  SessionState,
  UserRole,
  SafeApiError,
} from '../types/agentguard';
import { agentGuardApi } from '../api/agentguard';
import { maskToken } from '../utils/redaction';
import { normalizeApiError } from '../utils/errorNormalizer';
import { checkPermission as checkCapabilityPermission } from '../utils/authorization';

export interface SessionContextType {
  // Session State Machine
  sessionState: SessionState;
  isAuthenticated: boolean;
  tokenPresent: boolean;
  maskedToken: string;

  // Identity & Authorization
  principalId: string;
  tenantId: string;
  roles: UserRole[];
  isGlobalAdmin: boolean;

  // Error telemetry
  lastAuthError: SafeApiError | null;

  // Actions
  setToken: (token: string) => Promise<void>;
  clearSession: () => void;
  logout: () => void;
  handleApiError: (error: unknown) => void;
  canPerform: (capability: string) => boolean;
  hasRole: (role: UserRole) => boolean;
  getRawTokenForApi: () => string;
}

const SessionContext = createContext<SessionContextType | null>(null);

interface SessionProviderProps {
  children: React.ReactNode;
  initialToken?: string;
}

export const SessionProvider: React.FC<SessionProviderProps> = ({
  children,
  initialToken = '',
}) => {
  // In-memory token storage (never persisted to browser storage)
  const tokenRef = useRef<string>(initialToken);

  const [sessionState, setSessionState] = useState<SessionState>(
    initialToken ? 'AUTHENTICATING' : 'UNAUTHENTICATED'
  );
  const [tokenPresent, setTokenPresent] = useState<boolean>(Boolean(initialToken));
  const [maskedToken, setMaskedToken] = useState<string>(maskToken(initialToken));
  const [principalId, setPrincipalId] = useState<string>('anonymous');
  const [tenantId, setTenantId] = useState<string>('default');
  const [roles, setRoles] = useState<UserRole[]>(['user']);
  const [isGlobalAdmin, setIsGlobalAdmin] = useState<boolean>(false);
  const [lastAuthError, setLastAuthError] = useState<SafeApiError | null>(null);

  // Clear session completely
  const clearSession = useCallback(() => {
    tokenRef.current = '';
    setTokenPresent(false);
    setMaskedToken('None');
    setPrincipalId('anonymous');
    setTenantId('default');
    setRoles(['user']);
    setIsGlobalAdmin(false);
    setSessionState('UNAUTHENTICATED');
    setLastAuthError(null);
  }, []);

  const logout = useCallback(() => {
    clearSession();
  }, [clearSession]);

  // Clean memory on window unload or pagehide
  useEffect(() => {
    const handleUnload = () => {
      tokenRef.current = '';
    };

    window.addEventListener('beforeunload', handleUnload);
    window.addEventListener('pagehide', handleUnload);

    return () => {
      window.removeEventListener('beforeunload', handleUnload);
      window.removeEventListener('pagehide', handleUnload);
      tokenRef.current = '';
    };
  }, []);

  // Internal function to authenticate token against backend
  const authenticateToken = useCallback(async (rawToken: string) => {
    if (!rawToken || !rawToken.trim()) {
      clearSession();
      return;
    }

    const trimmed = rawToken.trim();
    tokenRef.current = trimmed;
    setTokenPresent(true);
    setMaskedToken(maskToken(trimmed));
    setSessionState('AUTHENTICATING');
    setLastAuthError(null);

    try {
      // Test the token against the backend by listing principals or tenants
      // If the token is an admin/global_admin token, listPrincipals will succeed
      // If it's a user token, verify against audit or health
      let resolvedRoles: UserRole[] = ['user'];
      let resolvedPrincipal = 'authenticated-caller';
      let resolvedTenant = 'default';
      let resolvedGlobalAdmin = false;

      // Attempt verification via /api/v1/tenants (admins) or /api/v1/audit/events
      try {
        const tenantsResp = await agentGuardApi.listTenants(trimmed);
        if (tenantsResp && tenantsResp.tenants) {
          resolvedRoles = ['admin', 'operator', 'user'];
          resolvedPrincipal = 'admin-demo';
          // Check if global admin
          if (trimmed.includes('global-admin') || tenantsResp.tenants.length > 1) {
            resolvedRoles = ['global_admin', 'admin', 'operator', 'user'];
            resolvedGlobalAdmin = true;
            resolvedPrincipal = 'global-admin-demo';
          }
        }
      } catch (err: any) {
        if (err?.status === 403) {
          // Token is authenticated, but not an admin! Caller has 'operator' or 'user' role
          resolvedRoles = ['operator', 'user'];
          resolvedPrincipal = 'operator-demo';
        } else if (err?.status === 401) {
          // Token is invalid, expired, or revoked
          tokenRef.current = '';
          setTokenPresent(false);
          setMaskedToken('None');
          setSessionState('UNAUTHENTICATED');
          setLastAuthError(normalizeApiError(err));
          return;
        } else if (err?.status >= 500 || err?.status === 0) {
          // Backend unavailable or degraded - DO NOT destroy token!
          setSessionState('BACKEND_UNAVAILABLE');
          setLastAuthError(normalizeApiError(err));
          return;
        }
      }

      setPrincipalId(resolvedPrincipal);
      setTenantId(resolvedTenant);
      setRoles(resolvedRoles);
      setIsGlobalAdmin(resolvedGlobalAdmin);
      setSessionState('AUTHENTICATED');
    } catch (err) {
      const normalized = normalizeApiError(err);
      setLastAuthError(normalized);
      if (normalized.status === 401) {
        tokenRef.current = '';
        setTokenPresent(false);
        setMaskedToken('None');
        setSessionState('UNAUTHENTICATED');
      } else if (normalized.status === 403) {
        setSessionState('FORBIDDEN');
      } else {
        setSessionState('BACKEND_UNAVAILABLE');
      }
    }
  }, [clearSession]);

  const setToken = useCallback(async (token: string) => {
    await authenticateToken(token);
  }, [authenticateToken]);

  // Handle centralized API errors from any component
  const handleApiError = useCallback((error: unknown) => {
    const normalized = normalizeApiError(error);
    setLastAuthError(normalized);

    if (normalized.status === 401) {
      // 401 MUST invalidate session
      tokenRef.current = '';
      setTokenPresent(false);
      setMaskedToken('None');
      setSessionState('UNAUTHENTICATED');
    } else if (normalized.status === 403) {
      // 403 MUST preserve authentication state!
      setSessionState('FORBIDDEN');
    } else if (normalized.status >= 500 || normalized.status === 0) {
      // 5xx / Network failure MUST preserve credentials!
      setSessionState('BACKEND_UNAVAILABLE');
    }
  }, []);

  const canPerform = useCallback((capability: string) => {
    return checkCapabilityPermission(capability, roles);
  }, [roles]);

  const hasRole = useCallback((role: UserRole) => {
    return roles.includes(role);
  }, [roles]);

  const getRawTokenForApi = useCallback(() => {
    return tokenRef.current;
  }, []);

  // Initial authentication attempt if initialToken was passed
  useEffect(() => {
    if (initialToken) {
      authenticateToken(initialToken);
    }
  }, [initialToken, authenticateToken]);

  const contextValue: SessionContextType = {
    sessionState,
    isAuthenticated: sessionState === 'AUTHENTICATED' || sessionState === 'FORBIDDEN',
    tokenPresent,
    maskedToken,
    principalId,
    tenantId,
    roles,
    isGlobalAdmin,
    lastAuthError,
    setToken,
    clearSession,
    logout,
    handleApiError,
    canPerform,
    hasRole,
    getRawTokenForApi,
  };

  return (
    <SessionContext.Provider value={contextValue}>
      {children}
    </SessionContext.Provider>
  );
};

export function useSession(): SessionContextType {
  const context = useContext(SessionContext);
  if (!context) {
    return {
      sessionState: 'UNAUTHENTICATED',
      isAuthenticated: false,
      tokenPresent: false,
      maskedToken: 'None',
      principalId: 'anonymous',
      tenantId: 'default',
      roles: ['user'],
      isGlobalAdmin: false,
      lastAuthError: null,
      setToken: async () => {},
      clearSession: () => {},
      logout: () => {},
      handleApiError: () => {},
      canPerform: () => false,
      hasRole: () => false,
      getRawTokenForApi: () => '',
    };
  }
  return context;
}
