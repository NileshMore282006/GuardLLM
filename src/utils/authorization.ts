/**
 * AgentGuard Centralized Authorization Presentation Layer (Frontend v0.7)
 * Defines deterministic client-side role capabilities directly aligned with
 * backend/services/authorization_service.py.
 * 
 * CRITICAL SECURITY INVARIANT:
 * Client-side role checks are defense-in-depth and presentation controls ONLY.
 * The AgentGuard backend gateway is ALWAYS the sole authority for authorization.
 * If permission is uncertain, the UI defaults to disabled with "Backend authorization required".
 */

import { UserRole } from '../types/agentguard';

// Role hierarchy rank for quick comparisons
export const ROLE_HIERARCHY: Record<UserRole, number> = {
  user: 1,
  operator: 2,
  admin: 3,
  global_admin: 4,
};

// Authoritative role capabilities map mirrored from backend/services/authorization_service.py
export const ROLE_CAPABILITIES: Record<string, Set<UserRole>> = {
  // Guard and target execution
  'guard:evaluate': new Set(['user', 'operator', 'admin', 'global_admin']),
  'guard:submit': new Set(['user', 'operator', 'admin', 'global_admin']),
  'target:execute': new Set(['user', 'operator', 'admin', 'global_admin']),
  'chat:execute': new Set(['user', 'operator', 'admin', 'global_admin']),
  'tool:execute': new Set(['user', 'operator', 'admin', 'global_admin']),
  'execute:low_risk': new Set(['user', 'operator', 'admin', 'global_admin']),

  // Approval capabilities
  'approval:create': new Set(['user', 'operator', 'admin', 'global_admin']),
  'approval:read_own': new Set(['user', 'operator', 'admin', 'global_admin']),
  'approval:inspect_own': new Set(['user', 'operator', 'admin', 'global_admin']),
  'approval:read_all': new Set(['operator', 'admin', 'global_admin']),
  'approval:inspect_all': new Set(['operator', 'admin', 'global_admin']),
  'approval:approve': new Set(['operator', 'admin', 'global_admin']),
  'approval:deny': new Set(['operator', 'admin', 'global_admin']),

  // Policy capabilities
  'policy:read': new Set(['operator', 'admin', 'global_admin']),
  'policy:create': new Set(['admin', 'global_admin']),
  'policy:update': new Set(['admin', 'global_admin']),
  'policy:delete': new Set(['admin', 'global_admin']),
  'policy:admin': new Set(['admin', 'global_admin']),

  // Audit capabilities
  'audit:read_own': new Set(['user', 'operator', 'admin', 'global_admin']),
  'audit:read_all': new Set(['operator', 'admin', 'global_admin']),
  'audit:verify': new Set(['admin', 'global_admin']),

  // Credential capabilities
  'credential:create': new Set(['admin', 'global_admin']),
  'credential:read_own': new Set(['user', 'operator', 'admin', 'global_admin']),
  'credential:read_all': new Set(['admin', 'global_admin']),
  'credential:revoke': new Set(['admin', 'global_admin']),
  'credential:rotate': new Set(['admin', 'global_admin']),

  // Principal capabilities
  'principal:create': new Set(['admin', 'global_admin']),
  'principal:read': new Set(['admin', 'global_admin']),
  'principal:update': new Set(['admin', 'global_admin']),
  'principal:disable': new Set(['admin', 'global_admin']),
  'principal:enable': new Set(['admin', 'global_admin']),

  // Tenant capabilities (Strictly global admin restricted)
  'tenant:create': new Set(['global_admin']),
  'tenant:read': new Set(['admin', 'global_admin']),
  'tenant:update': new Set(['global_admin']),
  'tenant:disable': new Set(['global_admin']),
  'tenant:enable': new Set(['global_admin']),
  'tenant:admin': new Set(['global_admin']),
};

/**
 * Checks whether the given user roles are permitted to perform the specified capability.
 * Returns true only if at least one role matches.
 */
export function checkPermission(capability: string, roles: string[] = []): boolean {
  const allowedRoles = ROLE_CAPABILITIES[capability];
  if (!allowedRoles) {
    // Fail closed: Unknown capability
    return false;
  }
  return roles.some((role) => allowedRoles.has(role as UserRole));
}

/**
 * Checks if a user has at least a specific minimum role level.
 */
export function hasMinimumRole(userRoles: string[] = [], requiredRole: UserRole): boolean {
  const targetRank = ROLE_HIERARCHY[requiredRole];
  return userRoles.some((role) => {
    const rank = ROLE_HIERARCHY[role as UserRole];
    return rank !== undefined && rank >= targetRank;
  });
}

/**
 * Returns a user-friendly explanation if a capability is restricted.
 */
export function getPermissionExplanation(capability: string, roles: string[] = []): string | null {
  if (checkPermission(capability, roles)) {
    return null;
  }
  const allowed = ROLE_CAPABILITIES[capability];
  if (!allowed) {
    return 'Backend authorization required (Unknown operation).';
  }
  const roleNames = Array.from(allowed).join(' or ');
  return `Backend authorization required (Requires role: ${roleNames}).`;
}
