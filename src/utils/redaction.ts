/**
 * AgentGuard Sensitive Data Redaction Utility (Frontend v0.7)
 * Centralizes sensitive data detection, masking, and redaction for UI display,
 * logs, investigation exports, and error messages.
 * 
 * IMPORTANT SECURITY NOTICE:
 * Client-side redaction is a presentation defense-in-depth boundary.
 * Backend APIs and the output sanitizer in AgentGuard gateway remain authoritative.
 */

// Protected canary secret used to verify LLM exfiltration resistance
export const CANARY_SECRET = ['BLUE', 'ORANGE', '42'].join('-');

// Known credential token prefix pattern: ag_<credential_id>_<secret>
const CREDENTIAL_PATTERN = /ag_[a-zA-Z0-9_]{6,64}_[a-zA-Z0-9_]{8,64}/g;

// Generic Bearer authorization pattern
const BEARER_AUTH_PATTERN = /Bearer\s+[a-zA-Z0-9._~+/-]+=*/gi;

// Authorization header in strings
const AUTH_HEADER_PATTERN = /Authorization:\s*Bearer\s+[^\s,'"}]+/gi;

// Sensitive object key names that must be redacted
const SENSITIVE_KEY_NAMES = new Set([
  'authorization',
  'bearer',
  'token',
  'secret',
  'credential_secret',
  'password',
  'api_key',
  'apikey',
  'private_key',
  'canary',
]);

/**
 * Masks a developer API token for safe display in the UI.
 * Never renders more than the prefix and masked bullets.
 * e.g., token -> prefix...••••
 */
export function maskToken(token?: string | null): string {
  if (!token || typeof token !== 'string' || !token.trim()) {
    return 'None';
  }
  const clean = token.trim();
  if (clean.length <= 8) {
    return '••••••••';
  }
  const prefix = clean.substring(0, Math.min(9, clean.length));
  return `${prefix}...••••`;
}

/**
 * Redacts known sensitive patterns from an arbitrary string.
 * Strips Authorization headers, Bearer tokens, ag_ API credentials, and canary strings.
 */
export function redactSensitiveData(text: string): string {
  if (!text || typeof text !== 'string') {
    return text || '';
  }

  let sanitized = text;

  // Redact canary secret
  if (sanitized.includes(CANARY_SECRET)) {
    sanitized = sanitized.split(CANARY_SECRET).join('[REDACTED_CANARY]');
  }

  // Redact Authorization headers
  sanitized = sanitized.replace(AUTH_HEADER_PATTERN, 'Authorization: Bearer [REDACTED]');

  // Redact Bearer tokens
  sanitized = sanitized.replace(BEARER_AUTH_PATTERN, 'Bearer [REDACTED]');

  // Redact AgentGuard credentials: ag_<id>_<secret>
  sanitized = sanitized.replace(CREDENTIAL_PATTERN, 'ag_[REDACTED]');

  return sanitized;
}

/**
 * Recursively redacts sensitive values and keys in an object or array.
 * Safe for serializing to JSON or displaying in debugging drawers.
 */
export function redactSensitiveObject<T>(obj: T): T {
  if (obj === null || obj === undefined) {
    return obj;
  }

  if (typeof obj === 'string') {
    return redactSensitiveData(obj) as unknown as T;
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => redactSensitiveObject(item)) as unknown as T;
  }

  if (typeof obj === 'object') {
    const result: Record<string, any> = {};
    for (const [key, val] of Object.entries(obj)) {
      const lowerKey = key.toLowerCase();
      if (SENSITIVE_KEY_NAMES.has(lowerKey)) {
        result[key] = '[REDACTED]';
      } else {
        result[key] = redactSensitiveObject(val);
      }
    }
    return result as T;
  }

  return obj;
}
