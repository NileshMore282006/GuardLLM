/**
 * AgentGuard Error Normalizer (Frontend v0.7)
 * Normalizes HTTP status codes, network faults, and API exceptions into safe,
 * structured, redacted error representations without leaking stack traces,
 * file paths, SQL statements, or sensitive configuration details.
 */

import { SafeApiError, NormalizedErrorCode } from '../types/agentguard';
import { AgentGuardApiError } from '../api/agentguard';
import { redactSensitiveData } from './redaction';

// Patterns that identify internal leakage to be stripped
const INTERNAL_LEAK_PATTERNS = [
  /Traceback \(most recent call last\):[\s\S]*/i,
  /[a-zA-Z]:\\[\w\s.\\-]+/g, // Windows paths e.g. C:\Users\...
  /\/[\w\-.]+\/[\w\-./]+/g,   // POSIX paths e.g. /var/data/...
  /sqlite3\.\w+Error: .*/gi,
  /SELECT .* FROM .*/gi,
  /INSERT INTO .*/gi,
  /UPDATE .* SET .*/gi,
  /http:\/\/(localhost|127\.0\.0\.1):\d+/gi,
  /(?:localhost|127\.0\.0\.1):\d+/gi,
];

/**
 * Sanitizes an error message string to guarantee no file paths, stack traces,
 * or SQL queries are exposed to operators or users.
 */
export function sanitizeErrorMessage(rawMessage: string): string {
  if (!rawMessage || typeof rawMessage !== 'string') {
    return 'An unexpected system error occurred.';
  }

  let cleaned = redactSensitiveData(rawMessage);

  // If message contains a python traceback, strip it completely
  if (cleaned.includes('Traceback (most recent call last):')) {
    return 'An internal backend exception occurred. Check gateway server logs for details.';
  }

  // Replace internal paths and database signatures
  for (const pattern of INTERNAL_LEAK_PATTERNS) {
    cleaned = cleaned.replace(pattern, '[internal-path]');
  }

  return cleaned.trim() || 'An unexpected error occurred.';
}

/**
 * Normalizes an unknown exception or API error into a structured SafeApiError.
 */
export function normalizeApiError(err: unknown): SafeApiError {
  const timestamp = Date.now();

  // If it's already an AgentGuardApiError
  if (err instanceof AgentGuardApiError) {
    const status = err.status;
    let code: NormalizedErrorCode = 'UNKNOWN_ERROR';
    let safeMessage = '';

    switch (status) {
      case 400:
        code = 'VALIDATION_ERROR';
        safeMessage = 'Invalid request parameters or payload formatting.';
        break;
      case 401:
        code = 'AUTHENTICATION_REQUIRED';
        safeMessage = 'Authentication required. Please provide a valid API token.';
        break;
      case 403:
        code = 'FORBIDDEN';
        safeMessage = 'Access denied. Insufficient role permissions for this operation.';
        break;
      case 404:
        code = 'NOT_FOUND';
        safeMessage = 'The requested resource was not found on the backend.';
        break;
      case 409:
        code = 'RESOURCE_CONFLICT';
        safeMessage = err.message || 'Resource state conflict. The item has already been modified or consumed.';
        break;
      case 413:
        code = 'PAYLOAD_TOO_LARGE';
        safeMessage = 'Payload exceeds the configured 1MB body size boundary.';
        break;
      case 415:
        code = 'VALIDATION_ERROR';
        safeMessage = 'Unsupported media type. JSON body required.';
        break;
      case 422:
        code = 'VALIDATION_ERROR';
        safeMessage = 'Validation error: invalid request schema or parameter types.';
        break;
      case 429:
        code = 'RATE_LIMITED';
        safeMessage = 'Rate limit exceeded. Please back off before retrying.';
        break;
      case 500:
        code = 'INTERNAL_ERROR';
        safeMessage = 'An internal error occurred in the AgentGuard gateway.';
        break;
      case 502:
      case 503:
      case 504:
        code = 'BACKEND_UNAVAILABLE';
        safeMessage = 'AgentGuard backend service is currently unavailable.';
        break;
      case 0:
        if (err.code === 'ABORTED') {
          code = 'ABORTED';
          safeMessage = 'Request cancelled locally.';
        } else {
          code = 'NETWORK_ERROR';
          safeMessage = 'Unable to reach AgentGuard gateway. Check server connectivity.';
        }
        break;
      default:
        code = 'UNKNOWN_ERROR';
        safeMessage = `Request failed with HTTP status ${status}.`;
        break;
    }

    return {
      code,
      status,
      message: safeMessage,
      safeDetails: sanitizeErrorMessage(err.message),
      timestamp,
    };
  }

  // Handle AbortError
  if (err instanceof DOMException && err.name === 'AbortError') {
    return {
      code: 'ABORTED',
      status: 0,
      message: 'Request was cancelled.',
      timestamp,
    };
  }

  // Handle generic Error
  if (err instanceof Error) {
    return {
      code: 'UNKNOWN_ERROR',
      status: 0,
      message: sanitizeErrorMessage(err.message),
      timestamp,
    };
  }

  return {
    code: 'UNKNOWN_ERROR',
    status: 0,
    message: 'An unknown error occurred.',
    timestamp,
  };
}
