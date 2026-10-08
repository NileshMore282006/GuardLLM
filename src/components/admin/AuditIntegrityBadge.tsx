import React from 'react';
import { ShieldCheck, ShieldAlert, KeyRound, AlertTriangle } from 'lucide-react';
import { AuditVerifyResponse, AuditVerificationStatus } from '../../types/agentguard';

interface AuditIntegrityBadgeProps {
  verifyResult: AuditVerifyResponse | null;
  isLoading?: boolean;
}

export const AuditIntegrityBadge: React.FC<AuditIntegrityBadgeProps> = ({
  verifyResult,
  isLoading = false,
}) => {
  if (isLoading) {
    return (
      <div
        className="glass-panel"
        style={{
          padding: '0.75rem 1rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          fontSize: '0.8125rem',
          color: 'var(--text-muted)',
        }}
      >
        <span className="spinner" style={{ width: '14px', height: '14px' }} />
        <span>Verifying SHA-256 hash chain cryptographic integrity...</span>
      </div>
    );
  }

  if (!verifyResult) {
    return (
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          fontSize: '0.75rem',
          color: 'var(--text-muted)',
          padding: '0.4rem 0.75rem',
          borderRadius: '6px',
          background: 'var(--bg-tertiary)',
        }}
      >
        <span>Audit integrity: Not yet verified against server chain</span>
      </div>
    );
  }

  // Derive authoritative verification status
  let status: AuditVerificationStatus = 'VALID';
  if (!verifyResult.valid) {
    const detailsLower = (verifyResult.details || '').toLowerCase();
    const statusLower = (verifyResult.status || '').toLowerCase();
    if (statusLower === 'key_missing' || detailsLower.includes('key is missing') || detailsLower.includes('key is required')) {
      status = 'KEY MISSING';
    } else if (detailsLower.includes('incompatible') || detailsLower.includes('algorithm')) {
      status = 'INCOMPATIBLE';
    } else {
      status = 'TAMPERED';
    }
  }

  const isTampered = status === 'TAMPERED';
  const isKeyMissing = status === 'KEY MISSING';
  const isIncompatible = status === 'INCOMPATIBLE';
  const isValid = status === 'VALID';

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '0.35rem',
        padding: '0.85rem 1.15rem',
        borderRadius: '8px',
        background: isValid
          ? 'var(--color-allow-bg)'
          : isTampered
          ? 'rgba(239, 68, 68, 0.2)'
          : 'rgba(245, 158, 11, 0.15)',
        border: `1px solid ${
          isValid
            ? 'var(--color-allow-border)'
            : isTampered
            ? 'rgba(239, 68, 68, 0.6)'
            : 'rgba(245, 158, 11, 0.5)'
        }`,
        boxShadow: isTampered ? '0 0 20px rgba(239, 68, 68, 0.35)' : 'none',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          {isValid && <ShieldCheck size={18} style={{ color: 'var(--color-allow)' }} />}
          {isTampered && <ShieldAlert size={20} style={{ color: 'var(--color-block)' }} />}
          {isKeyMissing && <KeyRound size={18} style={{ color: 'var(--color-warn)' }} />}
          {isIncompatible && <AlertTriangle size={18} style={{ color: 'var(--color-warn)' }} />}

          <span
            style={{
              fontSize: '0.875rem',
              fontWeight: 700,
              letterSpacing: '0.04em',
              color: isValid
                ? 'var(--color-allow)'
                : isTampered
                ? 'var(--color-block)'
                : 'var(--color-warn)',
            }}
          >
            AUDIT INTEGRITY: {status}
          </span>
        </div>

        <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          Verified Events: <strong style={{ color: 'var(--text-primary)' }}>{verifyResult.total_events}</strong>
        </div>
      </div>

      <div style={{ fontSize: '0.8125rem', color: isTampered ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
        {verifyResult.details}
      </div>

      {verifyResult.first_invalid_event && (
        <div style={{ fontSize: '0.75rem', color: 'var(--color-block)', fontWeight: 600 }}>
          First Compromised Event ID: <span className="mono-text">{verifyResult.first_invalid_event}</span>
        </div>
      )}
    </div>
  );
};
