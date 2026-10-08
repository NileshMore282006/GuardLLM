import React, { useState } from 'react';
import { KeyRound, Copy, Check, AlertOctagon, X } from 'lucide-react';

interface CredentialSecretRevealProps {
  credentialId: string;
  secret: string;
  principalId: string;
  tenantId: string;
  onDismiss: () => void;
}

export const CredentialSecretReveal: React.FC<CredentialSecretRevealProps> = ({
  credentialId,
  secret,
  principalId,
  tenantId,
  onDismiss,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 3000);
    } catch {
      // Fallback if clipboard API is restricted
      setCopied(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="secret-reveal-title"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(5, 8, 16, 0.9)',
        backdropFilter: 'blur(10px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 10000,
        padding: '1rem',
      }}
    >
      <div
        className="glass-panel"
        style={{
          width: '100%',
          maxWidth: '580px',
          border: '1px solid rgba(245, 158, 11, 0.5)',
          boxShadow: '0 25px 50px rgba(0, 0, 0, 0.9), 0 0 30px rgba(245, 158, 11, 0.15)',
          padding: '1.75rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '1.25rem',
          borderRadius: '14px',
          background: 'var(--bg-secondary)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div
              style={{
                padding: '0.6rem',
                borderRadius: '10px',
                background: 'rgba(245, 158, 11, 0.15)',
                color: 'var(--color-warn)',
              }}
            >
              <KeyRound size={24} />
            </div>
            <div>
              <h3 id="secret-reveal-title" style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                Credential Generated Successfully
              </h3>
              <span style={{ fontSize: '0.8125rem', color: 'var(--color-warn)', fontWeight: 600 }}>
                Credential secret shown once.
              </span>
            </div>
          </div>
          <button
            type="button"
            onClick={onDismiss}
            aria-label="Dismiss and clear secret"
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: '0.25rem',
            }}
          >
            <X size={18} />
          </button>
        </div>

        <div
          style={{
            background: 'rgba(245, 158, 11, 0.08)',
            border: '1px solid rgba(245, 158, 11, 0.25)',
            borderRadius: '8px',
            padding: '0.85rem 1rem',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '0.625rem',
          }}
        >
          <AlertOctagon size={18} style={{ color: 'var(--color-warn)', flexShrink: 0, marginTop: '2px' }} />
          <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
            <strong style={{ color: 'var(--color-warn)' }}>Important: </strong>
            This cryptographic secret will never be displayed again and cannot be recovered from the backend or browser storage. Store it securely in a dedicated secrets manager.
          </div>
        </div>

        <div style={{ background: 'var(--bg-tertiary)', padding: '1rem', borderRadius: '8px', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            <span>Principal: <strong style={{ color: 'var(--text-primary)' }}>{principalId}</strong></span>
            <span>Tenant: <strong style={{ color: 'var(--text-primary)' }}>{tenantId}</strong></span>
            <span>ID: <span className="mono-text" style={{ color: 'var(--text-secondary)' }}>{credentialId}</span></span>
          </div>

          <div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.35rem', letterSpacing: '0.05em' }}>
              Bearer Secret / Token
            </div>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '0.5rem 0.75rem',
              }}
            >
              <code
                className="mono-text"
                data-testid="credential-secret-value"
                style={{
                  flex: 1,
                  fontSize: '0.8125rem',
                  color: 'var(--color-allow)',
                  wordBreak: 'break-all',
                  userSelect: 'all',
                }}
              >
                {secret}
              </code>
              <button
                type="button"
                onClick={handleCopy}
                title="Copy secret to clipboard"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                  padding: '0.35rem 0.75rem',
                  background: copied ? 'var(--color-allow-bg)' : 'var(--bg-tertiary)',
                  border: `1px solid ${copied ? 'var(--color-allow-border)' : 'var(--border-subtle)'}`,
                  color: copied ? 'var(--color-allow)' : 'var(--text-secondary)',
                  borderRadius: '5px',
                  cursor: 'pointer',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  flexShrink: 0,
                  transition: 'all var(--transition-fast)',
                }}
              >
                {copied ? <Check size={14} /> : <Copy size={14} />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
          <button
            type="button"
            onClick={onDismiss}
            style={{
              padding: '0.55rem 1.5rem',
              fontSize: '0.875rem',
              fontWeight: 600,
              background: 'var(--color-accent)',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              cursor: 'pointer',
            }}
          >
            I have saved the secret
          </button>
        </div>
      </div>
    </div>
  );
};
