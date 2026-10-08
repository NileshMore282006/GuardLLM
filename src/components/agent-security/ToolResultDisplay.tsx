import React from 'react';
import { Terminal, Shield, Lock, AlertTriangle } from 'lucide-react';

interface ToolResultDisplayProps {
  toolName: string;
  result: string | null;
  isSanitized?: boolean;
  attackType?: string | null;
}

export const ToolResultDisplay: React.FC<ToolResultDisplayProps> = ({
  toolName,
  result,
  isSanitized = true,
  attackType,
}) => {
  if (result === null || result === undefined) {
    return null;
  }

  const isIndirectInjection = attackType === 'indirect_prompt_injection' || result.includes('UNTRUSTED TOOL DATA FILTERED');

  return (
    <div
      className="glass-panel"
      id="tool-result-panel"
      style={{
        padding: '1.25rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.85rem',
        border: '1px solid var(--border-subtle)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Terminal size={17} style={{ color: 'var(--color-accent)' }} />
          <div>
            <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Tool Execution Output
            </h3>
            <p style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
              Treated strictly as UNTRUSTED DATA — Never elevated to privileged instruction
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <span
            style={{
              fontSize: '0.6875rem',
              fontWeight: 700,
              padding: '0.2rem 0.55rem',
              borderRadius: 'var(--radius-sm)',
              background: 'rgba(99, 102, 241, 0.15)',
              color: 'var(--color-accent)',
              border: '1px solid rgba(99, 102, 241, 0.3)',
              display: 'flex',
              alignItems: 'center',
              gap: '0.3rem',
            }}
          >
            <Lock size={11} />
            <span>UNTRUSTED DATA</span>
          </span>

          {isSanitized && (
            <span
              style={{
                fontSize: '0.6875rem',
                fontWeight: 600,
                padding: '0.2rem 0.55rem',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(16, 185, 129, 0.12)',
                color: 'var(--color-allow)',
                border: '1px solid var(--color-allow-border)',
                display: 'flex',
                alignItems: 'center',
                gap: '0.3rem',
              }}
            >
              <Shield size={11} />
              <span>SANITIZED</span>
            </span>
          )}
        </div>
      </div>

      {isIndirectInjection && (
        <div
          role="alert"
          style={{
            padding: '0.6rem 0.75rem',
            borderRadius: 'var(--radius-sm)',
            background: 'rgba(245, 158, 11, 0.1)',
            border: '1px solid rgba(245, 158, 11, 0.3)',
            color: '#fbbf24',
            fontSize: '0.75rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <AlertTriangle size={15} style={{ flexShrink: 0 }} />
          <span>
            <strong>Indirect Injection Detected:</strong> AgentGuard sanitized untrusted tool output,
            neutralizing attempt to inject system directives or extract canary secrets.
          </span>
        </div>
      )}

      {/* Untrusted Data Container - strictly text, no HTML parsing, no script execution */}
      <div
        id="tool-untrusted-result-content"
        style={{
          background: 'rgba(0, 0, 0, 0.45)',
          borderRadius: 'var(--radius-md)',
          padding: '0.85rem 1rem',
          border: '1px solid var(--border-subtle)',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.8125rem',
          color: '#e2e8f0',
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
          lineHeight: 1.5,
          userSelect: 'text',
        }}
      >
        <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem', marginBottom: '0.35rem' }}>
          [TOOL RESULT from {toolName} (UNTRUSTED DATA)]
        </div>
        {result}
        <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem', marginTop: '0.35rem' }}>
          [END TOOL RESULT]
        </div>
      </div>
    </div>
  );
};
