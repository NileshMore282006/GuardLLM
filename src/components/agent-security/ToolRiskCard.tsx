import React from 'react';
import { ToolRiskLevel, ToolSecurityDecision, ApprovalStatus } from '../../types/agentguard';
import { Shield, ShieldAlert, AlertTriangle, CheckCircle, Info } from 'lucide-react';

interface ToolRiskCardProps {
  decision: ToolSecurityDecision | null;
  riskLevel: ToolRiskLevel | null;
  approvalStatus: ApprovalStatus | null;
  attackType?: string | null;
  latencyMs?: number | null;
  reason?: string | null;
}

export const ToolRiskCard: React.FC<ToolRiskCardProps> = ({
  decision,
  riskLevel,
  approvalStatus,
  attackType,
  latencyMs,
  reason,
}) => {
  if (!decision && !riskLevel) {
    return null;
  }

  const getRiskColor = (level: ToolRiskLevel | null) => {
    switch (level?.toLowerCase()) {
      case 'low':
        return { text: '#10b981', bg: 'rgba(16, 185, 129, 0.1)', border: 'rgba(16, 185, 129, 0.3)' };
      case 'medium':
        return { text: '#f59e0b', bg: 'rgba(245, 158, 11, 0.1)', border: 'rgba(245, 158, 11, 0.3)' };
      case 'high':
        return { text: '#f97316', bg: 'rgba(249, 115, 22, 0.1)', border: 'rgba(249, 115, 22, 0.3)' };
      case 'critical':
        return { text: '#ef4444', bg: 'rgba(239, 68, 68, 0.15)', border: 'rgba(239, 68, 68, 0.4)' };
      default:
        return { text: 'var(--text-muted)', bg: 'rgba(255, 255, 255, 0.05)', border: 'var(--border-subtle)' };
    }
  };

  const getDecisionBadge = (dec: ToolSecurityDecision | null) => {
    switch (dec) {
      case 'ALLOW':
        return { text: 'ALLOW', color: 'var(--color-allow)', bg: 'var(--color-allow-bg)', border: 'var(--color-allow-border)', icon: <CheckCircle size={14} /> };
      case 'BLOCK':
        return { text: 'BLOCK', color: 'var(--color-block)', bg: 'var(--color-block-bg)', border: 'var(--color-block-border)', icon: <ShieldAlert size={14} /> };
      case 'PENDING_APPROVAL':
        return { text: 'PENDING APPROVAL', color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.15)', border: 'rgba(245, 158, 11, 0.3)', icon: <AlertTriangle size={14} /> };
      case 'ERROR':
        return { text: 'ERROR', color: '#f87171', bg: 'rgba(239, 68, 68, 0.1)', border: 'rgba(239, 68, 68, 0.3)', icon: <AlertTriangle size={14} /> };
      default:
        return { text: 'EVALUATING', color: 'var(--text-muted)', bg: 'rgba(255, 255, 255, 0.05)', border: 'var(--border-subtle)', icon: <Info size={14} /> };
    }
  };

  const riskStyle = getRiskColor(riskLevel);
  const decisionBadge = getDecisionBadge(decision);

  return (
    <div
      className="glass-panel"
      id="tool-risk-card"
      style={{
        padding: '1.25rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.85rem',
        border: decision === 'BLOCK' ? '1px solid var(--color-block-border)' : '1px solid var(--border-subtle)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Shield size={18} style={{ color: decisionBadge.color }} />
          <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Security Evaluation
          </h3>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span
            id="tool-decision-badge"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.35rem',
              fontSize: '0.75rem',
              fontWeight: 700,
              padding: '0.25rem 0.6rem',
              borderRadius: 'var(--radius-sm)',
              background: decisionBadge.bg,
              color: decisionBadge.color,
              border: `1px solid ${decisionBadge.border}`,
            }}
          >
            {decisionBadge.icon}
            <span>{decisionBadge.text}</span>
          </span>

          {riskLevel && (
            <span
              id="tool-risk-level-badge"
              style={{
                fontSize: '0.75rem',
                fontWeight: 700,
                textTransform: 'uppercase',
                padding: '0.25rem 0.6rem',
                borderRadius: 'var(--radius-sm)',
                background: riskStyle.bg,
                color: riskStyle.text,
                border: `1px solid ${riskStyle.border}`,
              }}
            >
              {riskLevel} RISK
            </span>
          )}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.5rem', fontSize: '0.75rem' }}>
        <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.5rem 0.65rem', borderRadius: 'var(--radius-sm)' }}>
          <div style={{ color: 'var(--text-muted)' }}>Approval State</div>
          <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
            {approvalStatus || 'N/A'}
          </div>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.5rem 0.65rem', borderRadius: 'var(--radius-sm)' }}>
          <div style={{ color: 'var(--text-muted)' }}>Attack Taxonomy</div>
          <div style={{ fontWeight: 600, color: attackType && attackType !== 'none' ? 'var(--color-block)' : 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
            {attackType || 'none'}
          </div>
        </div>

        {latencyMs !== undefined && latencyMs !== null && (
          <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.5rem 0.65rem', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ color: 'var(--text-muted)' }}>Evaluation Latency</div>
            <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
              {latencyMs.toFixed(1)} ms
            </div>
          </div>
        )}
      </div>

      {reason && (
        <div
          style={{
            fontSize: '0.75rem',
            color: 'var(--text-secondary)',
            background: 'rgba(255, 255, 255, 0.02)',
            padding: '0.5rem 0.75rem',
            borderRadius: 'var(--radius-sm)',
            borderLeft: `2px solid ${decisionBadge.color}`,
          }}
        >
          <strong>Reason:</strong> {reason}
        </div>
      )}
    </div>
  );
};
