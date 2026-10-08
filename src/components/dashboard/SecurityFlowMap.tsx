import React from 'react';
import { AuditEventItem } from '../../types/agentguard';
import {
  ArrowRight,
  Shield,
  Lock,
  FileCheck,
  Cpu,
  Wrench,
  Bot,
  Sparkles,
  Database,
  AlertOctagon,
} from 'lucide-react';

interface SecurityFlowMapProps {
  selectedEvent: AuditEventItem | null;
}

export const SecurityFlowMap: React.FC<SecurityFlowMapProps> = ({ selectedEvent }) => {
  // Determine stage states based on selectedEvent telemetry
  const isBlocked = selectedEvent?.decision === 'BLOCK';
  const action = selectedEvent?.action || '';
  const resourceType = selectedEvent?.resource_type || '';

  // Determine which stage was the decision point or stopping point
  let blockingStage: string | null = null;
  if (isBlocked) {
    if (action.startsWith('auth_') || action === 'auth_failure') {
      blockingStage = 'AUTH_TENANT';
    } else if (action === 'policy_deny') {
      blockingStage = 'POLICY';
    } else if (action === 'guard_block' || action === 'guard_error') {
      blockingStage = 'GUARD';
    } else if (action === 'tool_block' || action === 'approval_deny' || action === 'approval_replay') {
      blockingStage = 'TOOL_APPROVAL';
    } else {
      blockingStage = 'GUARD';
    }
  }

  const getStageStatus = (stageId: string): 'passed' | 'blocked' | 'skipped' | 'neutral' => {
    if (!selectedEvent) return 'neutral';

    if (stageId === 'REQUEST' || stageId === 'HTTP_BOUNDARY') {
      return 'passed';
    }

    if (stageId === 'AUTH_TENANT') {
      if (blockingStage === 'AUTH_TENANT') return 'blocked';
      return 'passed';
    }

    if (blockingStage === 'AUTH_TENANT') return 'skipped';

    if (stageId === 'POLICY') {
      if (blockingStage === 'POLICY') return 'blocked';
      return 'passed';
    }

    if (blockingStage === 'POLICY') return 'skipped';

    if (stageId === 'GUARD') {
      if (blockingStage === 'GUARD') return 'blocked';
      return 'passed';
    }

    if (blockingStage === 'GUARD') return 'skipped';

    if (stageId === 'TOOL_APPROVAL') {
      if (resourceType === 'tool' || selectedEvent.tool_name || selectedEvent.approval_id) {
        if (blockingStage === 'TOOL_APPROVAL') return 'blocked';
        return 'passed';
      }
      return 'skipped';
    }

    if (blockingStage === 'TOOL_APPROVAL') return 'skipped';

    if (stageId === 'TARGET') {
      if (action === 'target_execute' || action === 'chat_execute') {
        return 'passed';
      }
      return 'skipped';
    }

    if (stageId === 'OUTPUT_SANITIZER') {
      if (action === 'target_execute' || action === 'chat_execute') {
        return 'passed';
      }
      return 'skipped';
    }

    if (stageId === 'AUDIT') {
      // The audit record exists in the audit log!
      return 'passed';
    }

    return 'neutral';
  };

  const stages = [
    { id: 'REQUEST', label: 'Client Request', icon: Cpu },
    { id: 'HTTP_BOUNDARY', label: 'HTTP Boundary', icon: Lock },
    { id: 'AUTH_TENANT', label: 'Auth & Tenant', icon: Shield },
    { id: 'POLICY', label: 'Policy Check', icon: FileCheck },
    { id: 'GUARD', label: 'Guard Model', icon: AlertOctagon },
    { id: 'TOOL_APPROVAL', label: 'Tool / Approval', icon: Wrench },
    { id: 'TARGET', label: 'Target Model', icon: Bot },
    { id: 'OUTPUT_SANITIZER', label: 'Output Sanitizer', icon: Sparkles },
    { id: 'AUDIT', label: 'Audit Chain', icon: Database },
  ];

  return (
    <div className="glass-panel security-flow-map" style={{ padding: '1rem', marginTop: '1rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
        <div>
          <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Security Perimeter Lifecycle Observation
          </span>
          <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>
            {selectedEvent ? `Telemetry visualization for event ${selectedEvent.event_id}` : 'Select an event below to trace execution pipeline'}
          </span>
        </div>
        <span style={{ fontSize: '0.625rem', color: 'var(--text-muted)', background: 'var(--bg-tertiary)', padding: '0.15rem 0.4rem', borderRadius: '4px' }}>
          Observational Only — Non-Bypassing
        </span>
      </div>

      <div
        className="flow-stages-row"
        style={{
          display: 'flex',
          alignItems: 'center',
          overflowX: 'auto',
          paddingBottom: '0.5rem',
          gap: '0.4rem',
        }}
      >
        {stages.map((stg, idx) => {
          const status = getStageStatus(stg.id);
          const Icon = stg.icon;

          let bg = 'var(--bg-tertiary)';
          let border = 'var(--border-subtle)';
          let color = 'var(--text-muted)';

          if (status === 'passed') {
            bg = 'rgba(16, 185, 129, 0.12)';
            border = 'rgba(16, 185, 129, 0.35)';
            color = 'var(--color-allow)';
          } else if (status === 'blocked') {
            bg = 'rgba(239, 68, 68, 0.18)';
            border = 'rgba(239, 68, 68, 0.5)';
            color = 'var(--color-block)';
          } else if (status === 'skipped') {
            bg = 'rgba(255, 255, 255, 0.02)';
            border = 'rgba(255, 255, 255, 0.04)';
            color = 'var(--text-dim)';
          }

          return (
            <React.Fragment key={stg.id}>
              <div
                className="flow-stage-pill"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem',
                  padding: '0.4rem 0.65rem',
                  borderRadius: '6px',
                  background: bg,
                  border: `1px solid ${border}`,
                  color: color,
                  whiteSpace: 'nowrap',
                  fontSize: '0.6875rem',
                  fontWeight: 600,
                  transition: 'all var(--transition-fast)',
                }}
              >
                <Icon size={13} />
                <span>{stg.label}</span>
                {status === 'blocked' && (
                  <span style={{ fontSize: '0.5625rem', background: 'var(--color-block)', color: '#fff', padding: '0.05rem 0.25rem', borderRadius: '3px' }}>
                    BLOCKED
                  </span>
                )}
              </div>
              {idx < stages.length - 1 && (
                <ArrowRight size={11} color="var(--text-dim)" style={{ flexShrink: 0 }} />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
};
