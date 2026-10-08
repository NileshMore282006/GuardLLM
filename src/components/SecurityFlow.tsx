import React from 'react';
import { SecurityFlowState } from '../types/agentguard';
import { User, Shield, ShieldCheck, ShieldAlert, Cpu, CheckCircle2, AlertTriangle, Loader2 } from 'lucide-react';

interface SecurityFlowProps {
  flowState: SecurityFlowState;
}

export const SecurityFlow: React.FC<SecurityFlowProps> = ({ flowState }) => {
  const isAnalyzing = flowState === 'ANALYZING';
  const isAllowed = flowState === 'ALLOWED' || flowState === 'EXECUTING' || flowState === 'COMPLETED';
  const isBlocked = flowState === 'BLOCKED';
  const isExecuting = flowState === 'EXECUTING';
  const isCompleted = flowState === 'COMPLETED';
  const isError = flowState === 'ERROR';

  return (
    <div className="glass-panel flow-container" aria-label="Security Execution Flow">
      <div className="flow-title">
        <span>Security Pipeline Architecture</span>
        <span className="mono-text" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          State: {flowState}
        </span>
      </div>

      <div className="flow-steps">
        {/* Step 1: User Input */}
        <div className={`flow-step-node ${flowState !== 'IDLE' ? 'active' : ''}`}>
          <div className="step-icon-bubble">
            <User size={20} />
          </div>
          <span className="step-label">User Input</span>
          <span className="step-subtext">Untrusted Prompt</span>
        </div>

        {/* Connector 1 */}
        <div
          className={`flow-connector-line ${
            flowState !== 'IDLE' ? (isBlocked ? 'blocked' : isAllowed ? 'allowed' : 'active') : ''
          }`}
        />

        {/* Step 2: AgentGuard Gateway */}
        <div
          className={`flow-step-node ${
            isAnalyzing
              ? 'active'
              : isAllowed
              ? 'allowed'
              : isBlocked
              ? 'blocked'
              : isError
              ? 'blocked'
              : ''
          }`}
        >
          <div className="step-icon-bubble">
            {isAnalyzing ? (
              <Loader2 size={20} className="spinner-icon" />
            ) : isBlocked ? (
              <ShieldAlert size={20} />
            ) : isAllowed ? (
              <ShieldCheck size={20} />
            ) : isError ? (
              <AlertTriangle size={20} />
            ) : (
              <Shield size={20} />
            )}
          </div>
          <span className="step-label">AgentGuard</span>
          <span className="step-subtext">Multi-Layer Guard</span>
        </div>

        {/* Connector 2 */}
        <div
          className={`flow-connector-line ${
            isAllowed ? (isCompleted ? 'allowed' : 'active') : isBlocked ? 'blocked' : ''
          }`}
        />

        {/* Step 3: Decision / Gate */}
        <div
          className={`flow-step-node ${
            isAllowed ? 'allowed' : isBlocked ? 'blocked' : isError ? 'blocked' : ''
          }`}
        >
          <div className="step-icon-bubble">
            {isAllowed ? (
              <ShieldCheck size={20} />
            ) : isBlocked ? (
              <ShieldAlert size={20} />
            ) : (
              <Shield size={20} />
            )}
          </div>
          <span className="step-label">
            {isBlocked
              ? 'BLOCKED'
              : isAllowed
              ? 'ALLOWED'
              : isError
              ? 'ERROR'
              : 'Decision'}
          </span>
          <span className="step-subtext">
            {isBlocked
              ? 'Neutralized'
              : isAllowed
              ? 'Permitted'
              : isError
              ? 'Fail-Closed'
              : 'Policy Engine'}
          </span>
        </div>

        {/* Connector 3 */}
        <div
          className={`flow-connector-line ${
            isCompleted ? 'allowed' : isExecuting ? 'active' : ''
          }`}
        />

        {/* Step 4: Target LLM Execution */}
        <div
          className={`flow-step-node ${
            isCompleted ? 'allowed' : isExecuting ? 'active' : isBlocked ? '' : ''
          }`}
          style={{ opacity: isBlocked ? 0.4 : 1 }}
        >
          <div className="step-icon-bubble">
            {isExecuting ? (
              <Loader2 size={20} className="spinner-icon" />
            ) : isCompleted ? (
              <CheckCircle2 size={20} />
            ) : (
              <Cpu size={20} />
            )}
          </div>
          <span className="step-label">
            {isBlocked ? 'Not Invoked' : 'Target LLM'}
          </span>
          <span className="step-subtext">
            {isBlocked
              ? 'Protected'
              : isCompleted
              ? 'Completed'
              : isExecuting
              ? 'Generating'
              : 'Guarded Model'}
          </span>
        </div>
      </div>
    </div>
  );
};
