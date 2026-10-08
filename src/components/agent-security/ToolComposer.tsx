import React, { useState, useEffect } from 'react';
import { CONFIRMED_BACKEND_TOOLS, SECURITY_SCENARIOS, SecurityScenario } from './toolRegistry';
import { ToolDefinitionInfo } from '../../types/agentguard';
import { Wrench, Play, RotateCcw, AlertTriangle, CheckCircle, ShieldAlert } from 'lucide-react';

interface ToolComposerProps {
  selectedToolName: string;
  argumentsJson: string;
  onToolChange: (toolName: string, defaultArgsJson: string) => void;
  onArgumentsChange: (json: string) => void;
  onSubmit: () => void;
  isLoading: boolean;
  disabled?: boolean;
}

export const ToolComposer: React.FC<ToolComposerProps> = ({
  selectedToolName,
  argumentsJson,
  onToolChange,
  onArgumentsChange,
  onSubmit,
  isLoading,
  disabled = false,
}) => {
  const [jsonError, setJsonError] = useState<string | null>(null);

  const selectedTool: ToolDefinitionInfo =
    CONFIRMED_BACKEND_TOOLS.find((t) => t.tool_name === selectedToolName) ||
    CONFIRMED_BACKEND_TOOLS[0];

  // Validate JSON on user input without altering raw text
  useEffect(() => {
    if (!argumentsJson.trim()) {
      setJsonError('Tool arguments cannot be empty. Valid JSON object required.');
      return;
    }
    try {
      const parsed = JSON.parse(argumentsJson);
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        setJsonError('Tool arguments must be a valid JSON key-value object (e.g. { "key": "value" }).');
      } else {
        setJsonError(null);
      }
    } catch (err: unknown) {
      if (err instanceof Error) {
        setJsonError(`JSON Syntax Error: ${err.message}`);
      } else {
        setJsonError('Malformed JSON payload.');
      }
    }
  }, [argumentsJson]);

  const handleSelectTool = (toolName: string) => {
    const tool = CONFIRMED_BACKEND_TOOLS.find((t) => t.tool_name === toolName);
    if (tool) {
      const formattedDefault = JSON.stringify(tool.default_arguments, null, 2);
      onToolChange(toolName, formattedDefault);
    }
  };

  const handleSelectScenario = (scenario: SecurityScenario) => {
    onToolChange(scenario.tool_name, JSON.stringify(scenario.arguments, null, 2));
  };

  const handleResetToDefault = () => {
    onArgumentsChange(JSON.stringify(selectedTool.default_arguments, null, 2));
  };

  const isSubmitDisabled = disabled || isLoading || Boolean(jsonError);

  return (
    <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div
            style={{
              padding: '0.4rem',
              borderRadius: 'var(--radius-sm)',
              background: 'rgba(99, 102, 241, 0.15)',
              color: 'var(--color-accent)',
              display: 'flex',
              alignItems: 'center',
            }}
          >
            <Wrench size={18} />
          </div>
          <div>
            <h2 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Tool Request Composer
            </h2>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Propose a tool call to evaluate through AgentGuard Tool Authorization Gate
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span
            className={`status-badge ${selectedTool.risk_level}`}
            style={{ fontSize: '0.6875rem', textTransform: 'uppercase', padding: '0.2rem 0.6rem' }}
          >
            {selectedTool.risk_level} Risk (Backend Spec)
          </span>
          <span
            className="status-badge"
            style={{
              fontSize: '0.6875rem',
              background: selectedTool.side_effect ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
              color: selectedTool.side_effect ? '#f87171' : '#34d399',
              border: `1px solid ${selectedTool.side_effect ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`,
            }}
          >
            {selectedTool.side_effect ? 'Side-Effect (Mock)' : 'Read-Only'}
          </span>
        </div>
      </div>

      {/* Preset Test Scenarios */}
      <div>
        <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
          Quick Security Scenarios:
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
          {SECURITY_SCENARIOS.map((sc) => (
            <button
              key={sc.id}
              type="button"
              className="scenario-chip"
              onClick={() => handleSelectScenario(sc)}
              title={sc.description}
              style={{
                fontSize: '0.75rem',
                padding: '0.35rem 0.65rem',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(255, 255, 255, 0.04)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{sc.name}</span>
              <span style={{ fontSize: '0.65rem', opacity: 0.7, marginLeft: '0.35rem' }}>({sc.badge})</span>
            </button>
          ))}
        </div>
      </div>

      {/* Tool Selector */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
        <label htmlFor="tool-select" style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-secondary)' }}>
          Target Tool:
        </label>
        <select
          id="tool-select"
          value={selectedToolName}
          onChange={(e) => handleSelectTool(e.target.value)}
          disabled={disabled || isLoading}
          style={{
            background: 'var(--bg-input)',
            color: 'var(--text-primary)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
            padding: '0.65rem 0.85rem',
            fontSize: '0.875rem',
            fontFamily: 'var(--font-mono)',
            outline: 'none',
            cursor: 'pointer',
          }}
        >
          {CONFIRMED_BACKEND_TOOLS.map((t) => (
            <option key={t.tool_name} value={t.tool_name}>
              {t.tool_name} — [{t.risk_level.toUpperCase()} risk] {t.description}
            </option>
          ))}
        </select>
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          {selectedTool.description} (Controlled mock implementation; no real OS/network action)
        </div>
      </div>

      {/* Untrusted Arguments Notice */}
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: '0.6rem',
          padding: '0.65rem 0.85rem',
          borderRadius: 'var(--radius-md)',
          background: 'rgba(245, 158, 11, 0.08)',
          border: '1px solid rgba(245, 158, 11, 0.25)',
          color: '#fbbf24',
          fontSize: '0.75rem',
        }}
      >
        <ShieldAlert size={16} style={{ flexShrink: 0, marginTop: '0.1rem' }} />
        <div>
          <strong>Security Notice:</strong> Tool arguments are treated as <em>untrusted data</em>. They are
          scanned for prompt injection, secret exfiltration, and schema integrity by the AgentGuard Tool Guard.
        </div>
      </div>

      {/* Argument JSON Editor */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <label htmlFor="tool-arguments-editor" style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-secondary)' }}>
            Tool Arguments (JSON):
          </label>
          <button
            type="button"
            onClick={handleResetToDefault}
            disabled={disabled || isLoading}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              fontSize: '0.75rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.3rem',
            }}
          >
            <RotateCcw size={12} /> Reset to template
          </button>
        </div>

        <div style={{ position: 'relative' }}>
          <textarea
            id="tool-arguments-editor"
            value={argumentsJson}
            onChange={(e) => onArgumentsChange(e.target.value)}
            disabled={disabled || isLoading}
            rows={7}
            placeholder='{\n  "key": "value"\n}'
            spellCheck={false}
            style={{
              width: '100%',
              background: 'var(--bg-input)',
              color: jsonError ? '#fca5a5' : '#e2e8f0',
              border: `1px solid ${jsonError ? 'var(--color-block)' : 'var(--border-subtle)'}`,
              borderRadius: 'var(--radius-md)',
              padding: '0.75rem',
              fontSize: '0.8125rem',
              fontFamily: 'var(--font-mono)',
              lineHeight: 1.5,
              resize: 'vertical',
              outline: 'none',
              transition: 'border-color 0.15s ease',
            }}
          />
        </div>

        {jsonError ? (
          <div
            id="tool-arguments-error"
            role="alert"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              color: 'var(--color-block)',
              fontSize: '0.75rem',
            }}
          >
            <AlertTriangle size={13} />
            <span>{jsonError}</span>
          </div>
        ) : (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              color: 'var(--color-allow)',
              fontSize: '0.75rem',
            }}
          >
            <CheckCircle size={13} />
            <span>Valid JSON format (ready for server authorization)</span>
          </div>
        )}
      </div>

      {/* Action Button */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
        <button
          type="button"
          id="btn-analyze-tool"
          onClick={onSubmit}
          disabled={isSubmitDisabled}
          className="btn-primary"
          style={{
            padding: '0.65rem 1.25rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            fontSize: '0.875rem',
            fontWeight: 600,
            cursor: isSubmitDisabled ? 'not-allowed' : 'pointer',
            opacity: isSubmitDisabled ? 0.5 : 1,
          }}
        >
          {isLoading ? (
            <>
              <span className="spinner-border" />
              <span>Analyzing Tool Request...</span>
            </>
          ) : (
            <>
              <Play size={16} />
              <span>Analyze Tool Request</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};
