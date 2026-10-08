import React, { useRef, useEffect } from 'react';
import { ChatTurn } from '../types/agentguard';
import { MessageBubble } from './MessageBubble';
import { MessageComposer } from './MessageComposer';
import { SecurityScenarios } from './SecurityScenarios';
import { PlusCircle, Loader2, AlertCircle, MessageSquare } from 'lucide-react';

interface ChatWindowProps {
  conversationId: string;
  turns: ChatTurn[];
  isLoading: boolean;
  onSendMessage: (text: string) => void;
  onNewConversation: () => void;
  onCancelRequest: () => void;
  input: string;
  setInput: (value: string) => void;
  errorMessage: string | null;
}

export const ChatWindow: React.FC<ChatWindowProps> = ({
  conversationId,
  turns,
  isLoading,
  onSendMessage,
  onNewConversation,
  onCancelRequest,
  input,
  setInput,
  errorMessage,
}) => {
  const scrollEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to latest turn or loading indicator
  useEffect(() => {
    if (typeof scrollEndRef.current?.scrollIntoView === 'function') {
      scrollEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [turns, isLoading, errorMessage]);

  const handleSend = () => {
    if (!input.trim() || isLoading) return;
    onSendMessage(input.trim());
  };

  const handleSelectScenarioPrompt = (scenarioPrompt: string) => {
    setInput(scenarioPrompt);
  };

  return (
    <div className="chat-window-container glass-panel">
      {/* 1. Chat Window Header Bar */}
      <div className="chat-header-bar">
        <div className="chat-header-left">
          <button
            type="button"
            className="btn-new-chat"
            onClick={onNewConversation}
            disabled={isLoading}
            title="Start a new conversation session"
          >
            <PlusCircle size={15} />
            <span>New Conversation</span>
          </button>

          <span className="conv-id-chip mono-text" title={`Conversation ID: ${conversationId}`}>
            {conversationId ? conversationId.substring(0, 18) + '...' : 'conv-new'}
          </span>
        </div>

        <div className="chat-header-right">
          <span className="turns-count-chip">
            {turns.length} {turns.length === 1 ? 'Turn' : 'Turns'}
          </span>
        </div>
      </div>

      {/* 2. Messages Stream */}
      <div className="chat-messages-stream" role="log" aria-live="polite">
        {turns.length === 0 ? (
          <div className="chat-empty-state">
            <div className="empty-state-icon">
              <MessageSquare size={36} color="var(--color-accent)" />
            </div>
            <h3 className="empty-state-title">Multi-Turn AI Security Chat</h3>
            <p className="empty-state-desc">
              Interact with the guarded target LLM across multiple conversational turns.
              AgentGuard continuously assesses cross-turn intent and context manipulation.
            </p>
            <div className="empty-state-hint">
              <span>Select a scenario below or type a message to start.</span>
            </div>
          </div>
        ) : (
          turns.map((turn) => <MessageBubble key={turn.id} turn={turn} />)
        )}

        {/* Loading in-flight indicator */}
        {isLoading && (
          <div className="chat-turn-container loading-turn-row" aria-busy="true">
            <div className="loading-turn-pill glass-panel">
              <Loader2 size={16} className="spinner-icon" />
              <span>Analyzing context with AgentGuard & evaluating guard policies...</span>
            </div>
          </div>
        )}

        {/* Error Notification */}
        {errorMessage && (
          <div className="alert-box danger chat-error-alert" role="alert">
            <AlertCircle size={18} style={{ flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 600 }}>Security Gateway Notice</div>
              <div style={{ fontSize: '0.8125rem' }}>{errorMessage}</div>
            </div>
          </div>
        )}

        <div ref={scrollEndRef} />
      </div>

      {/* 3. Safe Test Scenarios Bar */}
      <SecurityScenarios
        onSelectPrompt={handleSelectScenarioPrompt}
        disabled={isLoading}
      />

      {/* 4. Message Composer */}
      <MessageComposer
        input={input}
        setInput={setInput}
        onSend={handleSend}
        isLoading={isLoading}
        onCancel={onCancelRequest}
      />
    </div>
  );
};
