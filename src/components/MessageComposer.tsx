import React from 'react';
import { Send, Square } from 'lucide-react';

interface MessageComposerProps {
  input: string;
  setInput: (value: string) => void;
  onSend: () => void;
  isLoading: boolean;
  onCancel: () => void;
}

export const MessageComposer: React.FC<MessageComposerProps> = ({
  input,
  setInput,
  onSend,
  isLoading,
  onCancel,
}) => {
  const isInputEmpty = !input.trim();

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    // Enter without Shift sends, Ctrl+Enter or Cmd+Enter also sends
    if (e.key === 'Enter') {
      if ((e.ctrlKey || e.metaKey) || !e.shiftKey) {
        e.preventDefault();
        if (!isLoading && !isInputEmpty) {
          onSend();
        }
      }
    }
  };

  return (
    <div className="composer-container glass-panel">
      <div className="composer-input-row">
        <label htmlFor="chat-message-input" className="sr-only" style={{ display: 'none' }}>
          Message to send
        </label>
        <textarea
          id="chat-message-input"
          className="composer-textarea"
          placeholder="Send a message to AgentGuard Multi-Turn Chat..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={isLoading}
          rows={3}
          aria-label="Multi-turn chat message"
        />

        <div className="composer-actions">
          {isLoading ? (
            <button
              type="button"
              className="btn-stop"
              onClick={onCancel}
              title="Cancel request locally"
              aria-label="Cancel in-flight request"
            >
              <Square size={14} />
              <span>Cancel</span>
            </button>
          ) : (
            <button
              type="button"
              className="btn-primary btn-send"
              onClick={onSend}
              disabled={isLoading || isInputEmpty}
              aria-label="Send message"
            >
              <Send size={15} />
              <span>Send</span>
            </button>
          )}
        </div>
      </div>

      <div className="composer-footer">
        <div className="composer-hint text-muted">
          <span>Press</span>
          <kbd className="kbd-badge">Enter</kbd>
          <span>to send,</span>
          <kbd className="kbd-badge">Shift</kbd>
          <span>+</span>
          <kbd className="kbd-badge">Enter</kbd>
          <span>for newline</span>
        </div>

        <div className="composer-counter text-muted">
          {input.length} characters
        </div>
      </div>
    </div>
  );
};
