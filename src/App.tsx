import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  HealthResponse,
  GuardResponse,
  ExecuteResponse,
  SecurityFlowState,
  HistoryItem,
  ChatMessage,
  ChatTurn,
  TurnSecurityMetadata,
  AppMode,
  ConversationSummary,
} from './types/agentguard';
import { agentGuardApi, AgentGuardApiError } from './api/agentguard';
import { Header, TopBar } from './components/Header';
import { ChatWindow } from './components/ChatWindow';
import { SecurityPanel } from './components/SecurityPanel';
import { SecurityFlow } from './components/SecurityFlow';
import { PromptInput } from './components/PromptInput';
import { SecurityDecision } from './components/SecurityDecision';
import { ExecutionResult } from './components/ExecutionResult';
import { RequestHistory } from './components/RequestHistory';
import { AgentSecurityView } from './components/agent-security/AgentSecurityView';
import { SecurityDashboard } from './components/dashboard/SecurityDashboard';
import { AdministrationView } from './components/admin/AdministrationView';
import { SecurityOperationsView } from './components/secops/SecurityOperationsView';
import { AlertCircle } from 'lucide-react';
import { SessionProvider, useSession } from './context/SessionContext';
import { DegradedModeBanner } from './components/common/DegradedModeBanner';

interface AppProps {
  initialMode?: AppMode;
}

export const AppContent: React.FC<AppProps> = ({ initialMode = 'chat' }) => {
  // Application Mode (v0.2 Chat vs v0.1 Security Playground)
  const [mode, setMode] = useState<AppMode>(initialMode);

  // Theme State ('light' vs 'dark')
  const [theme, setTheme] = useState<'light' | 'dark'>('light');

  const handleToggleTheme = () => {
    setTheme((prev) => {
      const nextTheme = prev === 'light' ? 'dark' : 'light';
      if (typeof document !== 'undefined') {
        document.documentElement.setAttribute('data-theme', nextTheme);
        document.body.setAttribute('data-theme', nextTheme);
      }
      return nextTheme;
    });
  };

  // System Health
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [isOnline, setIsOnline] = useState<boolean>(false);
  const [isHealthLoading, setIsHealthLoading] = useState<boolean>(true);

  // Central Session Hooks
  const { setToken, handleApiError } = useSession();

  // =========================================================================
  // Multi-Turn Chat State (v0.2)
  // =========================================================================
  const [conversationId, setConversationId] = useState<string>(
    () => `conv-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 7)}`
  );
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [conversations, setConversations] = useState<ConversationSummary[]>([]);
  const [chatInput, setChatInput] = useState<string>('');
  const [isChatLoading, setIsChatLoading] = useState<boolean>(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const [chatFlowState, setChatFlowState] = useState<SecurityFlowState>('IDLE');
  const [developerToken, setDeveloperToken] = useState<string>('');
  const abortControllerRef = useRef<AbortController | null>(null);

  const loadConversations = useCallback(async () => {
    try {
      const list = await agentGuardApi.listConversations();
      if (Array.isArray(list)) {
        setConversations(list);
      }
    } catch {
      // In offline or fallback mode
    }
  }, []);

  useEffect(() => {
    loadConversations();
  }, [loadConversations]);

  const handleDeveloperTokenChange = (token: string) => {
    setDeveloperToken(token);
    setToken(token);
  };

  // =========================================================================
  // Playground Interaction State (v0.1 Backward Compatibility)
  // =========================================================================
  const [prompt, setPrompt] = useState<string>('');
  const [playgroundFlowState, setPlaygroundFlowState] = useState<SecurityFlowState>('IDLE');
  const [isPlaygroundLoading, setIsPlaygroundLoading] = useState<boolean>(false);
  const [isPlaygroundExecuting, setIsPlaygroundExecuting] = useState<boolean>(false);
  const [playgroundError, setPlaygroundError] = useState<string | null>(null);
  const [guardResult, setGuardResult] = useState<GuardResponse | null>(null);
  const [executionResult, setExecutionResult] = useState<ExecuteResponse | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);

  // 1. Health Status Polling with Visibility Check & Concurrency Guard (v0.7)
  const isCheckingHealthRef = useRef<boolean>(false);
  const checkHealth = useCallback(async () => {
    if (isCheckingHealthRef.current) return;
    isCheckingHealthRef.current = true;
    try {
      const data = await agentGuardApi.health();
      setHealth(data);
      setIsOnline(true);
    } catch (err) {
      setIsOnline(false);
      handleApiError(err);
    } finally {
      setIsHealthLoading(false);
      isCheckingHealthRef.current = false;
    }
  }, [handleApiError]);

  useEffect(() => {
    checkHealth();
    const interval = setInterval(() => {
      // Pause polling if document is hidden to prevent background request storms
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') {
        return;
      }
      checkHealth();
    }, 15000);

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        checkHealth();
      }
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      clearInterval(interval);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [checkHealth]);

  // =========================================================================
  // Multi-Turn Chat Actions
  // =========================================================================

  const handleSendChatMessage = async (text: string) => {
    if (!text.trim() || isChatLoading) return;

    const userMessage: ChatMessage = { role: 'user', content: text.trim() };
    const nextMessages: ChatMessage[] = [...chatMessages, userMessage];

    // Clear composer input and error
    setChatInput('');
    setChatError(null);
    setIsChatLoading(true);
    setChatFlowState('ANALYZING');

    const abortController = new AbortController();
    abortControllerRef.current = abortController;
    const turnNumber = turns.length + 1;

    try {
      // Send complete canonical conversation sequence to POST /api/v1/chat
      const resp = await agentGuardApi.chat(
        nextMessages,
        conversationId,
        abortController.signal,
        developerToken
      );

      const turnSecurity: TurnSecurityMetadata = {
        decision: resp.decision,
        risk_score: resp.risk_score,
        attack_type: resp.attack_type,
        guard_model: resp.guard_model,
        target_model: resp.target_model,
        request_id: resp.request_id,
        latency_ms: resp.latency_ms,
      };

      if (resp.decision === 'ALLOW') {
        setChatFlowState('COMPLETED');
        const assistantMessage: ChatMessage = {
          role: 'assistant',
          content: resp.response || '',
        };
        // Update conversation context with allowed turn
        setChatMessages([...nextMessages, assistantMessage]);

        const newTurn: ChatTurn = {
          id: resp.request_id || `turn-${Date.now()}`,
          turnNumber,
          userMessage: text.trim(),
          assistantResponse: resp.response,
          security: turnSecurity,
          timestamp: new Date().toLocaleTimeString(),
        };
        setTurns((prev) => [...prev, newTurn]);
      } else if (resp.decision === 'BLOCK') {
        setChatFlowState('BLOCKED');
        // SECURITY INVARIANT: Target NOT invoked; do NOT fabricate assistant response!
        // Do not add assistant message to conversation context.
        const newTurn: ChatTurn = {
          id: resp.request_id || `turn-${Date.now()}`,
          turnNumber,
          userMessage: text.trim(),
          assistantResponse: null,
          security: turnSecurity,
          timestamp: new Date().toLocaleTimeString(),
        };
        setTurns((prev) => [...prev, newTurn]);
      } else {
        setChatFlowState('ERROR');
        const newTurn: ChatTurn = {
          id: resp.request_id || `turn-${Date.now()}`,
          turnNumber,
          userMessage: text.trim(),
          assistantResponse: null,
          security: turnSecurity,
          timestamp: new Date().toLocaleTimeString(),
        };
        setTurns((prev) => [...prev, newTurn]);
      }
      loadConversations();
    } catch (err: unknown) {
      setChatFlowState('ERROR');
      if (err instanceof AgentGuardApiError) {
        setChatError(err.message);
      } else {
        setChatError('Failed to communicate with AgentGuard chat gateway.');
      }
      // Preserve message in composer so user does not lose their input
      setChatInput(text);
    } finally {
      setIsChatLoading(false);
      abortControllerRef.current = null;
    }
  };

  const handleSelectConversation = async (selectedId: string) => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    setIsChatLoading(true);
    try {
      const detail = await agentGuardApi.getConversation(selectedId);
      if (detail && detail.conversation_id) {
        setConversationId(detail.conversation_id);
        setTurns(detail.turns || []);
        const reconstructed: ChatMessage[] = [];
        for (const t of detail.turns || []) {
          reconstructed.push({ role: 'user', content: t.userMessage });
          if (t.assistantResponse && t.security?.decision === 'ALLOW') {
            reconstructed.push({ role: 'assistant', content: t.assistantResponse });
          }
        }
        setChatMessages(reconstructed);
        setChatError(null);
        setChatFlowState(
          detail.turns && detail.turns.length > 0
            ? detail.turns[detail.turns.length - 1].security?.decision === 'ALLOW'
              ? 'COMPLETED'
              : 'BLOCKED'
            : 'IDLE'
        );
      }
    } catch (err) {
      console.warn('Could not load conversation from SQLite:', err);
    } finally {
      setIsChatLoading(false);
      setMode('chat');
    }
  };

  const handleNewConversation = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    setConversationId(
      `conv-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 7)}`
    );
    setChatMessages([]);
    setTurns([]);
    setChatInput('');
    setChatError(null);
    setChatFlowState('IDLE');
    setIsChatLoading(false);
  };

  const handleCancelChatRequest = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    setIsChatLoading(false);
    setChatFlowState('IDLE');
    setChatError('Request cancelled locally.');
  };

  // =========================================================================
  // Security Playground Actions (v0.1)
  // =========================================================================

  const handleAnalyzePrompt = async () => {
    if (!prompt.trim() || isPlaygroundLoading || isPlaygroundExecuting) return;

    setIsPlaygroundLoading(true);
    setPlaygroundFlowState('ANALYZING');
    setPlaygroundError(null);
    setGuardResult(null);
    setExecutionResult(null);

    try {
      const result = await agentGuardApi.guardPrompt(prompt.trim());
      setGuardResult(result);

      if (result.decision === 'ALLOW') {
        setPlaygroundFlowState('ALLOWED');
      } else if (result.decision === 'BLOCK') {
        setPlaygroundFlowState('BLOCKED');
      } else {
        setPlaygroundFlowState('ERROR');
      }

      const newHistoryItem: HistoryItem = {
        id: result.request_id || `hist-${Date.now()}`,
        timestamp: new Date().toLocaleTimeString(),
        prompt: prompt.trim(),
        decision: result.decision,
        attack_type: result.attack_type,
        risk_score: result.risk_score,
        latency_ms: result.latency_ms,
        guardResult: result,
      };
      setHistory((prev) => [newHistoryItem, ...prev]);
    } catch (err: unknown) {
      setPlaygroundFlowState('ERROR');
      if (err instanceof AgentGuardApiError) {
        setPlaygroundError(err.message);
      } else {
        setPlaygroundError('Failed to communicate with AgentGuard backend.');
      }
    } finally {
      setIsPlaygroundLoading(false);
    }
  };

  const handleExecutePrompt = async () => {
    if (
      !guardResult ||
      guardResult.decision !== 'ALLOW' ||
      isPlaygroundExecuting ||
      isPlaygroundLoading
    ) {
      return;
    }

    setIsPlaygroundExecuting(true);
    setPlaygroundFlowState('EXECUTING');
    setPlaygroundError(null);

    try {
      const execResult = await agentGuardApi.executePrompt(prompt);
      setExecutionResult(execResult);

      if (execResult.decision === 'ALLOW') {
        setPlaygroundFlowState('COMPLETED');
      } else if (execResult.decision === 'BLOCK') {
        setPlaygroundFlowState('BLOCKED');
      } else {
        setPlaygroundFlowState('ERROR');
      }

      setHistory((prev) =>
        prev.map((item, idx) =>
          idx === 0 ? { ...item, executeResult: execResult } : item
        )
      );
    } catch (err: unknown) {
      setPlaygroundFlowState('ERROR');
      if (err instanceof AgentGuardApiError) {
        setPlaygroundError(err.message);
      } else {
        setPlaygroundError('Failed to execute guarded prompt through target LLM.');
      }
    } finally {
      setIsPlaygroundExecuting(false);
    }
  };

  const handleSelectHistory = (item: HistoryItem) => {
    setPrompt(item.prompt);
    setGuardResult(item.guardResult);
    setExecutionResult(item.executeResult || null);
    setPlaygroundError(null);

    if (item.executeResult && item.executeResult.decision === 'ALLOW') {
      setPlaygroundFlowState('COMPLETED');
    } else if (item.decision === 'ALLOW') {
      setPlaygroundFlowState('ALLOWED');
    } else if (item.decision === 'BLOCK') {
      setPlaygroundFlowState('BLOCKED');
    } else {
      setPlaygroundFlowState('ERROR');
    }
  };

  const handleClearHistory = () => {
    setHistory([]);
  };

  const latestTurn = turns.length > 0 ? turns[turns.length - 1] : null;

  return (
    <div className="axia-dashboard-layout">
      <Header
        health={health}
        isOnline={isOnline}
        isLoading={isHealthLoading}
        mode={mode}
        onModeChange={setMode}
        onNewConversation={handleNewConversation}
        conversationId={conversationId}
        turnsCount={turns.length}
        conversations={conversations}
        onSelectConversation={handleSelectConversation}
        onSelectScenarioPrompt={(scenarioPrompt) => {
          setChatInput(scenarioPrompt);
          setMode('chat');
        }}
      />

      <div className="axia-main-viewport">
        <TopBar
          health={health}
          isOnline={isOnline}
          isLoading={isHealthLoading}
          mode={mode}
          theme={theme}
          onToggleTheme={handleToggleTheme}
        />

        <DegradedModeBanner
          isOnline={isOnline}
          onRetry={checkHealth}
          isRetrying={isHealthLoading}
        />

        <main className="app-container">
          {mode === 'secops' ? (
            /* =========================================================================
               Security Operations & Incident Response (v0.6)
               ========================================================================= */
            <SecurityOperationsView
              health={health}
              developerToken={developerToken}
              setDeveloperToken={handleDeveloperTokenChange}
            />
          ) : mode === 'admin' ? (
            /* =========================================================================
               Administration & Audit Control Plane (v0.5)
               ========================================================================= */
            <AdministrationView
              health={health}
              developerToken={developerToken}
              setDeveloperToken={handleDeveloperTokenChange}
            />
          ) : mode === 'dashboard' ? (
            /* =========================================================================
               Security Dashboard & Observability (v0.4)
               ========================================================================= */
            <SecurityDashboard
              health={health}
              isOnline={isOnline}
              developerToken={developerToken}
              sessionHistory={history}
              sessionChatTurns={turns}
            />
          ) : mode === 'agent-security' ? (
            /* =========================================================================
               Agent Security: Tool Calls, Risk & Human Approval (v0.3)
               ========================================================================= */
            <AgentSecurityView
              developerToken={developerToken}
              setDeveloperToken={handleDeveloperTokenChange}
            />
          ) : mode === 'chat' ? (
            /* =========================================================================
               Multi-Turn Security Chat View (v0.2)
               ========================================================================= */
            <div className="chat-layout-grid">
              <ChatWindow
                conversationId={conversationId}
                turns={turns}
                isLoading={isChatLoading}
                onSendMessage={handleSendChatMessage}
                onNewConversation={handleNewConversation}
                onCancelRequest={handleCancelChatRequest}
                input={chatInput}
                setInput={setChatInput}
                errorMessage={chatError}
              />

              <SecurityPanel
                latestTurn={latestTurn}
                turns={turns}
                flowState={chatFlowState}
                developerToken={developerToken}
                setDeveloperToken={handleDeveloperTokenChange}
              />
            </div>
          ) : (
            /* =========================================================================
               Single-Prompt Security Playground View (v0.1)
               ========================================================================= */
            <>
              <SecurityFlow flowState={playgroundFlowState} />

              {playgroundError && (
                <div className="alert-box danger" role="alert">
                  <AlertCircle size={20} style={{ flexShrink: 0 }} />
                  <div>
                    <div style={{ fontWeight: 600 }}>Security Gateway Notice</div>
                    <div style={{ fontSize: '0.8125rem' }}>{playgroundError}</div>
                  </div>
                </div>
              )}

              <div className="playground-grid">
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                  <PromptInput
                    prompt={prompt}
                    setPrompt={setPrompt}
                    onAnalyze={handleAnalyzePrompt}
                    isLoading={isPlaygroundLoading}
                    isExecuting={isPlaygroundExecuting}
                  />

                  {executionResult && <ExecutionResult execution={executionResult} />}
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                  {guardResult ? (
                    <SecurityDecision
                      guardResult={guardResult}
                      onExecute={handleExecutePrompt}
                      isExecuting={isPlaygroundExecuting}
                      hasExecuted={executionResult !== null}
                    />
                  ) : (
                    <div
                      className="glass-panel"
                      style={{
                        padding: '2rem',
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        justifyContent: 'center',
                        textAlign: 'center',
                        color: 'var(--text-muted)',
                        minHeight: '260px',
                      }}
                    >
                      <p style={{ fontSize: '0.8125rem', maxWidth: '300px' }}>
                        Enter or select a prompt and click "Analyze Prompt" to evaluate its
                        security through the AgentGuard perimeter.
                      </p>
                    </div>
                  )}

                  <RequestHistory
                    history={history}
                    onSelect={handleSelectHistory}
                    onClear={handleClearHistory}
                  />
                </div>
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
};

export const App: React.FC<AppProps> = (props) => {
  return (
    <SessionProvider>
      <AppContent {...props} />
    </SessionProvider>
  );
};

export default App;
