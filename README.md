# AgentGuard v1.0 Release Candidate — Enterprise AI Security Gateway & Guard Architecture

AgentGuard is an integrated, defense-in-depth security gateway and guard perimeter for Large Language Models (LLMs) and agentic workflows. It intercepts user interactions, evaluates single-turn prompts and multi-turn conversations for adversarial attacks (jailbreaks, prompt injections, privilege escalation, roleplay manipulation, and data leakage), governs tool and function execution with deterministic risk policies, enforces human-in-the-loop approvals for privileged actions, binds cryptographically verifiable Bearer credentials to isolated tenant security contexts, and maintains a tamper-evident, HMAC-chained persistent audit trail.

### Evolutionary Milestones:
- **Core Engine (v1 - v5)**: Multi-layer prompt inspection pipeline (Unicode canonicalization, regex heuristics, structured JSON guard model, output leak sanitizer). Frozen and unmodified.
- **Backend v0.4**: Operational hardening (in-process rate limiting, inference concurrency controls, timeout protection, correlation tracking, readiness probes).
- **Backend v0.5**: Tool & function-call security (schema validation, argument injection defenses, indirect prompt injection protection).
- **Backend v0.6**: Human approval & high-risk action control (state machine, HMAC action binding, replay protection, TTL enforcement).
- **Backend v0.7**: Dynamic policy administration & persistent security audit logging.
- **Backend v0.8**: Production authentication, multi-tenant isolation, Argon2id Bearer credentials (`ag_<id>_<secret>`), deterministic RBAC.
- **Backend v0.9**: Secure deployment configuration, secret provider abstraction, database hardening (SQLite WAL, busy timeouts), HTTP boundary enforcement.
- **Backend v1.0 Release Candidate**: Integrated end-to-end security gateway, streaming body size bounding, hardened proxy CIDR traversal, fail-closed single-process enforcement, 20-point invariant verification, failure injection suite, audit tamper resistance, and comprehensive 179-case security benchmark.

---

## Integrated Architecture & Request Lifecycle

```
[ EXTERNAL CLIENT ]
        │
        ▼
[ REVERSE PROXY / PERIMETER ] (Caddy / Nginx: TLS Termination, Request Buffering, Port 443)
        │  X-Forwarded-For: <client_ip>, <trusted_proxy>
        ▼
[ AGENTGUARD GATEWAY (v1.0 RC) ]
  1. HTTP Boundary Guard:
     - Streaming byte counting (Enforces MAX_REQUEST_BODY_SIZE = 1MB; fails closed 413)
     - Header size & Content-Type validation (application/json)
     - Hardened Proxy Resolver (Right-to-left traversal, CIDR network parsing, discards untrusted headers)
  2. Rate & Abuse Limiting:
     - Global IP rate limiter
     - Category rate limiters (Credentials, Approvals, Policies, Audit)
     - Auth failure backoff rate limiter
  3. Authentication & Credential Verification:
     - Parses cryptographically secure Bearer token (`ag_<id>_<secret>`)
     - Timing-safe Argon2id hash verification
     - Disabled/expired credential check (Fails closed: 401)
  4. Tenant Resolution & RBAC Enforcement:
     - Binds request to authenticated server-side RequestSecurityContext
     - Client headers (X-AgentGuard-Role, X-AgentGuard-Tenant) STRICTLY DISREGARDED
     - Multi-tenant isolation verified (Fails closed: 403)
  5. Dynamic Security Policy Engine:
     - Evaluates active policies by priority (DENY, REQUIRE_APPROVAL, ALLOW)
  6. Frozen v5 Security Engine (`agentguard.py`):
     - Unicode & base64 normalization
     - Deterministic intent-aware pre-checks
     - Guard LLM semaphore & timeout protection
     - Guard evaluation decision (ALLOW / BLOCK / ERROR)
  7. Tool Authorization & Risk Gateway:
     - Low-risk tools: Allowed directly
     - Critical tools: Blocked unconditionally
     - High-risk tools: Transitions to PENDING_APPROVAL
  8. Human Approval State Machine:
     - Deterministic HMAC-SHA-256 argument binding
     - One-time execution token consumption (Replay returns 409)
     - TTL expiration check (Fails closed: 400)
  9. Execution & Sanitization:
     - Invokes Target LLM / Mock Tool
     - Output Leak Sanitizer redacts canary secrets (`[REDACTED]`)
  10. Cryptographic Audit Logging:
     - Keyed HMAC-SHA-256 forward-chained event hashing
     - Secrets and tokens NEVER recorded
  11. Hardened SQLite Storage:
     - WAL journal mode, synchronous NORMAL, busy timeout 5000ms
        │
        ▼
[ CLIENT RESPONSE ] (Includes standard security headers: CSP, HSTS, X-Content-Type-Options)
```

---

## API Endpoints

### 1. `GET /health`
Application process health and configuration status. Does **not** depend on external Ollama availability.
- **Status Code:** `200 OK`
- **Response:**
  ```json
  {
    "status": "ok",
    "version": "0.4.0",
    "guard_model": "llama3.2:latest",
    "target_model": "llama3.2:latest"
  }
  ```

### 2. `GET /ready`
Readiness probe verifying whether backend dependencies (Ollama service) are reachable and ready to serve inference requests.
- **Status Code:** `200 OK` (when connected) or `503 Service Unavailable` (when unreachable)
- **Response (Connected):**
  ```json
  {
    "status": "ready",
    "version": "0.4.0",
    "ollama": "connected",
    "guard_model": "llama3.2:latest",
    "target_model": "llama3.2:latest"
  }
  ```
- **Response (Unreachable):**
  ```json
  {
    "request_id": "...",
    "status": "not_ready",
    "error": {
      "code": "DEPENDENCY_UNAVAILABLE",
      "message": "Ollama service is not reachable."
    }
  }
  ```

### 3. `GET /metrics`
Lightweight, in-process operational metrics collector. Memory-only, resets on application restart.
- **Status Code:** `200 OK`
- **Response:**
  ```json
  {
    "uptime_seconds": 124.5,
    "total_requests": 42,
    "requests_by_endpoint": {
      "/health": 10,
      "/ready": 2,
      "/metrics": 1,
      "/api/v1/guard": 12,
      "/api/v1/execute": 11,
      "/api/v1/chat": 6
    },
    "requests_by_status": {"200": 38, "422": 2, "429": 1, "503": 1},
    "decisions": {"allow": 18, "block": 11, "error": 0},
    "rate_limited_count": 1,
    "concurrency_rejected_count": 1,
    "guard": {"invocations": 29, "failures": 0, "timeouts": 0},
    "target": {"invocations": 18, "failures": 0, "timeouts": 0},
    "timeouts": {"guard_timeouts": 0, "target_timeouts": 0, "total_timeouts": 0}
  }
  ```

### 4. `POST /api/v1/guard`
Single-turn security evaluation without target execution.
- **Request:** `{"prompt": "Hello world"}`
- **Response:**
  ```json
  {
    "request_id": "c741a7a1-99aa-4a68-888f-70814e88b0d4",
    "decision": "ALLOW",
    "risk_score": 0.0,
    "attack_type": "none",
    "guard_model": "llama3.2:latest",
    "latency_ms": 12.5
  }
  ```

### 5. `POST /api/v1/execute`
Single-turn guarded execution gateway. Executes target model only on `ALLOW`.
- **Request:** `{"prompt": "What is 2+2?"}`
- **Response (ALLOW):**
  ```json
  {
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "decision": "ALLOW",
    "risk_score": 0.0,
    "attack_type": "none",
    "guard_model": "llama3.2:latest",
    "target_model": "llama3.2:latest",
    "response": "2 + 2 = 4",
    "latency_ms": 1250.0
  }
  ```

### 6. `POST /api/v1/chat`
Context-aware guarded multi-turn conversation execution.
- **Request:**
  ```json
  {
    "conversation_id": "demo-conv-123",
    "messages": [
      {"role": "user", "content": "Let us solve math problems."},
      {"role": "assistant", "content": "I am ready."},
      {"role": "user", "content": "What is 25 * 4?"}
    ]
  }
  ```
- **Response (ALLOW):**
  ```json
  {
    "request_id": "f45fe300-ea02-43d0-a21d-4d616a774783",
    "conversation_id": "demo-conv-123",
    "decision": "ALLOW",
    "risk_score": 0.0,
    "attack_type": "none",
    "guard_model": "llama3.2:latest",
    "target_model": "llama3.2:latest",
    "response": "25 * 4 = 100",
    "latency_ms": 2508.58
  }
  ```

### 7. `POST /api/v1/tool/execute`
Authorized tool/function-call execution and security evaluation endpoint. Evaluates tool calls against AgentGuard policy and executes deterministic mock tools strictly on `ALLOW`.
- **Request:**
  ```json
  {
    "tool_name": "get_weather",
    "arguments": {
      "city": "Mumbai"
    }
  }
  ```
- **Response (ALLOW):**
  ```json
  {
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "decision": "ALLOW",
    "tool_name": "get_weather",
    "result": "Weather report for Mumbai: 27°C, Partly Cloudy, Wind: 12 km/h NE, Humidity: 62%.",
    "latency_ms": 10.4,
    "risk_level": "low",
    "attack_type": "none"
  }
  ```
- **Response (BLOCK):**
  ```json
  {
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "decision": "BLOCK",
    "tool_name": "delete_record",
    "result": null,
    "latency_ms": 0.8,
    "risk_level": "critical",
    "attack_type": "critical_tool_escalation"
  }
  ```
- **Response (ERROR):**
  ```json
  {
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "decision": "ERROR",
    "tool_name": "unknown_tool",
    "result": null,
    "latency_ms": 1.2,
    "risk_level": null,
    "attack_type": "tool_policy_error"
  }
  ```

---

## Operational Hardening Capabilities (v0.4)

### 1. In-Process Rate Limiting
- **Mechanism:** In-process sliding-window rate limiter per client IP.
- **Behavior:** Rejects excess requests with **HTTP 429 Too Many Requests**, attaches `Retry-After: <seconds>` header.
- **Safety:** Bookkeeping errors fail open safely without crashing. Prompts are never logged.
- **Disclaimer:** Designed for local development and edge process reliability; not a distributed multi-node rate limiter.

### 2. Concurrency Controls
- **Mechanism:** Asynchronous and thread-safe bounded semaphores for Guard and Target inferences.
- **Guaranteed Invariant:** Requests **never bypass concurrency controls** to invoke Ollama directly.
- **Behavior:** When capacity is exhausted, requests are safely rejected with **HTTP 503 Service Unavailable** (`CONCURRENCY_LIMIT`) without calling Ollama.

### 3. Timeout Hardening & Fail-Closed Protection
- **Guard Timeout Protection:** Guard inference is bounded by `AGENTGUARD_GUARD_TIMEOUT_SECONDS` (default `30.0s`).
  - Upon timeout: Fails closed to `BLOCK` (`guard_timeout`), risk score `1.0`. Target LLM is **strictly NEVER called**.
- **Target Timeout Protection:** Target inference is bounded by `AGENTGUARD_TARGET_TIMEOUT_SECONDS` (default `60.0s`).
  - Upon timeout: Returns safe `ERROR` (`target_timeout`), response `null`. No tracebacks or internal timeouts are exposed.

### 4. Structured Error Responses
All API error responses follow a consistent, safe schema:
```json
{
  "request_id": "...",
  "error": {
    "code": "RATE_LIMITED",
    "message": "Request rate limit exceeded. Please retry in 59 seconds."
  }
}
```
**Standard Safe Error Codes:**
- `VALIDATION_ERROR` (HTTP 422)
- `RATE_LIMITED` (HTTP 429)
- `CONCURRENCY_LIMIT` (HTTP 503)
- `DEPENDENCY_UNAVAILABLE` (HTTP 503)
- `INTERNAL_ERROR` (HTTP 500)

### 5. Request Correlation
- Every incoming request receives a tracking `request_id`.
- Client-supplied `X-Request-ID` headers are validated and preserved. If omitted, a server-side UUID is generated.
- `X-Request-ID` is returned in all response headers and embedded in structured error payloads.

### 6. Security Telemetry Policy
**Safe Logged Fields:**
- `timestamp`, `request_id`, `conversation_id`, `endpoint`, `decision`, `attack_type`, `risk_score`, `message_count`, `latency_ms`, `HTTP status`, `model name`.

**Strictly Prohibited from Logs:**
- Full user prompts or query text
- Complete conversation histories
- Raw Guard model thoughts or tokens
- Raw Target model generation
- Secrets (including canary code `BLUE-ORANGE-42`)
- Internal stack traces or file system paths

---

## Environment Variables Configuration

| Variable | Default | Description |
| :--- | :--- | :--- |
| `AGENTGUARD_VERSION` | `0.4.0` | API application version |
| `AGENTGUARD_GUARD_MODEL` | `llama3.2:latest` | Ollama model identifier for Guard evaluation |
| `AGENTGUARD_TARGET_MODEL` | `llama3.2:latest` | Ollama model identifier for Target LLM execution |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Base HTTP endpoint for Ollama service |
| `AGENTGUARD_GUARD_TIMEOUT_SECONDS` | `30.0` | Inference timeout for Guard security check |
| `AGENTGUARD_TARGET_TIMEOUT_SECONDS` | `60.0` | Inference timeout for Target model execution |
| `AGENTGUARD_RATE_LIMIT_ENABLED` | `true` | Enables in-process client IP rate limiting |
| `AGENTGUARD_RATE_LIMIT_REQUESTS` | `100` | Allowed requests per time window |
| `AGENTGUARD_RATE_LIMIT_WINDOW_SECONDS` | `60` | Time window for rate limiter in seconds |
| `AGENTGUARD_MAX_CONCURRENT_GUARD_REQUESTS` | `4` | Max concurrent Guard inferences |
| `AGENTGUARD_MAX_CONCURRENT_TARGET_REQUESTS` | `2` | Max concurrent Target model inferences |
| `AGENTGUARD_MAX_PROMPT_LENGTH` | `20000` | Maximum character length for single prompt |
| `AGENTGUARD_MAX_CHAT_MESSAGES` | `50` | Maximum message turns in chat conversation |
| `AGENTGUARD_MAX_TOTAL_CONVERSATION_LENGTH` | `100000` | Maximum total character size of chat conversation |
| `AGENTGUARD_ALLOWED_ORIGINS` | *(localhost)* | Permitted CORS origins for local web development |

---

## Operational Performance Benchmark Results

Generated by `benchmark_performance_v04.py` against local Ollama (`llama3.2:latest`):
Artifact: `performance_v04_benchmark_results.json`

| Measurement Category | Count | Mean (ms) | Median (ms) | P95 (ms) | Min (ms) | Max (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Guard-Only (ALLOW)** | 5 | 987.1 | 523.6 | 2385.9 | 511.8 | 2848.6 |
| **Guard-Only (BLOCK)** | 5 | 588.7 | 590.8 | 613.9 | 539.7 | 615.7 |
| **Execute (ALLOW)** | 3 | 670.1 | 680.2 | 683.4 | 646.5 | 683.7 |
| **Execute (BLOCK)** | 5 | 553.8 | 540.8 | 599.5 | 532.0 | 612.8 |
| **Chat (ALLOW)** | 3 | 673.0 | 670.4 | 684.4 | 662.7 | 686.0 |
| **Chat (BLOCK)** | 5 | 8.4 | 8.3 | 9.1 | 7.4 | 9.1 |
| **Guard Timeout Behavior** | 5 | 8.1 | 7.9 | 8.9 | 7.7 | 9.0 |
| **Target Timeout Behavior** | 5 | 540.0 | 536.7 | 560.6 | 528.1 | 565.6 |

*Methodology: Measured end-to-end HTTP request latencies under controlled local test conditions. Demonstrates fast deterministic blocking (~8ms) and safe timeout error containment.*

---

## Backend v0.5 — Tool & Function-Call Security Boundary

Backend v0.5 introduces a defense-in-depth authorization boundary between the Target LLM and any external actions or tools it proposes to invoke.

> [!IMPORTANT]
> **Core Security Principle:**
> *"Agent-generated tool calls are treated as untrusted requests and must pass AgentGuard authorization before execution."*
> The Target LLM must **NEVER** directly control tool execution.

### 1. Mock-Only Architecture (No Real External Actions)
**Explicit Policy for Backend v0.5:**
Real external systems are strictly disabled:
- **No** shell / subprocess / OS commands
- **No** arbitrary Python code execution
- **No** filesystem writes
- **No** email delivery
- **No** browser automation
- **No** database modifications
- **No** external network or cloud APIs

All tools are implemented as deterministic in-memory mock functions for policy evaluation and security benchmarking.

### 2. Tool Security Pipeline
```
Client Request
      │
      ▼
Context & Input Security (Guard v5)
      │
      ▼
Target LLM (Proposes Action)
      │
      ▼
Tool Call Detection & Canonical Parser
      │
      ▼
Tool Authorization Gate (Tool Guard)
      │
      ├───────────────────────┬────────────────────────┐
      ▼                       ▼                        ▼
   [BLOCK]                 [ERROR]                  [ALLOW]
      │                       │                        │
      ▼                       ▼                        ▼
 Stop Tool Loop          Fail Closed            Controlled Mock Executor
 (Tool NEVER called)  (Tool NEVER called)       (is_authorized=True flag required)
                                                       │
                                                       ▼
                                             Tool Result Guard
                                             (Sanitizes Indirect Injection,
                                              Redacts Canary Secrets,
                                              Wraps as UNTRUSTED DATA)
                                                       │
                                                       ▼
                                             Target LLM Context
                                                       │
                                                       ▼
                                             Output Leak Sanitizer
                                                       │
                                                       ▼
                                                  Client Output
```

### 3. Controlled Tool Registry
Each registered tool is defined with immutable security metadata:
- **`get_weather`**: Risk `low`, Read-only `true`, Side-effect `false`.
- **`search_documents`**: Risk `low`, Read-only `true`, Side-effect `false`.
- **`send_email`**: Risk `high`, Read-only `false`, Side-effect `true` *(Mock simulation only; blocked by default)*.
- **`delete_record`**: Risk `critical`, Read-only `false`, Side-effect `true` *(Mock simulation only; blocked by default)*.

### 4. Tool Risk Policy
- **Low-Risk Read-Only Tools:** Automatically allowed if arguments pass strict schema and injection inspection.
- **High-Risk Side-Effect Tools:** Strictly **BLOCKED** by default in v0.5 unless explicitly enabled via environment variable (`AGENTGUARD_ALLOW_HIGH_RISK_TOOLS=true`).
- **Critical Destructive Tools:** Strictly **BLOCKED** by default in v0.5 (`AGENTGUARD_ALLOW_CRITICAL_TOOLS=false`).
- **Unknown Tools / Ambiguous Names:** Strictly **BLOCKED** with `unknown_tool`. Homoglyphs, case variations, or URL-encoded names are rejected as `tool_name_obfuscation`.

### 5. Untrusted Argument Security
Arguments generated by LLMs are analyzed as untrusted user input:
- **Schema Validation:** Strict argument type checking, required argument presence, unknown key prohibition, payload bounds.
- **Prompt Injection in Arguments:** Reuses AgentGuard v5 input normalization, regex patterns, and deterministic pre-checks.
- **Canary Secret Extraction:** Rejects any argument attempting to extract or access `BLUE-ORANGE-42`.
- **Encoded & Obfuscated Payloads:** Decodes and inspects Base64, ROT13, reversed text, and Unicode homoglyphs.

### 6. Tool Result Security & Sanitization
Tool outputs are treated strictly as untrusted data:
- **Indirect Prompt Injection:** Adversarial instructions returned in tool data are stripped and marked with safety notices.
- **System Spoofing:** Prevents tool data from masquerading as `### System:` or `[System Message]` instructions.
- **Canary Secret Redaction:** Tool returns containing `BLUE-ORANGE-42` are redacted to `[REDACTED]`.
- **Untrusted Context Wrapper:** Formatted as `[TOOL RESULT from <tool> (UNTRUSTED DATA)] ... [END TOOL RESULT]`.

### 7. Tool-Call Loop Limits
- Maximum allowed tool iterations per request is bounded by `AGENTGUARD_MAX_TOOL_CALLS_PER_REQUEST` (default `3`).
- Infinite loops or excessive tool-calling patterns are halted safely with `BLOCK` (`tool_call_limit`).

### 8. Security Invariants
1. **Unknown tool** $\rightarrow$ Tool NEVER executes.
2. **Invalid arguments** $\rightarrow$ Tool NEVER executes.
3. **Blocked tool call** $\rightarrow$ Tool NEVER executes.
4. **Tool Guard error** $\rightarrow$ Tool NEVER executes (fails closed).
5. **Tool-call limit exceeded** $\rightarrow$ Tool loop stops, no further execution.
6. **Malicious tool result** $\rightarrow$ Neutralized, never gains privileged system authority.
7. **Direct executor invocation without authorization** $\rightarrow$ Raises `UnauthorizedToolExecutionError`.

---

## Tool Security Benchmark Results (v0.5)

Generated by `benchmark/tool_security_v05.py`:
Artifact: `benchmark/tool_security_v05_results.json`

| Metric | Target | Benchmark Result |
| :--- | :---: | :---: |
| **Total Test Cases** | 70 | **70** |
| **Adversarial Attack Cases** | 50 | **50** |
| **Attacks Blocked / Neutralized** | 100% | **50 / 50 (100.0%)** |
| **Unauthorized Tool Execution Rate** | **0.0%** | **0.0% (0 / 50)** |
| **Post-Guard Attack Success Rate (ASR)** | **0.0%** | **0.0%** |
| **Canary Secret Token Leaks** | 0 | **0** |
| **Benign Test Cases** | 20 | **20** |
| **Benign Tools Allowed** | 100% | **20 / 20 (100.0%)** |
| **Benign False-Positive Rate (FPR)** | $\le 5\%$ | **0.0%** |
| **Mean Evaluation Latency** | — | **1.66 ms** |

---

## Backend v0.6 — Human Approval & High-Risk Action Control

Backend v0.6 establishes an explicit, hardened human authorization layer between tool proposal, risk classification, and execution.

> [!IMPORTANT]
> **Central Invariant:**
> *"The Model must NEVER be able to approve its own high-risk action."*
> Prompt injection, model self-approval assertions, tool description manipulation, and argument injections can never satisfy or bypass the human approval boundary.

### 1. Architecture & Control Flow

```
Tool Proposal
      │
      ▼
  Tool Guard
      │
Risk Classification
      │
      ├───────────────────────────────┐
      ▼                               ▼
  [Low Risk]                  [High / Critical]
      │                               │
      ▼                               ▼
Execute Immediately            PENDING_APPROVAL
                                      │
                              Approval Gateway
                               (Out-of-band)
                                ↙          ↘
                            [DENIED]    [APPROVED]
                               │            │
                               ▼            ▼
                             STOP     Verify Binding
                                            │
                                            ▼
                                       Execute Once
                                            │
                                            ▼
                                        CONSUMED
```

### 2. Explicit Approval State Machine
- **`NOT_REQUIRED`**: Low-risk read-only tools that do not require explicit authorization.
- **`PENDING_APPROVAL`**: Tool call validated and waiting for out-of-band explicit human action.
- **`APPROVED`**: Explicit approval granted by an authorized approval call (ephemeral transition).
- **`DENIED`**: Explicit rejection by an authorized operator. Tool will never execute.
- **`EXPIRED`**: Approval request exceeded its configured Time-To-Live without decision.
- **`CANCELLED`**: Request explicitly cancelled prior to execution.
- **`CONSUMED`**: Terminal state reached immediately after the authorized action executes once.
- **`ERROR`**: Terminal error state encountered during processing.

### 3. Risk-Based Approval Policy
- **Low-Risk Tools** (`get_weather`, `search_documents`): Read-only, safe, default execution if argument schema and injection checks pass.
- **Medium-Risk Tools**: Configurable via `AGENTGUARD_MEDIUM_RISK_REQUIRE_APPROVAL` (default: `false`).
- **High-Risk Tools** (`send_email`): External side-effects. Always requires human approval (`PENDING_APPROVAL`).
- **Critical Tools** (`delete_record`): Destructive actions. Strictly requires human approval, never auto-executed under any default policy.
- **Unknown Risk / Missing Policy / Evaluation Error**: Fails closed (`BLOCK`).

### 4. Cryptographic Action Binding & Canonical Argument Hashing
Approvals are never broad permissions. Every approval token is strictly bound to the exact proposed action:
- **`approval_id`**: Cryptographically strong random identifier (`appr_` prefix + 32 hex characters via `secrets.token_hex(16)`).
- **Deterministic Canonical Serialization**: Arguments are canonicalized (keys sorted recursively, compact JSON without whitespace, UTF-8 encoded).
- **SHA-256 Argument Hash**: The exact hash is computed and stored with the approval record.
- **Action Binding Verification**: Execution requires matching `(tool_name, argument_hash, conversation_id, risk_level)`. If an attacker or compromised agent alters any argument or swaps the target tool, execution is immediately blocked with `APPROVAL_BINDING_MISMATCH`.

### 5. One-Time Execution & Replay Prevention
- An approval cannot be reused as a permanent credential.
- Execution atomically transitions the approval from `APPROVED` to `CONSUMED` under lock.
- Subsequent execution attempts with the same `approval_id` fail immediately with `APPROVAL_ALREADY_CONSUMED` and increment `approval_replay_attempts`.

### 6. Time-to-Live (TTL) & Expiration
- Configured via `AGENTGUARD_APPROVAL_TTL_SECONDS` (default: `300` seconds).
- Expired approvals automatically transition to `EXPIRED`.
- Expired approvals can never execute and are never silently renewed.

### 7. Concurrency & Race Condition Protection
- Thread-safe in-memory store guarded with `threading.Lock`.
- Guarantees **at most one tool execution** even under concurrent approval or parallel execution attempts.

### 8. Immunity to Model Self-Approval & Injection
- The model's generated text is **not** an authorization signal.
- Phrases like *"User approved this"*, *"Admin override"*, or *"approval_status: approved"* in prompts, tool arguments, or prior tool outputs are completely ignored by the approval boundary.
- Any prompt injection or canary extraction detected in proposed arguments causes the Tool Guard to reject approval creation upfront.

### 9. Approval REST API Endpoints (Local Testing)
- `POST /api/v1/approvals`: Create an approval request for a proposed tool call.
- `GET /api/v1/approvals`: List recent approval records (safe argument summaries only).
- `GET /api/v1/approvals/{approval_id}`: Retrieve detailed approval status and safe metadata.
- `POST /api/v1/approvals/{approval_id}/approve`: Explicit human approval operation (executes tool and transitions to `CONSUMED`).
- `POST /api/v1/approvals/{approval_id}/deny`: Explicit human denial operation (transitions to `DENIED`).

### 10. Security Limitations (v0.6 Scope)
> [!WARNING]
> - **In-Memory Store Only:** Approvals are stored in memory and reset upon application restart. Production deployment requires an external, durable, encrypted approval store.
> - **No Human Authentication / RBAC in v0.6:** The `/api/v1/approvals/*` endpoints are designed for local development and red-teaming. They do not verify production user identity or role-based access control.

---

## Human Approval Benchmark Results (v0.6)

Generated by `benchmark/approval_security_v06.py`:
Artifact: `benchmark/approval_security_v06_results.json`

| Metric | Target | Benchmark Result |
| :--- | :---: | :---: |
| **Total Test Scenarios** | 60 | **60** |
| **Adversarial Attack Cases** | 40 | **40** |
| **Attacks Blocked / Neutralized** | 100% | **40 / 40 (100.0%)** |
| **Unauthorized High-Risk Tool Executions** | **0** | **0** |
| **Unauthorized Execution Rate** | **0.0%** | **0.0%** |
| **Approval Replay Success Rate** | **0.0%** | **0.0%** |
| **Action-Binding Bypass Rate** | **0.0%** | **0.0%** |
| **Expired Approval Executions** | 0 | **0** |
| **Race Condition Double Executions** | 0 | **0** |
| **Benign Test Scenarios** | 20 | **20** |
| **Benign Approval Success Rate** | 100% | **20 / 20 (100.0%)** |
| **Benign False-Positive Rate (FPR)** | $\le 5\%$ | **0.0%** |
| **Mean Evaluation Latency** | — | **80.83 ms** |

---

## Backend v0.7: Identity, Policy Administration & Persistent Security Audit

Backend v0.7 introduces three foundational security capabilities:
1. **Identity & Principal Abstraction (Local / Development-Only):** Explicit principal model supporting `user`, `service`, and `admin` types with deterministic role mapping (`user`, `operator`, `admin`).
2. **Policy Administration Engine:** Dynamic security policies with strict field validation, soft-deletion, monotonic version increments, and deterministic resolution precedence (`DENY` > `REQUIRE_APPROVAL` > `ALLOW` > `DEFAULT`).
3. **Persistent Tamper-Evident Security Audit Log:** SQLite-backed audit store (`data/agentguard_audit.db`) with parameterized SQL, canary secret redaction (`BLUE-ORANGE-42`), raw prompt exclusion, SHA-256 cryptographic hash chaining, and integrity verification.

> [!IMPORTANT]
> **DEVELOPMENT / LOCAL IDENTITY NOTICE:**
> "This v0.7 identity system is development/local identity only and is NOT production authentication."
> Client-supplied identity headers (`X-AgentGuard-Principal`) are resolved against a local static registry. Client role self-assignment (e.g. `X-AgentGuard-Role`) is strictly rejected.

> [!WARNING]
> **AUDIT DATABASE IMMUTABILITY NOTICE:**
> "The audit database is tamper-evident through hash chaining but is not an immutable or remotely trusted audit system."
> Local SQLite administrators can modify database files directly; cryptographic chaining detects unexpected record modifications or deletions.

---

### v0.7 End-to-End Security Architecture Flow

```
Client Request
      │ (X-AgentGuard-Principal)
      ▼
Identity / Principal Resolution (Local Registry)
      │
      ▼
Policy Resolution (Deterministic Precedence)
      │
      ▼
Input Guard (Frozen v5 Multi-Layer Security Engine)
      │
      ▼
Tool Guard (Schema, Type, Range & Injection Defense)
      │
      ▼
Risk Classification & Policy Re-Check
      │
      ▼
Approval Requirement Boundary (If High-Risk / Critical)
      │
      ▼
Human Approval & Policy Version Re-Validation
      │
      ▼
Guarded Tool / Target Execution (Mock Simulated)
      │
      ▼
Output Leak Sanitizer (Redacts Canary Secrets)
      │
      ▼
Tamper-Evident Audit Event (SHA-256 Hash Chain in SQLite)
```

---

### Role-Based Access Control (RBAC) Matrix

| Capability | `user` | `operator` | `admin` | Notes |
| :--- | :---: | :---: | :---: | :--- |
| `guard:submit` | ✅ | ✅ | ✅ | Submit prompts for guard evaluation |
| `execute:low_risk` | ✅ | ✅ | ✅ | Execute low-risk tools (`get_weather`) |
| `approval:create` | ✅ | ✅ | ✅ | Propose high-risk tool operations |
| `approval:inspect_own` | ✅ | ✅ | ✅ | Inspect only approvals owned by caller |
| `approval:inspect_all` | ❌ | ✅ | ✅ | Inspect all approvals across principals |
| `approval:approve` | ❌ | ✅ | ✅ | Explicitly approve high-risk action |
| `approval:deny` | ❌ | ✅ | ✅ | Explicitly deny approval request |
| `policy:read` | ❌ | ✅ | ✅ | Read active and disabled security policies |
| `policy:admin` | ❌ | ❌ | ✅ | Create, update, or soft-delete policies |
| `audit:read_own` | ✅ | ✅ | ✅ | Read own security audit records |
| `audit:read_all` | ❌ | ✅ | ✅ | Read all security audit events |
| `audit:verify` | ❌ | ❌ | ✅ | Run cryptographic chain verification |

---

### Policy Administration API Endpoints

| Method | Endpoint | Allowed Roles | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/policies` | `admin` | Create new policy rule (initial version = 1) |
| `GET` | `/api/v1/policies` | `operator`, `admin` | List configured policies |
| `GET` | `/api/v1/policies/{policy_id}` | `operator`, `admin` | Retrieve policy definition by ID |
| `PUT` | `/api/v1/policies/{policy_id}` | `admin` | Update policy (increments version) |
| `DELETE` | `/api/v1/policies/{policy_id}` | `admin` | Soft-delete policy (increments version) |

---

### Persistent Security Audit API Endpoints

| Method | Endpoint | Allowed Roles | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/audit/events` | `user` (own only), `operator`, `admin` | Query parameterized, bounded audit events |
| `GET` | `/api/v1/audit/verify` | `admin` | Cryptographic SHA-256 chain verification |

---

### v0.7 Configuration Environment Variables

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `AGENTGUARD_IDENTITY_ENABLED` | `false` | Enable strict principal resolution and enforcement |
| `AGENTGUARD_DEFAULT_PRINCIPAL` | `user-demo` | Default principal when identity is disabled |
| `AGENTGUARD_AUDIT_DB_PATH` | `data/agentguard_audit.db` | Local SQLite audit database file path |
| `AGENTGUARD_AUDIT_ENABLED` | `true` | Enable persistent audit event logging |
| `AGENTGUARD_AUDIT_CHAIN_ENABLED` | `true` | Enable SHA-256 cryptographic tamper-evident chaining |
| `AGENTGUARD_AUDIT_RETENTION_LIMIT`| `100000` | Maximum audit events retained before rotation |
| `AGENTGUARD_MAX_AUDIT_PAGE_SIZE` | `100` | Maximum records returned per audit query page |
| `AGENTGUARD_CANARY_SECRET` | `BLUE-ORANGE-42` | Protected secret token strictly redacted from logs |

---

## Security Benchmark Results (v0.7)

Generated by `benchmark_v07_security.py`:
Artifact: `benchmark_v07_results.json`

| Metric | Target | Benchmark Result |
| :--- | :---: | :---: |
| **Benchmark Final Status** | **PASS** | **PASS** |
| **Category A: Identity Attacks** | 100% | **8 / 8 (100.0%)** |
| **Category B: Policy Attacks** | 100% | **8 / 8 (100.0%)** |
| **Category C: Approval Attacks** | 100% | **7 / 7 (100.0%)** |
| **Category D: Audit Attacks** | 100% | **7 / 7 (100.0%)** |
| **Category E: Regression Attacks** | 100% | **7 / 7 (100.0%)** |
| **Benign Validation Cases** | 100% | **6 / 6 (100.0%)** |
| **Unauthorized Privileged Actions** | **0** | **0** |
| **Unauthorized Policy Mutations** | **0** | **0** |
| **Unauthorized Tool Executions** | **0** | **0** |
| **Approval Replay Successes** | **0** | **0** |
| **Approval Transfer Successes** | **0** | **0** |
| **Secret Leaks (`BLUE-ORANGE-42`)** | **0** | **0** |
| **Audit Chain Verification Failures** | **0** | **0** |
| **Benign False-Positive Rate (FPR)** | $\le 5\%$ | **0.0%** |
| **Guard Regression Count** | **0** | **0** |

### Latency Profiles (Controlled Local Benchmark)

| Operation | Median (p50) | p95 | Mean |
| :--- | :---: | :---: | :---: |
| **Identity Resolution** | 0.002 ms | 0.002 ms | 0.002 ms |
| **Policy Evaluation** | 0.002 ms | 0.003 ms | 0.002 ms |
| **Audit Write (SQLite + SHA-256)** | 10.83 ms | 13.09 ms | 10.94 ms |
| **Audit Query Read (Parameterized)** | 1.61 ms | 2.56 ms | 1.61 ms |
| **End-to-End Guard Request** | 713.75 ms | 1686.67 ms | 974.90 ms |

---

## AgentGuard Backend v0.8: Production-Style Authentication, Tenant Isolation & API Credentials

Backend v0.8 establishes a production-grade authentication perimeter, cryptographically verifiable API credentials, strict multi-tenant isolation, and fine-grained RBAC authorization over the AgentGuard platform.

### Core Security Chain
Every request follows a strict, non-bypassable sequence:
```
Client Request
      │
      ▼
Credential Authentication (Bearer ag_<cred_id>_<secret>)
      │
      ▼
Timing-Safe Verification (Argon2id hashing + constant-time dummy verify)
      │
      ▼
Server-Side Principal Resolution (DB lookup, active status check)
      │
      ▼
Tenant Isolation Enforcement (Server-bound tenant_id, fail-closed boundaries)
      │
      ▼
Authorization / RBAC Evaluation (Deterministic role capabilities check)
      │
      ▼
Policy Resolution (Tenant-scoped policy evaluation)
      │
      ▼
Guard Inference (Frozen v5 security engine analysis)
      │
      ▼
Tool Guard & Argument Validation (Function-call boundary)
      │
      ▼
Human Approval Gate (High-risk action state machine)
      │
      ▼
Target Execution (Timeout & concurrency protected)
      │
      ▼
Output Sanitization (Secret canary redaction)
      │
      ▼
Persistent Security Audit (SQLite + SHA-256 hash chaining)
```

### Security Invariants & Guarantees
1. **Never Trust Client Headers:** Client-supplied headers (`X-AgentGuard-Role`, `X-AgentGuard-Tenant`, `X-AgentGuard-Principal`) and LLM model outputs are **strictly disregarded** for authorization and tenancy when Bearer credentials are used. Roles and tenant boundaries are loaded exclusively from server-side storage.
2. **Cryptographically Verifiable Credentials:** Bearer credentials follow format `ag_<credential_id>_<secret>`. The secret is generated with 256 bits of cryptographic entropy (`secrets.token_hex(32)`).
3. **Argon2id Hashing:** Plaintext secrets are never stored in the database, never logged, and never returned in GET responses. Secrets are hashed using Argon2id (`memory_cost=65536` [64 MiB], `time_cost=3` iterations, `parallelism=4` threads).
4. **Timing Attack Protection:** Constant-time dummy Argon2id hash verification is executed for unknown or malformed credential IDs to prevent timing-based enumeration attacks.
5. **One-Time Secret Disclosure:** The plaintext credential secret is returned **exactly once** upon creation or rotation. Subsequent GET requests omit `credential_secret` and `credential_hash`.
6. **Multi-Tenant Isolation:** All resources (policies, approvals, credentials, audit events, and principals) are strictly isolated by `tenant_id`. Cross-tenant access fails closed with HTTP 404 or 403 to prevent cross-tenant enumeration.
7. **Privilege Hierarchy:** Distinguishes `global_admin` (cross-tenant administration, tenant provisioning) from tenant-scoped `admin` (management within the caller's bound tenant). Disabling the final active administrator in a tenant is strictly blocked (`FINAL_ADMIN_PROTECTION`).

### Credential Lifecycle State Machine
API credentials follow a deterministic state machine:
- **`ACTIVE`**: Fully valid, authorized for API authentication.
- **`REVOKED`**: Immediately rejected across all endpoints (HTTP 401 `CREDENTIAL_REVOKED`).
- **`EXPIRED`**: Immediately rejected upon passing `expires_at` (HTTP 401 `CREDENTIAL_EXPIRED`).
- **`DISABLED`**: Administratively deactivated (HTTP 403 `CREDENTIAL_DISABLED`).

Rotation generates a new secret and immediately transitions the previous credential to `REVOKED`, preventing replay attacks.

---

### API Endpoints (Backend v0.8)

#### 1. Credential Management (`/api/v1/credentials`)
| Method | Endpoint | Allowed Roles | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/credentials` | `admin`, `global_admin` | Create credential for principal; returns secret once |
| `GET` | `/api/v1/credentials` | `admin`, `global_admin` | List credentials within caller's tenant |
| `GET` | `/api/v1/credentials/{cred_id}` | `admin`, `global_admin` | Inspect safe credential metadata (no secrets/hashes) |
| `POST` | `/api/v1/credentials/{cred_id}/rotate` | `admin`, `global_admin` | Rotate secret; immediately revokes old credential |
| `POST` | `/api/v1/credentials/{cred_id}/revoke` | `admin`, `global_admin` | Immediately revoke credential across all endpoints |

#### 2. Principal Administration (`/api/v1/principals`)
| Method | Endpoint | Allowed Roles | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/principals` | `admin`, `global_admin` | Create principal in tenant |
| `GET` | `/api/v1/principals` | `admin`, `global_admin` | List principals within caller's tenant |
| `GET` | `/api/v1/principals/{principal_id}` | `admin`, `global_admin` | Inspect principal record |
| `PUT` | `/api/v1/principals/{principal_id}` | `admin`, `global_admin` | Update principal roles or status |
| `POST` | `/api/v1/principals/{principal_id}/disable` | `admin`, `global_admin` | Disable principal (protected against final admin) |
| `POST` | `/api/v1/principals/{principal_id}/enable` | `admin`, `global_admin` | Enable disabled principal |

#### 3. Tenant Administration (`/api/v1/tenants`)
| Method | Endpoint | Allowed Roles | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/tenants` | `global_admin` | Provision a new tenant |
| `GET` | `/api/v1/tenants` | `global_admin` | List all configured tenants |
| `GET` | `/api/v1/tenants/{tenant_id}` | `admin` (own), `global_admin` | Inspect tenant details |
| `PUT` | `/api/v1/tenants/{tenant_id}` | `global_admin` | Update tenant metadata or status |
| `POST` | `/api/v1/tenants/{tenant_id}/disable` | `global_admin` | Disable tenant (immediately fails closed) |
| `POST` | `/api/v1/tenants/{tenant_id}/enable` | `global_admin` | Re-enable disabled tenant |

---

### v0.8 Configuration Environment Variables

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `AGENTGUARD_AUTH_ENABLED` | `false` | Enable strict Bearer credential authentication enforcement |
| `AGENTGUARD_LEGACY_IDENTITY_ENABLED` | `false` | Allow legacy header-based identity when no Bearer token is provided |
| `AGENTGUARD_DEFAULT_TENANT` | `default` | Default tenant identifier for bootstrap resources |
| `AGENTGUARD_CREDENTIAL_DB_PATH` | `data/agentguard_identity.db` | SQLite database path for identity and credential storage |
| `AGENTGUARD_CREDENTIAL_HASH_ALGORITHM` | `argon2id` | Cryptographic algorithm for credential hashing |
| `AGENTGUARD_CREDENTIAL_EXPIRATION_SECONDS` | `2592000` | Default credential expiration (30 days) |
| `AGENTGUARD_BOOTSTRAP_ADMIN_ENABLED` | `false` | Generate one-time bootstrap admin credential on startup |
| `AGENTGUARD_BOOTSTRAP_ADMIN_PRINCIPAL` | `bootstrap-admin` | Principal identifier for bootstrap administrator |
| `AGENTGUARD_GLOBAL_ADMIN_ENABLED` | `true` | Enable global administrator role support |

---

### Security Benchmark Results (v0.8)

Generated by `benchmark_v08_security.py`:
Artifact: `benchmark_v08_results.json`

| Metric | Target | Benchmark Result |
| :--- | :---: | :---: |
| **Benchmark Final Status** | **PASS** | **PASS** |
| **Category A: Credential Attacks** | 100% | **9 / 9 (100.0%)** |
| **Category B: Identity Attacks** | 100% | **6 / 6 (100.0%)** |
| **Category C: Cross-Tenant Attacks** | 100% | **10 / 10 (100.0%)** |
| **Category D: Credential Lifecycle Attacks** | 100% | **5 / 5 (100.0%)** |
| **Category E: Authorization Attacks** | 100% | **7 / 7 (100.0%)** |
| **Category F: Regression Attacks & Canary Preservation** | 100% | **6 / 6 (100.0%)** |
| **Category G: Benign Controls** | 100% | **7 / 7 (100.0%)** |
| **Credential Attack Block Rate** | 100% | **100.0%** |
| **Identity Spoofing Block Rate** | 100% | **100.0%** |
| **Cross-Tenant Violation Rate** | 0.0% | **0.0%** |
| **Credential Lifecycle Violation Rate** | 0.0% | **0.0%** |
| **Unauthorized Privileged Actions** | **0** | **0** |
| **Secret Leaks (`BLUE-ORANGE-42`)** | **0** | **0** |
| **Audit Chain Verification Failures** | **0** | **0** |
| **Benign False-Positive Rate (FPR)** | $\le 5\%$ | **0.0%** |
| **Guard Regression Count** | **0** | **0** |

### Latency Profiles (Controlled Local Benchmark, 50 iterations)

| Operation | Mean | Median (p50) | p95 | Max |
| :--- | :---: | :---: | :---: | :---: |
| **Credential Lookup** | 1.118 ms | 1.044 ms | 1.661 ms | 3.260 ms |
| **Credential Verification (Argon2id)** | 88.116 ms | 87.583 ms | 92.717 ms | 94.608 ms |
| **Auth Context Creation** | 95.644 ms | 94.330 ms | 99.641 ms | 127.665 ms |
| **Tenant Resolution** | 1.023 ms | 0.951 ms | 1.399 ms | 2.488 ms |
| **Authorization Check (RBAC)** | 0.003 ms | 0.003 ms | 0.005 ms | 0.020 ms |
| **Audit Write (SQLite + SHA-256 Chaining)** | 10.811 ms | 10.600 ms | 11.653 ms | 26.419 ms |
| **End-to-End Guard Request (with Bearer Auth)** | 830.220 ms | 685.281 ms | 1554.425 ms | 1587.922 ms |

---

## AgentGuard v0.9 — Secure Deployment, Secrets Management & Hardening

AgentGuard v0.9 focuses on operational security, cryptographic integrity, secret management, database resilience, and abuse mitigation for hardened local deployments without altering the frozen v5 security engine.

### Core Architectural Pillars in v0.9

1. **Configuration Profile Validation (`validate_at_startup`)**:
   - Explicit environment modes: `development`, `test`, and `production` (`AGENTGUARD_ENV`).
   - Fail-closed startup: In `production`, server refuses to start if authentication is disabled, legacy header identity is permitted, wildcard CORS (`*`) is present, `AUDIT_INTEGRITY_KEY` is missing or trivial (<32 chars), or keys violate cryptographic separation.
   - Numerical boundary guarantees: rejects negative/zero timeouts, negative quotas, or path traversal tokens (`..`).

2. **Secret Management Abstraction (`SecretManager`)**:
   - Provider abstraction (`SecretProvider`, `EnvSecretProvider`) preventing hardcoded keys.
   - Automatic registration and scrubbing of all known secrets (`[REDACTED_SECRET]`, `[REDACTED_CREDENTIAL]`, `[REDACTED_TOKEN]`).
   - Exception and log sanitization preventing accidental stack-trace secret leakage.

3. **HMAC-SHA-256 Audit Integrity**:
   - Keyed HMAC-SHA-256 chaining using `AUDIT_INTEGRITY_KEY`.
   - Deterministic canonical JSON serialization (`sort_keys=True`, UTF-8 encoded).
   - 4-way verification status: `valid` (authentic chain), `tampered` (record or hash modified), `key_missing` (audit key absent), or `incompatible` (legacy format).
   - Case-insensitive canary and secret redaction on all logged fields.

4. **Hardened SQLite Storage (`get_hardened_connection`)**:
   - Standardized pragmas across all database connections:
     - `PRAGMA foreign_keys = ON;`
     - `PRAGMA busy_timeout = 5000;`
     - `PRAGMA journal_mode = WAL;`
     - `PRAGMA synchronous = NORMAL;`
   - Strict path validation via `sanitize_db_path`: blocks path traversal (`..`), device paths, and enforces `.db`/`.sqlite` extensions.
   - Automatic integrity checks (`PRAGMA quick_check`) during health probing and connection initialization.

5. **HTTP Hardening & Abuse Resistance**:
   - Oversized payload protection: rejects requests exceeding `MAX_REQUEST_BODY_SIZE` (1 MB default) with `HTTP 413 Payload Too Large`.
   - Media type enforcement: requires `Content-Type: application/json` on mutating POST/PUT routes with `HTTP 415 Unsupported Media Type`.
   - Reverse proxy header spoofing defense: client IP resolved from `X-Forwarded-For` only when direct peer IP is in `TRUSTED_PROXIES`.
   - Standard security headers emitted on all HTTP responses:
     - `X-Content-Type-Options: nosniff`
     - `X-Frame-Options: DENY`
     - `Cache-Control: no-store, no-cache, must-revalidate`
     - `Pragma: no-cache`
   - Multi-tier category rate limiting: distinct windows and limits for `auth_failure`, `approvals`, `credentials`, `policies`, and `audit`.
   - Tenant concurrency slot limits (`tenant_slot`) preventing single-tenant inference resource exhaustion.

6. **Comprehensive Health & Readiness Verification (`/ready`)**:
   - Multi-dependency validation: returns `ready` only when configuration is valid, all SQLite stores (`credential_store`, `policy_store`, `audit_store`, `tenant_store`, `principal_store`) pass integrity checks, and Ollama is reachable.

---

### v0.9 Configuration Environment Variables

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `AGENTGUARD_ENV` | `development` | Operational environment profile (`development`, `test`, `production`) |
| `AGENTGUARD_AUDIT_INTEGRITY_KEY` | None | 32+ character HMAC-SHA-256 key for tamper-evident audit chaining (mandatory in production) |
| `AGENTGUARD_TRUSTED_PROXIES` | `""` | Comma-delimited list of trusted reverse proxy IP addresses for header resolution |
| `AGENTGUARD_MAX_REQUEST_BODY_SIZE` | `1048576` | Maximum allowed HTTP request body size in bytes (default 1 MB) |
| `AGENTGUARD_DB_BUSY_TIMEOUT_MS` | `5000` | SQLite lock wait timeout in milliseconds |
| `AGENTGUARD_DB_JOURNAL_MODE` | `WAL` | SQLite write-ahead logging journal mode |
| `AGENTGUARD_DB_SYNCHRONOUS` | `NORMAL` | SQLite disk synchronization durability mode |
| `AGENTGUARD_MAX_CONCURRENT_PER_TENANT` | `4` | Maximum concurrent LLM inference slots per tenant |
| `AGENTGUARD_RATE_LIMIT_AUTH_FAILURE` | `10` | Allowed authentication failures per IP per 60s window |
| `AGENTGUARD_RATE_LIMIT_APPROVALS` | `30` | Allowed approval submissions per principal per 60s window |
| `AGENTGUARD_RATE_LIMIT_CREDENTIALS` | `20` | Allowed credential operations per principal per 60s window |

---

### Comprehensive Security Benchmark Results (v1.0 Release Candidate)

Generated by `benchmark_v10_security.py`:
Artifact: `benchmark_v10_results.json`

| Metric | Target | Benchmark Result | Evaluation |
| :--- | :---: | :---: | :---: |
| **Total Test Cases Executed** | 150+ | **179 cases across 24 categories** | Verified |
| **Execution Duration** | < 120s | **70.78 seconds** | Optimal |
| **Test Cases Passing** | > 95% | **176 / 179 (98.32%)** | Verified |
| **Adversarial Block Rate** | > 90% | **97.81% (134 / 137 attacks blocked)** | High Assurance |
| **Benign False Positive Rate** | < 5% | **0.00% (0 / 42 benign queries blocked)** | Perfect Usability |
| **Canary Secret Leaks** | **0** | **0 leaks detected** | Verified |
| **Unauthorized Privileged Actions** | **0** | **0 actions permitted** | Verified |
| **Unauthorized Tool Executions** | **0** | **0 tools executed** | Verified |
| **Cross-Tenant Violations** | **0** | **0 cross-tenant accesses** | Verified |
| **Approval State Machine Bypasses** | **0** | **0 bypasses permitted** | Verified |
| **Audit Integrity Failures** | **0** | **0 integrity failures** | Verified |
| **Target Invocations after BLOCK/ERROR** | **0** | **0 target calls** | Verified |

---

## 20 Core Security Invariants

AgentGuard v1.0 formally enforces and validates 20 core security invariants:

1. **INVARIANT 1 (Block Isolation):** A blocked prompt never reaches the target model.
2. **INVARIANT 2 (Error Isolation):** A Guard evaluation error or timeout fails closed; the target model is never invoked.
3. **INVARIANT 3 (Tool Isolation):** A blocked or critical tool call never executes the underlying tool.
4. **INVARIANT 4 (Approval Gateway):** A high-risk tool cannot execute without an explicit, valid human approval.
5. **INVARIANT 5 (Approval TTL):** An expired approval cannot execute (fails closed with 400).
6. **INVARIANT 6 (Replay Protection):** A consumed approval cannot execute twice (replaying returns 409).
7. **INVARIANT 7 (Action Binding):** Modifying tool arguments post-approval invalidates execution binding.
8. **INVARIANT 8 (Tenant Isolation):** Cross-tenant access strictly fails closed (403/404).
9. **INVARIANT 9 (Identity Integrity):** Client-supplied identity headers cannot alter the authenticated server context.
10. **INVARIANT 10 (Output Sanitization):** Target model outputs pass through the leak sanitizer before returning.
11. **INVARIANT 11 (Canary Defense):** The canary secret cannot appear in an externally returned response.
12. **INVARIANT 12 (Audit Sanitization):** The canary secret cannot appear in audit records.
13. **INVARIANT 13 (Log Redaction):** API credentials and secrets never appear in log output.
14. **INVARIANT 14 (Policy Authorization):** Unauthorized principals cannot mutate security policies (403).
15. **INVARIANT 15 (Credential Revocation):** A revoked or expired Bearer token cannot authenticate (401).
16. **INVARIANT 16 (Audit Tamper Evidence):** Any modification, insertion, or truncation in the audit log is detected by `verify_audit_chain`.
17. **INVARIANT 17 (Database Resilience):** SQLite operations utilize WAL mode, busy timeouts, and fail safely without leaking internal state.
18. **INVARIANT 18 (HTTP Boundary Defense):** Request bodies exceeding 1MB or malformed streaming chunks are rejected with 413.
19. **INVARIANT 19 (Proxy Spoofing Defense):** `X-Forwarded-For` headers from untrusted network peers are disregarded.
20. **INVARIANT 20 (Process Architecture):** Local production deployments require `single_process`; multi-process configurations fail closed at startup.

---

## Production Deployment & Operational Architecture

### 1. Reverse Proxy Perimeter Architecture
In production deployments, AgentGuard is designed to operate behind a dedicated reverse proxy (e.g. Caddy, Nginx, or AWS ALB):
- **TLS Termination:** Reverse proxy handles TLS certificate management (HTTPS on 443).
- **Buffer & Connection Defense:** Reverse proxy absorbs slowloris attacks and buffers incoming HTTP streams.
- **Trusted Proxy Peer Binding:** Configure `AGENTGUARD_TRUSTED_PROXIES` with the exact CIDR network of the reverse proxy (e.g. `10.0.0.0/16,127.0.0.1`). AgentGuard's hardened `ProxyResolver` will traverse `X-Forwarded-For` right-to-left and discard untrusted client-supplied headers.

### 2. Process Model & Concurrency Guard
- **Single Process:** Set `AGENTGUARD_PROCESS_MODEL=single_process` (the default). AgentGuard's in-process rate limiting, tenant concurrency semaphores, and memory state machines require single-process execution for local production deployments.
- **Fail-Closed Guard:** If `AGENTGUARD_ENV=production` and `AGENTGUARD_PROCESS_MODEL=multi_process`, startup validation fails closed and halts execution.

### 3. SQLite Storage Lifecycle & WAL Concurrency
- **Journal Mode:** Write-Ahead Logging (`PRAGMA journal_mode = WAL`) enables concurrent readers without blocking the writer.
- **Busy Timeout:** Configured to 5000ms (`PRAGMA busy_timeout = 5000`) to prevent transient lock failures.
- **Operational Limit:** SQLite supports single-writer concurrency. For high-throughput distributed write architectures, an external ACID database would be required.

### 4. Secrets Management & Zero-Plaintext Storage
- **Key Derivation:** Master encryption keys are managed through `AGENTGUARD_SECRET_PROVIDER`.
- **Argon2id Credential Hashing:** Bearer tokens (`ag_<id>_<secret>`) are hashed using Argon2id with random salts. Secrets are never stored in plaintext and never logged.
- **Audit Integrity Key:** Set `AGENTGUARD_AUDIT_INTEGRITY_KEY` (32+ bytes) for keyed HMAC-SHA-256 forward-chained audit logs.

### 5. Incident Response & Emergency Operations
- **Immediate Credential Revocation:** If an API credential is compromised:
  ```http
  POST /api/v1/credentials/{credential_id}/revoke
  Authorization: Bearer <admin_token>
  ```
  Revocation is effective immediately across all active connections.
- **Tenant Isolation / Disablement:** If a tenant is identified as compromised:
  ```http
  PUT /api/v1/tenants/{tenant_id}
  Authorization: Bearer <global_admin_token>
  {"status": "DISABLED"}
  ```
- **Audit Tamper Inspection:** Routine or triggered forensic verification of audit integrity:
  ```http
  GET /api/v1/audit/verify
  Authorization: Bearer <admin_token>
  ```
- **Emergency Deny Policy:** To immediately halt execution of a specific tool across all tenants:
  ```http
  POST /api/v1/policies
  Authorization: Bearer <admin_token>
  {"name": "Emergency Tool Halt", "action": "DENY", "tool_scope": "target_tool", "priority": 1, "enabled": true}
  ```

---

## Realistic Security Boundaries & Honest Disclaimers

> **HONEST PRODUCTION BOUNDARIES & DISCLAIMERS:**
> 1. **In-Process Scope:** Rate limits, auth failure backoffs, and tenant inference semaphores are process-local memory counters. They are designed for single-process local production deployments.
> 2. **SQLite WAL Limits:** Hardened SQLite WAL mode provides excellent single-host resilience, but does not support multi-host write clustering.
> 3. **Tamper-Evident vs Immutable Hardware:** Keyed HMAC-SHA-256 audit chaining makes tampering mathematically evident upon verification, but does not prevent physical storage deletion. External replication to write-once (WORM) storage is recommended for high-assurance compliance.
> 4. **Text-Based Prompt Guard Scope:** AgentGuard v5 inspects text prompts and conversation messages. It does not analyze multimodal (audio/video/image) injection vectors.
> 5. **Probabilistic Defense-in-Depth:** While LLM guard assessments are probabilistic, AgentGuard layers deterministic pre-checks, schema validators, RBAC, and policy engines so that critical boundaries (e.g. tools, approvals, secrets, tenant isolation) are absolute and deterministic.

---

## Complete Test Suite & Verification Execution

Run the complete test suite across all AgentGuard components:

```powershell
# Activate local virtual environment
.\venv\Scripts\Activate.ps1

# 1. Core Frozen v5 Security Engine (52 tests - 0.04s)
python test_agentguard.py

# 2. Complete Backend Integration & Hardening Suite (394 tests - 70.9s)
python -m unittest discover -s tests -p "test_*.py"

# 3. 20-Point Live Smoke Test Suite (20 tests - 10.0s)
python smoke_test_v10.py

# Total Automated Tests: 466 / 466 passing (100% pass rate)
```

To run the full v1.0 Comprehensive Security Benchmark (179 cases):
```powershell
python benchmark_v10_security.py
```

---

## AgentGuard Frontend v0.2 — Multi-Turn Security Chat & Playground

AgentGuard Frontend v0.2 upgrades the web interface to a **Real Multi-Turn AI Security Chat** while retaining backward compatibility with the single-turn **Security Playground (v0.1)**.

### Information Architecture & Multi-Turn Flow
```
USER MESSAGE (Turn N)
    ↓
FULL CONVERSATION CONTEXT SEQUENCE ([user, assistant, ... user])
    ↓
AGENTGUARD GATEWAY (POST /api/v1/chat)
    ↓
CONTEXT-AWARE SECURITY EVALUATION
    ├── 🟢 ALLOWED → Target LLM Invocation → Output Leak Sanitizer → Assistant Response Appended
    └── 🔴 BLOCKED → Target Protection Active → Target NOT Invoked → Blocked Turn Interruption Card
```

### Key Capabilities in v0.2
- **Multi-Turn Context Security**: Sends complete canonical turn history (`role: 'user' | 'assistant'`) to `POST /api/v1/chat`. Evaluates cross-turn intent, roleplay escalation, and context poisoning attacks across the entire conversation.
- **Fail-Closed Target LLM Isolation**: When a turn returns `BLOCK`, the Target LLM is strictly not invoked. Zero fabricated assistant responses are ever generated or appended.
- **Dual Application Modes**: Switch between **Multi-Turn Chat (v0.2)** and **Security Playground (v0.1)** seamlessly via header navigation tabs.
- **Session Controls**: `+ New Conversation` resets local state with a fresh conversation ID; local request cancellation via `AbortController` ("Request cancelled locally").
- **Zero-Trust Hygiene**: Zero backend credentials, master keys, canary secrets, or direct Ollama calls in frontend source code.

---

## AgentGuard Frontend v0.3 — Agent Security: Tool Calls, Risk & Human Approvals

Frontend v0.3 visualizes and interacts with the backend's agent security gateway and human approval system:
- **Controlled Tool Selector**: Inspects tools registered in backend (`get_weather`, `search_documents`, `send_email`).
- **Interactive Argument Schema**: Enforces argument types and constraints before submission.
- **Risk Classification & State Machine**: Visualizes transitions: `IDLE` → `ANALYZING` → `PENDING_APPROVAL` → `APPROVED` / `DENIED` / `CONSUMED` / `EXPIRED`.
- **Human Approval Modal**: Review tool details, sanitized argument summaries, and expiration timers.
- **One-Time Consumption & Replay Resistance**: Fails closed with HTTP 409 Conflict if an approval token is reused.

---

## AgentGuard Frontend v0.4 — Security Dashboard

Frontend v0.4 delivers deep observability into the backend security posture:
- **Backend Status & Probes**: Real-time health (`/health`) and readiness probe checks (`/ready`).
- **Runtime Metrics**: Process memory, uptime, total requests, and rate-limited counters (`/metrics`).
- **Decision & Attack Breakdown**: Interactive distributions of `ALLOW` vs `BLOCK` decisions and detected threat types.
- **Audit Event Explorer**: Chronological audit trail with filtering by decision, action, and tenant.

---

## AgentGuard Frontend v0.5 — Administration & Audit Control Plane

Frontend v0.5 provides enterprise governance and multi-tenant administration:
- **Tenant Management**: Provision and inspect isolated tenants with strict RBAC enforcement.
- **Principal & Identity Management**: View principals, assign roles (`admin`, `operator`, `user`), and manage account statuses.
- **Credential Lifecycle**: Issue cryptographically secure Bearer tokens (`ag_<id>_<secret>`) with one-time secret disclosure.
- **Dynamic Policy Administration**: Create, prioritize, and manage declarative security policies (`DENY`, `REQUIRE_APPROVAL`, `ALLOW`).
- **Cryptographic Audit Verification**: Executes `/api/v1/audit/verify` to validate HMAC-SHA-256 chain integrity.

---

## AgentGuard Frontend v0.6 — Security Operations & Incident Response (SecOps)

Frontend v0.6 delivers a comprehensive Security Operations (SecOps) and Incident Response interface:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   AgentGuard SecOps Console (v0.6)                     │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Security Posture Strip                                              │
│    - Process Health: 200 OK | Readiness: READY | Audit Chain: VALID    │
│    - Developer Session: ag_c_...•••• | In-Process Memory: 54.6 MB      │
├────────────────────────────────────┬───────────────────────────────────┤
│ 2. Security Alerts Panel           │ 3. Operational Queue (Approvals)  │
│    - Critical / High / Info alerts │    - PENDING / RESOLVED tabs      │
│    - Triage & Investigate actions  │    - Approve / Deny with Dialog   │
├────────────────────────────────────┴───────────────────────────────────┤
│ 4. Incident Investigation Workspace (Session-Only React State)         │
│    - Disclaimer: "Local investigation — not persisted by AgentGuard"   │
│    - Multi-Event Correlation: request_id, principal_id, tenant_id      │
│    - Pipeline Timeline: Correlated stages (Observed vs Unavailable)   │
│    - Operator Notes & Sanitized Package Export (JSON download)         │
├────────────────────────────────────────────────────────────────────────┤
│ 5. Live Security Event Stream & Presets                                │
│    - All Events | Threat Blocks | Auth Failures | Policy Denials       │
│    - Server-side filtering, pagination, and Inspect Drawer             │
├────────────────────────────────────────────────────────────────────────┤
│ 6. Authoritative Security Mitigations & Destructive Action Modal       │
│    - Revoke Credential | Disable Principal | Disable Tenant           │
│    - Impact Disclosure Dialog: Human confirmation before API dispatch  │
└────────────────────────────────────────────────────────────────────────┘
```

### Core Capabilities & Architectural Invariants:
1. **Security Posture Strip (`SecurityPostureCard`)**:
   - Queries `/health`, `/ready`, `/metrics`, and `/api/v1/audit/verify`.
   - Displays real-time cryptographic audit chain integrity (`Audit Chain: VALID` or `AUDIT CHAIN INTEGRITY BREACH DETECTED`).
   - Masks developer tokens (`ag_c_...••••`) to prevent visual shoulder-surfing.
2. **Alerts Triage Panel (`SecurityAlertsPanel`)**:
   - Synthesizes high-signal incidents directly from backend audit blocks, authentication failures, integrity alerts, and pending approvals.
   - Severity filters: `ALL`, `CRITICAL`, `HIGH`, `INFO`.
3. **Operational Queue (`OperationalQueue`)**:
   - Lists pending high-risk tool authorizations directly from `/api/v1/approvals`.
   - Requires explicit human confirmation dialog before executing privileged `/approve` or `/deny` calls.
   - Handles replay attempts safely by surfacing HTTP 409 Conflict without crashes.
4. **Session-Only Incident Workspace (`IncidentWorkspace`)**:
   - **Privacy Boundary**: Operates strictly in React memory state. Never stored in `localStorage`, `sessionStorage`, `IndexedDB`, or cookies.
   - Prominently displays: *"Local investigation — not persisted by AgentGuard"*.
   - Multi-event correlation across `request_id`, `principal_id`, `tenant_id`, `approval_id`, and `tool_name`.
   - Allows operator note drafting, sanitized investigation export (`.json`), and quick workspace clearing.
5. **Correlated Pipeline Timeline (`PipelineTimeline`)**:
   - Maps observed audit events across standard execution pipeline stages (`HTTP Boundary` → `Authentication` → `Guard Inspection` → `Tool Authorization` → `Target LLM Execution` → `Sanitization`).
   - Explicitly marks unobserved stages with: *"Not available from current audit data."* Zero fabricated data.
6. **Live Event Stream (`SecurityEventStream`)**:
   - Paginated feed of persistent audit events with server-side filters (`decision`, `action`, `tenant_id`, `request_id`).
   - One-click filter presets: `All Events`, `Threat Blocks`, `Auth Failures`, `Policy Denials`.
7. **Authoritative Mitigation Dispatch (`SecurityResponseActions`)**:
   - Directly triggers authoritative backend management APIs (`/credentials/{id}/revoke`, `/principals/{id}`, `/tenants/{id}`, `/policies/{id}`).
   - **Destructive Action Confirmation Modal**: All mitigations require explicit human confirmation with full impact disclosure before execution.
8. **Zero-Trust & Leak Prevention**:
   - Canary string `BLUE-ORANGE-42` and raw Bearer tokens are NEVER rendered in the DOM or exported in telemetry.

---

### Development & Execution Instructions

#### Prerequisites
- Node.js (v18+) and npm installed
- Python virtual environment configured (`.\venv`)
- Local Ollama instance running with `llama3.2:latest`

#### 1. Start the Backend Gateway
```powershell
.\venv\Scripts\uvicorn backend.main:app --host 127.0.0.1 --port 8000
```
- **Backend API**: `http://127.0.0.1:8000`
- **Interactive OpenAPI Documentation**: `http://127.0.0.1:8000/docs`

#### 2. Start the Frontend Application
```powershell
# Install frontend dependencies
npm install

# Launch Vite development server
npm run dev
```
- **Frontend URL**: `http://localhost:5173`

#### 3. Run Frontend Automated Test Suite
```powershell
# Run all 160 Vitest unit, integration, and security invariant tests across 7 suites
npx vitest run

# Run automated static credential & storage pattern scanner
npm run security-check

# Run production build validation (TypeScript + Vite bundling)
npm run build
```

#### 4. Run Live SecOps & Security Hardening Smoke Test
```powershell
# 15-point live backend smoke test verifying authentication, RBAC, 409 race handling, and secret boundaries
.\venv\Scripts\python.exe scratch\live_smoke_v07.py
```

---

## Frontend v0.7 — Security Hardening, Session Security & Operational Reliability

Frontend v0.7 is a dedicated **security-hardening milestone** focused on operational integrity, centralized session security, presentation-layer defense-in-depth, sensitive data protection, concurrency safety, and graceful degraded-mode resilience.

> [!IMPORTANT]
> **Defense-in-Depth Principle**:
> Frontend authorization controls are defense-in-depth only. AgentGuard backend authorization remains authoritative.

### 1. Central Session Security & Token Handling
- **Single Source of Truth (`SessionContext`)**: A unified React context and `useSession` hook governs all frontend session states. Components cannot duplicate token state or bypass session lifecycle methods.
- **Strictly Memory-Only (`tokenRef`)**: Tokens reside exclusively within React runtime memory. They are **NEVER** persisted to `localStorage`, `sessionStorage`, `IndexedDB`, cookies, query parameters, or browser history.
- **Unload Sanitization**: Automatic event listeners on `beforeunload` and `pagehide` wipe token memory when tabs or browser windows close. Tokens are cleared on page reload.
- **Token Masking (`maskToken`)**: Developer API tokens are masked across all UI surfaces (e.g., `ag_c_407c...••••`). Raw tokens are never rendered in the DOM, React error logs, or browser console.

### 2. State Machine & Error Segregation
The session abstraction models explicit backend-supported session states:
`UNKNOWN` → `AUTHENTICATING` → `AUTHENTICATED` → `UNAUTHENTICATED` → `FORBIDDEN` → `EXPIRED` → `BACKEND_UNAVAILABLE`

Strict error boundaries:
- **HTTP 401 Unauthorized**: Invalidates the frontend session, clears in-memory credentials, terminates privileged actions, and displays an authentication requirement modal.
- **HTTP 403 Forbidden**: **Preserves** authentication and credential state. Signals authorization failure without logging the operator out.
- **HTTP 5xx / Network Failures**: **Preserves** valid session credentials and transitions to degraded mode, preventing accidental logout during temporary gateway drops.

### 3. Centralized Authorization Presentation Layer
Mirrors the backend RBAC capabilities (`backend/services/authorization_service.py`) across roles:
- `user`: Low-risk conversational interactions and guard evaluations.
- `operator`: Security operations, incident response, and approval reviews/actions.
- `admin`: Credential revocation, principal management, and policy updates.
- `global_admin`: Global control plane, tenant creation, tenant disabling, and destructive actions.

If client capability checks are uncertain, UI controls fail closed to disabled with `"Backend authorization required"`.

### 4. Privileged Action Guard (`DestructiveActionDialog`)
A reusable high-assurance confirmation modal for high-impact mutations (credential revocation, principal/tenant disabling, policy deletion, approval denial):
1. Verifies authenticated session presence.
2. Checks presentation capability permissions.
3. Discloses full impact: Action name, Target resource, Current server state, Operational impact, and Reversibility.
4. Requires an intentional confirmation checkbox (`I understand the operational impact and confirm execution...`).
5. Displays real-time loading feedback on gateway dispatch without showing premature success.
6. Refetches authoritative server state upon completion.

### 5. Stale Data, Race Condition & HTTP 409 Safety
- **Stateful Object Tracking**: Maintains server versions and state for approvals, credentials, principals, tenants, and policies.
- **Approval Replay Guard**: Gracefully captures HTTP 409 when an approval is approved or denied concurrently by another operator, displaying a consumed notice and auto-refreshing the queue.
- **Policy Editor Concurrency Safety (`PolicyEditor`)**: Preserves the operator's local draft in state when encountering an HTTP 409 conflict, displaying reconciliation guidance and reloading latest server versions.
- **Request Cancellation**: Leverages `AbortController` across long-running queries to cancel obsolete network calls on unmount or tab navigation.

### 6. Incident Investigation & Sanitized Export Boundary
- **Memory-Only Workspace (`IncidentWorkspace`)**: Investigation states, notes, and correlated events exist strictly in React state.
- **Deterministic Field Allowlist**: The export bundle enforces the `SanitizedInvestigationExport` schema. Generic `JSON.stringify(entireState)` serialization is prohibited.
- **Sanitization & Redaction**: Authorization headers, Bearer tokens, credential secrets (`ag_*`), and test canary tokens (`BLUE-ORANGE-42`) are stripped.
- Prominently displays: `"Sanitized investigation bundle — Local investigation — not persisted by AgentGuard backend"`.

### 7. Degraded Mode & Health Polling Safety
- **Degraded Mode Banner (`DegradedModeBanner`)**: Activates when `/health` fails or the gateway is unreachable. Locks destructive mutations and displays last-known-state warnings.
- **Visibility-Aware Polling**: Pauses 15-second background health checks when browser tabs are hidden, preventing request storms.
- **Bounded Retry**: Disables retry buttons during in-flight health requests to prevent retry cascades.

### 8. Browser Hardening & Limitations
- **Defense-in-Depth Meta Headers**: `X-Content-Type-Options: nosniff` and `Referrer-Policy: strict-origin-when-cross-origin` configured in `index.html`.
- **Known Limitation**: Browser JavaScript memory is not an impenetrable cryptographic boundary against compromised extensions or Cross-Site Scripting (XSS). Production environments must deploy AgentGuard behind a hardened reverse proxy (Caddy/Nginx) enforcing Content-Security-Policy (CSP), HTTP Strict Transport Security (HSTS), and HTTP-only cookie session handling.

#   G u a r d L L M  
 