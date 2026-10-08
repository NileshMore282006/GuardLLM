# AgentGuard Security Threat Model & Invariant Architecture (v1.0 RC)

**Document Version:** 1.0.0-RC  
**Application:** AgentGuard Integrated Security Gateway  
**Engine:** Frozen v5 Multi-Layer Guard Engine  
**Classification:** Public Security Specification  

---

## 1. System Overview & Architecture

AgentGuard is a deterministic, defense-in-depth security gateway positioned between untrusted clients and large language models (LLMs). The gateway intercepts all inbound requests, authenticates callers, enforces multi-tenant boundaries and role-based access control (RBAC), evaluates requests against dynamic policy, applies the frozen v5 multi-layer prompt-injection security engine, monitors and governs mock tool calls with human approval gates, scrubs outputs through a leak sanitizer, and records every security decision in a tamper-evident HMAC-SHA256 audit log.

```
Untrusted Client Input
        ↓
HTTP Boundary Protection (Bounded Body, CIDR-Hardened Proxy Resolver, CORS, Media Type)
        ↓
In-Process Rate / Abuse Controls (Per-Client Network IP & Per-Principal Category Limits)
        ↓
Authentication & Credential Verification (Argon2id Hashes, Prefixed Bearer Tokens)
        ↓
Tenant Resolution & Isolation (Strict Tenant Context, Single & Multi-Tenant Boundaries)
        ↓
Role-Based Access Control (RBAC: Admin, Operator, User Roles)
        ↓
Dynamic Policy Engine (Principal / Tool / Action Authorization Matrix)
        ↓
Frozen v5 Guard Engine (Deterministic Heuristic, Regex, Perplexity, Structural Pre-Checks)
        ↓
Tool Authorization Gate (Schema Enforcement, Argument Sanitization, Injection Detection)
        ↓
Human Approval Gate (High/Critical Actions, Single-Use Token, TTL, Hash Binding)
        ↓
Execution Boundary (Isolated Target LLM & Deterministic Mock Tool Executors)
        ↓
Output Leak Sanitizer (Canary Scrubbing, Registered Secret Redaction, Response Capping)
        ↓
HMAC-SHA256 Audit Log (Forward-Chained Cryptographic Hashes, Tamper-Evident Storage)
        ↓
Persistent SQLite Hardened Storage (WAL Mode, Secure Deletes, Foreign Key Enforcements)
```

---

## 2. Protected Assets

| Asset ID | Asset Name | Description | Confidentiality | Integrity | Availability |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **AST-01** | **API Credentials** | Bearer tokens (`ag_<id>_<secret>`) and Argon2id hash digests | High | High | High |
| **AST-02** | **Tenant Identity** | Boundary bindings separating organization and workspace data | High | High | High |
| **AST-03** | **Principals & Roles** | User identities, role memberships (`admin`, `operator`, `user`), and permissions | Medium | High | High |
| **AST-04** | **Security Policies** | Dynamic rule sets defining ALLOW, DENY, and REQUIRE_APPROVAL actions | Medium | High | High |
| **AST-05** | **Human Approvals** | Time-bound, hash-bound tokens authorizing single execution of high-risk tools | High | High | High |
| **AST-06** | **Target LLM Access** | Gateway access to downstream generative models (e.g., Llama 3.2) | High | High | High |
| **AST-07** | **Tool Execution** | Mock tool actions (e.g., `get_weather`, `send_email`, `delete_record`) | High | High | High |
| **AST-08** | **Audit Integrity Key** | Server-side HMAC-SHA256 secret key (`AUDIT_INTEGRITY_KEY`) | Critical | Critical | High |
| **AST-09** | **Canary Secret** | High-entropy canary token (`BLUE-ORANGE-42`) verifying data leakage | Critical | Critical | N/A |
| **AST-10** | **Audit Trail** | Chronological record of security events, decisions, and hash links | Medium | High | High |

---

## 3. Trust Boundaries

```
[ External / Untrusted Zone ]
        |
        | TB-1: HTTP Gateway Boundary (Untrusted Network → Gateway Process)
        v
[ AgentGuard Gateway Process ]
        |
        | TB-2: Authentication & Identity Boundary (Caller → Context)
        | TB-3: Tenant Isolation Boundary (Tenant A ⟷ Tenant B)
        | TB-4: Frozen v5 Security Engine Boundary (Gateway → Guard Evaluator)
        | TB-5: Tool & Human Approval Boundary (Gateway → Mock Tool Executor)
        | TB-6: Target LLM Boundary (Gateway → Ollama Inference Engine)
        | TB-7: Cryptographic Persistence Boundary (Gateway → SQLite DBs)
```

### Trust Boundary Details
- **TB-1 (HTTP Gateway Boundary):** The perimeter facing untrusted callers. Validates HTTP methods, verifies JSON media types, limits actual streaming body length to 1 MB, and parses proxy headers using strict right-to-left traversal against configured IPv4/IPv6 CIDR ranges.
- **TB-2 (Authentication Boundary):** Separates unauthenticated callers from authorized principals. Credentials use Argon2id hashing with prefixed high-entropy tokens. Caller headers (`X-AgentGuard-Role`, etc.) are ignored when Bearer auth is active.
- **TB-3 (Tenant Isolation Boundary):** Enforces horizontal data isolation. Non-admin users cannot query, mutate, or view audit logs, approvals, or credentials belonging to another tenant.
- **TB-4 (Frozen v5 Guard Boundary):** Immutable prompt-injection evaluation boundary. Evaluates prompts against direct, indirect, multi-turn, and obfuscated adversarial injections. Target LLM is never invoked if Guard emits BLOCK or ERROR.
- **TB-5 (Tool & Approval Boundary):** Governs tool invocation. Models propose tools, but the gateway evaluates arguments, blocks unknown tools, checks parameter types, and diverts high/critical tools into an approval state machine.
- **TB-6 (Target LLM Boundary):** Target LLM is invoked strictly after Guard ALLOW. Outputs pass through the leak sanitizer before leaving the gateway boundary.
- **TB-7 (Cryptographic Persistence Boundary):** Hardened SQLite databases with WAL mode, foreign keys, synchronous NORMAL, and forward-chained HMAC-SHA256 audit hashes.

---

## 4. Threat Catalog, Mitigations & Residual Risks

### THR-01: Direct & Indirect Prompt Injection
- **Threat:** Attacker crafts adversarial instructions to override system prompts or hijack model intent.
- **Mitigation:** Frozen v5 security engine with multi-layer heuristics, regex pre-checks, perplexity analysis, character normalization, and structural bounds. Tool outputs are enclosed in `<untrusted_tool_data>` context before model reflection.
- **Test Coverage:** `tests/test_end_to_end_security.py` (Inv 1, 2), `test_agentguard.py` (52 cases), `benchmark_v10_security.py`.
- **Residual Risk:** Novel zero-day jailbreaks outside the linguistic and structural distributions of frozen v5 may evade text classification. Multimodal prompt injection is outside frozen v5 scope.

### THR-02: Identity & Role Header Spoofing
- **Threat:** Attacker provides headers like `X-AgentGuard-Role: admin` to gain elevated privileges.
- **Mitigation:** Server-bound security context resolution. When Bearer credentials are supplied or identity is enabled, server derives principal, roles, and tenant exclusively from authenticated database records. Client headers are logged as security alerts and disregarded.
- **Test Coverage:** `tests/test_end_to_end_security.py` (Inv 9, 19), `tests/test_proxy_security.py`.
- **Residual Risk:** Legacy unauthenticated mode (`LEGACY_IDENTITY_ENABLED=True`) trusts headers for testing, but is strictly prohibited in production profiles by startup validation.

### THR-03: Proxy Header Spoofing (X-Forwarded-For Bypass)
- **Threat:** Attacker sends fake `X-Forwarded-For: 127.0.0.1` to spoof client identity and evade rate limits.
- **Mitigation:** `ProxyResolver` implements right-to-left traversal. Header is inspected only if the immediate network peer matches configured IPv4/IPv6 individual addresses or CIDR ranges. Untrusted headers from unvetted peers are discarded.
- **Test Coverage:** `tests/test_proxy_security.py` (8 test cases).
- **Residual Risk:** Misconfiguration of `TRUSTED_PROXIES` (e.g., trusting `0.0.0.0/0`) would expose the gateway to forwarded header spoofing.

### THR-04: Request Body Exhaustion (Chunked & Missing Content-Length)
- **Threat:** Attacker omits `Content-Length` or uses chunked transfer encoding with unbounded streaming data to exhaust server memory.
- **Mitigation:** Streaming body boundary middleware reads request stream chunk-by-chunk up to `MAX_REQUEST_BODY_SIZE + 1`. If cumulative bytes exceed 1 MB, stream reading halts immediately, chunks are released, and HTTP 413 is returned.
- **Test Coverage:** `tests/test_body_security.py` (7 test cases).
- **Residual Risk:** Transport-level slowloris attacks targeting open sockets before HTTP middleware execution must be mitigated by a perimeter reverse proxy (e.g., NGINX / Envoy).

### THR-05: High-Risk Tool Execution Without Approval
- **Threat:** Model generates high-risk tool call (e.g., `send_email`) that executes side-effects autonomously.
- **Mitigation:** Deterministic tool classification. High and critical tools cannot execute through `/api/v1/tool/execute`. Instead, an approval record is created in `PENDING_APPROVAL` status requiring an explicit operator/admin action.
- **Test Coverage:** `tests/test_end_to_end_security.py` (Inv 3, 4), `tests/test_failure_injection.py`.
- **Residual Risk:** Human approvers approving malicious requests based on deceptive summaries.

### THR-06: Approval Token Replay & Argument Tampering
- **Threat:** Attacker re-uses an approved token or alters arguments after approval has been granted.
- **Mitigation:** Cryptographic argument binding via SHA-256 canonical argument hashes. Strict state machine transitions (`PENDING_APPROVAL` → `APPROVED` → `CONSUMED`). Second execution attempts fail with HTTP 409 `APPROVAL_ALREADY_CONSUMED`. Tampered arguments fail binding verification.
- **Test Coverage:** `tests/test_end_to_end_security.py` (Inv 5, 6, 7), `tests/test_failure_injection.py`.
- **Residual Risk:** In-memory approval store does not survive application process restart (by design in local v1.0).

### THR-07: Cross-Tenant Data Access
- **Threat:** Principal from Tenant A queries or mutates audit events, credentials, or policies of Tenant B.
- **Mitigation:** Database queries filter by `tenant_id`. Callers cannot view or modify resources where `caller.tenant_id != resource.tenant_id` unless holding global admin authority.
- **Test Coverage:** `tests/test_end_to_end_security.py` (Inv 8, 16).
- **Residual Risk:** Operator error granting global admin role to non-administrative principals.

### THR-08: Audit Log Tampering
- **Threat:** Rogue administrator or compromised local actor modifies, deletes, or inserts audit records to erase unauthorized actions.
- **Mitigation:** Forward-chained HMAC-SHA256 signature chain. Each record incorporates the previous event's hash, timestamp, action, tenant, principal, decision, and risk score. Cryptographic verification detects any modification, deletion, reordering, or insertion.
- **Test Coverage:** `tests/test_audit_tampering.py` (14 comprehensive tampering cases).
- **Residual Risk:** SQLite database files reside on local storage. An attacker with filesystem write access and the `AUDIT_INTEGRITY_KEY` could recalculate the entire chain. Forwarding logs to append-only remote storage is recommended for enterprise setups.

### THR-09: Sensitive Credential & Canary Leakage
- **Threat:** Canary secret or user API tokens appear in model output, logs, or audit events.
- **Mitigation:** Three-tier leak protection:
  1. Output leak sanitizer scrubs canary tokens from model and tool responses.
  2. Audit event sanitizer redacts secrets and bearer tokens before database persistence.
  3. Structured logging filter scrubs tokens matching `ag_<id>_<secret>` and `Bearer ...`.
- **Test Coverage:** `tests/test_end_to_end_security.py` (Inv 10, 11, 12, 13).
- **Residual Risk:** High-entropy non-canary business secrets not registered in `SecretManager` are not detected by regex token matchers.

---

## 5. Fail-Closed Security Decision Matrix

The following matrix documents the deterministic system behavior across normal, malicious, and system failure conditions:

| Subsystem | Condition | Gateway Decision | Target Invocation | Tool Execution | Client Status | Error / Code |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **Guard** | Evaluation ALLOW | **ALLOW** | **Permitted** | N/A | 200 OK | `attack_type=none` |
| **Guard** | Evaluation BLOCK | **BLOCK** | **NEVER** | N/A | 200 OK | `attack_type=<type>` |
| **Guard** | Guard Timeout | **BLOCK** | **NEVER** | N/A | 200 OK | `attack_type=guard_timeout` |
| **Guard** | Guard Runtime Exception | **BLOCK** | **NEVER** | N/A | 200 OK | `attack_type=guard_error` |
| **Guard** | Ollama Connection Refused | **BLOCK** | **NEVER** | N/A | 200 OK | `attack_type=guard_error` |
| **Target** | Target Timeout | **ERROR** | Failed | N/A | 200 OK | `decision=ERROR`, `response=None` |
| **Target** | Target Exception | **ERROR** | Failed | N/A | 200 OK | `decision=ERROR`, `response=None` |
| **Tool** | Read-Only Low Risk ALLOW | **ALLOW** | N/A | **Permitted** | 200 OK | Deterministic Mock Result |
| **Tool** | Schema / Injection BLOCK | **BLOCK** | N/A | **NEVER** | 200 OK | `decision=BLOCK`, `result=None` |
| **Tool** | Unknown Tool Name | **BLOCK** | N/A | **NEVER** | 200 OK | `attack_type=unknown_tool` |
| **Tool** | High Risk Without Approval | **BLOCK** | N/A | **NEVER** | 200 OK | Direct execute returns `BLOCK` |
| **Approval** | Create High Risk Request | **PENDING** | N/A | **NEVER** | 200 OK | Returns `approval_id` |
| **Approval** | Legitimate Human Approve | **ALLOW** | N/A | **Executed Once**| 200 OK | Transitions to `CONSUMED` |
| **Approval** | Expired Approval (TTL) | **BLOCK** | N/A | **NEVER** | 400 Bad Req | `APPROVAL_EXPIRED` |
| **Approval** | Replayed Approval | **BLOCK** | N/A | **NEVER** | 409 Conflict | `APPROVAL_ALREADY_CONSUMED` |
| **Approval** | Tampered Tool Arguments | **BLOCK** | N/A | **NEVER** | 409 Conflict | `argument_hash_mismatch` |
| **Auth** | Missing / Invalid Token | **DENY** | **NEVER** | **NEVER** | 401 Unauth | `AUTHENTICATION_REQUIRED` |
| **Auth** | Revoked Credential | **DENY** | **NEVER** | **NEVER** | 401 Unauth | `CREDENTIAL_REVOKED` |
| **Auth** | Expired Credential | **DENY** | **NEVER** | **NEVER** | 401 Unauth | `CREDENTIAL_EXPIRED` |
| **Tenant** | Cross-Tenant Resource Access | **DENY** | **NEVER** | **NEVER** | 403 Forbidden | `FORBIDDEN` / `TENANT_NOT_FOUND`|
| **Tenant** | Disabled Tenant | **DENY** | **NEVER** | **NEVER** | 403 Forbidden | `TENANT_DISABLED` |
| **Policy** | Policy Action DENY | **BLOCK** | **NEVER** | **NEVER** | 200 OK | `policy_denied` |
| **Policy** | Policy Store DB Failure | **FAIL CLOSED** | **NEVER** | **NEVER** | 500 Server Err | Generic safe error |
| **Audit** | Audit Write Failure | **FAIL CLOSED** | **NEVER** | **NEVER** | 500 Server Err | Rejects mutating action |
| **Audit** | Audit Tampering Detected | **TAMPERED** | N/A | N/A | 200 OK | `valid=False`, `status=tampered` |
| **HTTP** | Request Body > 1 MB | **REJECT** | **NEVER** | **NEVER** | 413 Payload Large | Bounded streaming stop |
| **HTTP** | Non-JSON Media Type | **REJECT** | **NEVER** | **NEVER** | 415 Unsupported | `VALIDATION_ERROR` |
| **Config** | Production Missing Secrets | **HALT** | **NEVER** | **NEVER** | Startup Crash | `ConfigurationError` |

---

## 6. Operational Assumptions & Boundaries

1. **Process Model:** In v1.0 local deployments, rate limiting and tenant concurrency are in-process memory structures. Operators MUST deploy a single process (`AGENTGUARD_PROCESS_MODEL=single_process`). Multi-worker deployments in production without distributed coordination fail closed at startup.
2. **Reverse Proxy Dependency:** AgentGuard must run behind a perimeter reverse proxy (e.g., Envoy, NGINX, or Cloudflare) for TLS termination, connection timeouts, and transport-level protection.
3. **Storage Model:** SQLite WAL provides ACID storage for local deployment. Database backups should use SQLite Online Backup API (`VACUUM INTO`).
