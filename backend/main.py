"""
AgentGuard Backend v0.9 - Main Application Entry Point
FastAPI application providing a reliable, resource-bounded, and observable HTTP API gateway
around the AgentGuard v5 security engine.
Includes secure deployment profiles, configuration validation, secret redaction,
in-process rate limiting, inference concurrency controls, timeout hardening,
request correlation tracking, structured error handling, and in-memory telemetry.
"""

import logging
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict

import requests
from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.config import (
    AGENTGUARD_ENV,
    ALLOWED_ORIGINS,
    GUARD_MODEL,
    IS_PRODUCTION,
    MAX_REQUEST_BODY_SIZE,
    OLLAMA_BASE_URL,
    PROCESS_MODEL,
    TARGET_MODEL,
    TRUSTED_PROXIES,
    VERSION,
)
from backend.routes.chat import router as chat_router
from backend.routes.execute import router as execute_router
from backend.routes.guard import router as guard_router
from backend.routes.tool import router as tool_router
from backend.routes.approvals import router as approvals_router
from backend.routes.policies import router as policies_router
from backend.routes.audit import router as audit_router
from backend.routes.credentials import router as credentials_router
from backend.routes.principals import router as principals_router
from backend.routes.tenants import router as tenants_router
from backend.routes.openai_proxy import router as openai_router
from backend.schemas import HealthResponse, ReadyResponse
from backend.services.audit_service import AuditFailureError, audit_service
from backend.services.authentication_service import authenticate_request
from backend.services.authorization_service import ForbiddenError
from backend.services.concurrency_service import ConcurrencyLimitExceeded
from backend.services.config_validator import (
    ConfigurationError,
    validate_at_startup,
    validate_configuration,
    validate_ip_or_network,
)
from backend.services.credential_service import CredentialError, credential_service
from backend.services.db_hardening import (
    DatabaseCorruptionError,
    DatabasePathError,
    DatabaseSecurityError,
)
from backend.services.identity_service import (
    AuthenticationRequiredError,
    IdentityError,
    InvalidPrincipalError,
    PrincipalDisabledError,
    resolve_principal,
)
from backend.services.logging_service import configure_security_logging
from backend.services.metrics_service import metrics
from backend.services.policy_service import (
    PolicyConflictError,
    PolicyError,
    PolicyInvalidError,
    PolicyNotFoundError,
    policy_service,
)
from backend.services.principal_service import PrincipalError, principal_service
from backend.services.tenant_service import TenantError, tenant_service
from backend.services.rate_limiter import rate_limiter
from backend.services.proxy_service import proxy_resolver, configure_trusted_proxies

# Configure safe structured logger (no secrets, no full prompts)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("agentguard.api")


def resolve_client_ip(request: Request) -> str:
    """
    Resolves client IP address using robust trusted-proxy semantics.
    Supports IPv4/IPv6 CIDR ranges and right-to-left proxy chain traversal.
    """
    direct_ip = request.client.host if (request.client and request.client.host) else "127.0.0.1"
    forwarded = request.headers.get("x-forwarded-for")
    return proxy_resolver.resolve_client_ip(direct_ip, forwarded)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager for graceful startup and shutdown.
    Validates configuration, initializes proxy resolver, and applies security logging filters.
    """
    validate_at_startup()
    configure_trusted_proxies(TRUSTED_PROXIES)
    configure_security_logging()
    logger.info("AgentGuard Backend v%s initialized and ready to serve (env=%s, process_model=%s).", VERSION, AGENTGUARD_ENV, PROCESS_MODEL)
    yield
    logger.info("AgentGuard Backend v%s shutting down gracefully.", VERSION)


app = FastAPI(
    title="AgentGuard API",
    version=VERSION,
    description=(
        "AgentGuard Backend v0.9 — Operationally hardened HTTP API gateway and execution perimeter "
        "around the AgentGuard v5 AI security engine. Features secure deployment profiles, "
        "cryptographic integrity, SQLite hardening, category rate limiting, and observability hardening."
    ),
    docs_url="/docs",
    redoc_url=None,
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# CORS middleware
# Wildcard origins are rejected in production mode by startup configuration validator
allow_credentials_setting = True
if "*" in ALLOWED_ORIGINS:
    allow_credentials_setting = False

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=allow_credentials_setting,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def operational_middleware(request: Request, call_next):
    """
    Operational middleware:
    1. Extracts or generates correlation request_id.
    2. Enforces request body size limits.
    3. Validates Content-Type for mutating requests.
    4. Resolves trusted client IP.
    5. Applies global, category, and tenant rate limiting.
    6. Authenticates request and establishes server-bound security context.
    7. Attaches standard security headers and correlation ID to response.
    """
    client_request_id = request.headers.get("x-request-id")
    if client_request_id and client_request_id.strip():
        request_id = client_request_id.strip()
    else:
        request_id = str(uuid.uuid4())
    request.state.request_id = request_id

    # 1. Request body boundary protection (v1.0 Actual Received Byte Enforcer)
    content_length_header = request.headers.get("content-length")
    if content_length_header is not None:
        try:
            content_length = int(content_length_header)
            if content_length < 0:
                metrics.record_request(request.url.path, status.HTTP_400_BAD_REQUEST)
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={
                        "request_id": request_id,
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": "Negative Content-Length header is invalid.",
                        },
                    },
                    headers={"X-Request-ID": request_id},
                )
            if content_length > MAX_REQUEST_BODY_SIZE:
                metrics.record_request(request.url.path, status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={
                        "request_id": request_id,
                        "error": {
                            "code": "PAYLOAD_TOO_LARGE",
                            "message": f"Request body exceeds maximum allowed size of {MAX_REQUEST_BODY_SIZE} bytes.",
                        },
                    },
                    headers={"X-Request-ID": request_id},
                )
        except ValueError:
            metrics.record_request(request.url.path, status.HTTP_400_BAD_REQUEST)
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "request_id": request_id,
                    "error": {
                        "code": "VALIDATION_ERROR",
                        "message": "Invalid Content-Length header.",
                    },
                },
                headers={"X-Request-ID": request_id},
            )

    # 2. Actual Streaming Body Verification (chunked, missing Content-Length, streaming)
    # Bounded memory reading up to MAX_REQUEST_BODY_SIZE + 1
    transfer_encoding = request.headers.get("transfer-encoding", "").lower()
    has_body_indication = (
        request.method in ("POST", "PUT", "PATCH")
        or content_length_header is not None
        or "chunked" in transfer_encoding
    )
    if has_body_indication:
        body_chunks = []
        received_bytes = 0
        body_exceeded = False
        try:
            async for chunk in request.stream():
                received_bytes += len(chunk)
                if received_bytes > MAX_REQUEST_BODY_SIZE:
                    body_exceeded = True
                    break
                body_chunks.append(chunk)
        except Exception as stream_err:
            logger.warning("Stream read error: %s", stream_err)
            metrics.record_request(request.url.path, status.HTTP_400_BAD_REQUEST)
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "request_id": request_id,
                    "error": {
                        "code": "VALIDATION_ERROR",
                        "message": "Malformed transfer stream.",
                    },
                },
                headers={"X-Request-ID": request_id},
            )

        if body_exceeded:
            metrics.record_request(request.url.path, status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={
                    "request_id": request_id,
                    "error": {
                        "code": "PAYLOAD_TOO_LARGE",
                        "message": f"Request body exceeds maximum allowed size of {MAX_REQUEST_BODY_SIZE} bytes.",
                    },
                },
                headers={"X-Request-ID": request_id},
            )

        cached_body = b"".join(body_chunks)
        request._body = cached_body
    else:
        cached_body = b""
        request._body = cached_body

    # 3. Content-Type validation on mutating API requests
    if request.method in ("POST", "PUT", "PATCH") and (request.url.path.startswith("/api/") or request.url.path.startswith("/v1/")):
        if len(cached_body) > 0:
            content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
            if content_type != "application/json":
                metrics.record_request(request.url.path, status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)
                return JSONResponse(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    content={
                        "request_id": request_id,
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": "Unsupported Content-Type. Expected application/json.",
                        },
                    },
                    headers={"X-Request-ID": request_id},
                )

    # 4. Client IP identification through hardened trusted proxy resolver
    client_ip = resolve_client_ip(request)

    # 5. Global Rate limiting check
    is_allowed, retry_after = rate_limiter.check_rate_limit(client_ip)
    if not is_allowed:
        metrics.record_rate_limited()
        metrics.record_request(request.url.path, status.HTTP_429_TOO_MANY_REQUESTS)
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "request_id": request_id,
                "error": {
                    "code": "RATE_LIMITED",
                    "message": f"Request rate limit exceeded. Please retry in {retry_after} seconds.",
                },
            },
            headers={
                "Retry-After": str(retry_after or 60),
                "X-Request-ID": request_id,
            },
        )

    # 6. Resolve security context & authenticated principal
    open_paths = ("/health", "/ready", "/metrics", "/docs", "/openapi.json", "/v1/models")
    is_open_path = any(request.url.path == p or request.url.path.startswith(p + "/") for p in open_paths)
    try:
        ctx = authenticate_request(request=request, require_auth=False if is_open_path else None)
        request.state.context = ctx
        request.state.principal = ctx

        # 7. Endpoint category-specific rate limits using verified identity
        cat = None
        if "/api/v1/approvals" in request.url.path:
            cat = "approvals"
        elif "/api/v1/credentials" in request.url.path:
            cat = "credentials"
        elif "/api/v1/policies" in request.url.path:
            cat = "policies"
        elif "/api/v1/audit" in request.url.path:
            cat = "audit"

        if cat:
            principal_id = ctx.principal_id if ctx else None
            tenant_id = ctx.tenant_id if ctx else None
            is_cat_allowed, cat_retry = rate_limiter.check_category_rate_limit(
                category=cat,
                client_ip=client_ip,
                principal_id=principal_id,
                tenant_id=tenant_id,
            )
            if not is_cat_allowed:
                metrics.record_rate_limited()
                metrics.record_request(request.url.path, status.HTTP_429_TOO_MANY_REQUESTS)
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "request_id": request_id,
                        "error": {
                            "code": "RATE_LIMITED",
                            "message": f"Rate limit exceeded for {cat}. Please retry in {cat_retry} seconds.",
                        },
                    },
                    headers={
                        "Retry-After": str(cat_retry or 60),
                        "X-Request-ID": request_id,
                    },
                )

        # 8. Check tenant rate limit if context tenant resolved
        if ctx and hasattr(ctx, "tenant_id") and ctx.tenant_id:
            t_allowed, t_retry = rate_limiter.check_tenant_rate_limit(ctx.tenant_id)
            if not t_allowed:
                metrics.record_rate_limited()
                metrics.record_request(request.url.path, status.HTTP_429_TOO_MANY_REQUESTS)
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "request_id": request_id,
                        "error": {
                            "code": "RATE_LIMITED",
                            "message": f"Tenant request quota exceeded. Please retry in {t_retry} seconds.",
                        },
                    },
                    headers={
                        "Retry-After": str(t_retry or 60),
                        "X-Request-ID": request_id,
                    },
                )

    except (IdentityError, CredentialError, TenantError, PrincipalError) as auth_exc:
        # Rate limit authentication failure attempts per client IP and fail closed with 429 if quota exceeded
        is_auth_ok, retry_after = rate_limiter.record_auth_failure(client_ip)
        if not is_auth_ok:
            metrics.record_rate_limited()
            metrics.record_request(request.url.path, status.HTTP_429_TOO_MANY_REQUESTS)
            resp = JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "request_id": request_id,
                    "error": {
                        "code": "RATE_LIMITED",
                        "message": f"Too many authentication failures. Please retry in {retry_after} seconds.",
                    },
                },
                headers={
                    "Retry-After": str(retry_after or 60),
                    "X-Request-ID": request_id,
                },
            )
            _attach_security_headers(resp, request)
            return resp

        status_code = getattr(auth_exc, "status_code", 401)
        code = getattr(auth_exc, "code", "AUTHENTICATION_FAILED")
        message = getattr(auth_exc, "message", str(auth_exc))
        metrics.record_request(request.url.path, status_code)
        resp = JSONResponse(
            status_code=status_code,
            content={
                "request_id": request_id,
                "error_code": code,
                "error": {
                    "code": code,
                    "message": message,
                },
            },
            headers={"X-Request-ID": request_id},
        )
        _attach_security_headers(resp, request)
        return resp

    # Process request and attach standard security headers
    try:
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        _attach_security_headers(response, request)
        metrics.record_request(request.url.path, response.status_code)
        return response
    except Exception as exc:
        metrics.record_request(request.url.path, status.HTTP_500_INTERNAL_SERVER_ERROR)
        return await unhandled_exception_handler(request, exc)


def _attach_security_headers(response, request: Request):
    """Applies standard HTTP security hardening headers to all API responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    if IS_PRODUCTION or request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"


@app.exception_handler(ConfigurationError)
async def configuration_exception_handler(request: Request, exc: ConfigurationError):
    """Handles configuration failure errors without leaking secrets."""
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    logger.critical("Configuration error: request_id=%s code=%s message=%s", request_id, exc.code, exc.message)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "request_id": request_id,
            "error_code": exc.code,
            "error": {
                "code": exc.code,
                "message": exc.message,
            },
        },
        headers={"X-Request-ID": request_id},
    )


@app.exception_handler(DatabaseSecurityError)
async def database_security_exception_handler(request: Request, exc: DatabaseSecurityError):
    """Handles hardened SQLite database errors without leaking internal paths or SQL."""
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    logger.error("Database security rejection: request_id=%s code=%s message=%s", request_id, exc.code, exc.message)
    return JSONResponse(
        status_code=500,
        content={
            "request_id": request_id,
            "error_code": exc.code,
            "error": {
                "code": exc.code,
                "message": exc.message,
            },
        },
        headers={"X-Request-ID": request_id},
    )


@app.exception_handler(CredentialError)
async def credential_exception_handler(request: Request, exc: CredentialError):
    """Handles API credential validation and lifecycle errors."""
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    logger.warning("Credential rejection: request_id=%s code=%s message=%s", request_id, exc.code, exc.message)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "request_id": request_id,
            "error_code": exc.code,
            "error": {
                "code": exc.code,
                "message": exc.message,
            },
        },
        headers={"X-Request-ID": request_id},
    )


@app.exception_handler(TenantError)
async def tenant_exception_handler(request: Request, exc: TenantError):
    """Handles tenant resolution and multi-tenant isolation errors."""
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    logger.warning("Tenant rejection: request_id=%s code=%s message=%s", request_id, exc.code, exc.message)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "request_id": request_id,
            "error_code": exc.code,
            "error": {
                "code": exc.code,
                "message": exc.message,
            },
        },
        headers={"X-Request-ID": request_id},
    )


@app.exception_handler(PrincipalError)
async def principal_exception_handler(request: Request, exc: PrincipalError):
    """Handles principal administration and privilege errors."""
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    logger.warning("Principal rejection: request_id=%s code=%s message=%s", request_id, exc.code, exc.message)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "request_id": request_id,
            "error_code": exc.code,
            "error": {
                "code": exc.code,
                "message": exc.message,
            },
        },
        headers={"X-Request-ID": request_id},
    )


@app.exception_handler(IdentityError)
async def identity_exception_handler(request: Request, exc: IdentityError):
    """Handles authentication and principal validation errors."""
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    logger.warning("Identity rejection: request_id=%s code=%s message=%s", request_id, exc.code, exc.message)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "request_id": request_id,
            "error_code": exc.code,
            "error": {
                "code": exc.code,
                "message": exc.message,
            },
        },
        headers={"X-Request-ID": request_id},
    )


@app.exception_handler(ForbiddenError)
async def forbidden_exception_handler(request: Request, exc: ForbiddenError):
    """Handles deterministic RBAC authorization rejections."""
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    logger.warning("Authorization forbidden: request_id=%s code=%s message=%s", request_id, exc.code, exc.message)
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={
            "request_id": request_id,
            "error": {
                "code": exc.code,
                "message": exc.message,
            },
        },
        headers={"X-Request-ID": request_id},
    )


@app.exception_handler(PolicyError)
async def policy_exception_handler(request: Request, exc: PolicyError):
    """Handles security policy errors."""
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    logger.warning("Policy exception: request_id=%s code=%s message=%s", request_id, exc.code, exc.message)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "request_id": request_id,
            "error": {
                "code": exc.code,
                "message": exc.message,
            },
        },
        headers={"X-Request-ID": request_id},
    )


@app.exception_handler(AuditFailureError)
async def audit_failure_exception_handler(request: Request, exc: AuditFailureError):
    """Handles audit persistence failures in fail-closed mode without exposing database details."""
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    logger.error("Audit failure (failing closed): request_id=%s error=%s", request_id, exc.message)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "request_id": request_id,
            "error": {
                "code": "AUDIT_FAILURE",
                "message": "Security audit failure encountered. Request rejected for audit integrity.",
            },
        },
        headers={"X-Request-ID": request_id},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handles Pydantic input validation errors with structured, safe error format."""
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    logger.warning("Request validation failed: request_id=%s errors=%d", request_id, len(exc.errors()))
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "request_id": request_id,
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Invalid request payload or parameters.",
            },
            "detail": jsonable_encoder(exc.errors()),
        },
        headers={"X-Request-ID": request_id},
    )


@app.exception_handler(ConcurrencyLimitExceeded)
async def concurrency_exception_handler(request: Request, exc: ConcurrencyLimitExceeded):
    """Handles inference concurrency exhaustion, safely rejecting requests without calling Ollama."""
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    logger.warning("Concurrency limit reached: request_id=%s resource=%s", request_id, exc.resource)
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "request_id": request_id,
            "error": {
                "code": "CONCURRENCY_LIMIT",
                "message": f"Service is busy. Maximum concurrent inferences reached for {exc.resource}. Please try again later.",
            },
        },
        headers={"X-Request-ID": request_id},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """
    Global safe exception handler:
    Ensures internal stack traces, system paths, and secrets are NEVER exposed to API clients.
    """
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    logger.error("Unhandled API exception occurred: request_id=%s error_type=%s", request_id, type(exc).__name__)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "request_id": request_id,
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An internal server error occurred. Please contact the administrator.",
            },
            "detail": "An internal server error occurred. Please contact the administrator.",
        },
        headers={"X-Request-ID": request_id},
    )


@app.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    tags=["System"],
    summary="Application Process Health",
    description="Returns application process health and model metadata. Does not depend on Ollama connectivity.",
)
def health_check() -> HealthResponse:
    """
    Basic process liveness check. Always returns 200 OK while the backend process is running.
    """
    return HealthResponse(
        status="ok",
        version=VERSION,
        guard_model=GUARD_MODEL,
        target_model=TARGET_MODEL,
    )


@app.get(
    "/ready",
    response_model=ReadyResponse,
    status_code=status.HTTP_200_OK,
    tags=["System"],
    summary="Inference Readiness Check",
    description="Checks whether backend dependencies, configuration, and security stores are reachable and ready to serve requests.",
    responses={
        200: {
            "description": "Dependencies reachable; service ready for inference.",
            "model": ReadyResponse,
        },
        503: {
            "description": "Dependencies unreachable or down.",
        },
    },
)
def readiness_check(request: Request):
    """
    Comprehensive dependency & security readiness check.
    Verifies that configuration, identity, credentials, policies, tenants, principals,
    audit integrity, and configured Ollama instance are healthy.
    Never exposes internal filesystem paths or secret values.
    """
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))

    # 1. Configuration check
    cfg_result = validate_configuration()
    if not cfg_result.valid and IS_PRODUCTION:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "request_id": request_id,
                "status": "not_ready",
                "error": {
                    "code": "CONFIGURATION_ERROR",
                    "message": "Configuration validation failed.",
                },
            },
            headers={"X-Request-ID": request_id},
        )

    # 2. Credential store check
    if not credential_service.is_healthy():
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "request_id": request_id,
                "status": "not_ready",
                "error": {
                    "code": "DEPENDENCY_UNAVAILABLE",
                    "message": "Credential store is not accessible or failed integrity check.",
                },
            },
            headers={"X-Request-ID": request_id},
        )

    # 3. Policy store check
    if not policy_service.is_healthy():
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "request_id": request_id,
                "status": "not_ready",
                "error": {
                    "code": "DEPENDENCY_UNAVAILABLE",
                    "message": "Policy store is not accessible.",
                },
            },
            headers={"X-Request-ID": request_id},
        )

    # 4. Audit store check
    if not audit_service.is_healthy():
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "request_id": request_id,
                "status": "not_ready",
                "error": {
                    "code": "DEPENDENCY_UNAVAILABLE",
                    "message": "Audit store is not accessible or failed integrity check.",
                },
            },
            headers={"X-Request-ID": request_id},
        )

    # 5. Tenant store check
    if not tenant_service.is_healthy():
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "request_id": request_id,
                "status": "not_ready",
                "error": {
                    "code": "DEPENDENCY_UNAVAILABLE",
                    "message": "Tenant store is not accessible or failed integrity check.",
                },
            },
            headers={"X-Request-ID": request_id},
        )

    # 6. Principal store check
    if not principal_service.is_healthy():
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "request_id": request_id,
                "status": "not_ready",
                "error": {
                    "code": "DEPENDENCY_UNAVAILABLE",
                    "message": "Principal store is not accessible or failed integrity check.",
                },
            },
            headers={"X-Request-ID": request_id},
        )

    # 7. Audit integrity key check (required in production)
    if IS_PRODUCTION and not audit_service.get_integrity_key():
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "request_id": request_id,
                "status": "not_ready",
                "error": {
                    "code": "CONFIGURATION_ERROR",
                    "message": "Audit integrity key is required in production.",
                },
            },
            headers={"X-Request-ID": request_id},
        )

    # 8. Ollama service check
    try:
        resp = requests.get(f"{OLLAMA_BASE_URL}/api/version", timeout=2.0)
        if resp.status_code == 200:
            return ReadyResponse(
                status="ready",
                version=VERSION,
                environment=AGENTGUARD_ENV,
                ollama="connected",
                guard_model=GUARD_MODEL,
                target_model=TARGET_MODEL,
                identity="ready",
                credential_store="ready",
                policy_store="ready",
                audit_store="ready",
                configuration="ready",
                checks={
                    "configuration": "ok",
                    "process_model": PROCESS_MODEL,
                    "credential_store": "ok",
                    "policy_store": "ok",
                    "audit_store": "ok",
                    "tenant_store": "ok",
                    "principal_store": "ok",
                    "ollama": "connected",
                },
            )
        else:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={
                    "request_id": request_id,
                    "status": "not_ready",
                    "error": {
                        "code": "DEPENDENCY_UNAVAILABLE",
                        "message": f"Ollama service returned status {resp.status_code}.",
                    },
                },
                headers={"X-Request-ID": request_id},
            )
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "request_id": request_id,
                "status": "not_ready",
                "error": {
                    "code": "DEPENDENCY_UNAVAILABLE",
                    "message": "Ollama service is not reachable.",
                },
            },
            headers={"X-Request-ID": request_id},
        )


@app.get(
    "/metrics",
    tags=["System"],
    summary="Operational In-Memory Metrics",
    description="Returns in-process operational counters including total requests, status codes, decisions, timeouts, and rate limits.",
)
def metrics_endpoint() -> Dict[str, Any]:
    """
    Returns lightweight in-process metrics. Memory-only, resets on restart.
    """
    return metrics.get_metrics()


# Register security endpoints
app.include_router(guard_router)
app.include_router(execute_router)
app.include_router(chat_router)
app.include_router(tool_router)
app.include_router(approvals_router)
app.include_router(policies_router)
app.include_router(audit_router)
app.include_router(credentials_router)
app.include_router(principals_router)
app.include_router(tenants_router)
app.include_router(openai_router)
