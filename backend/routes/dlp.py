"""
DLP API Route
Provides dedicated endpoints for PII and sensitive data tokenization and reversible de-anonymization.
"""

from fastapi import APIRouter, Request, status
from backend.schemas import (
    DLPTokenizeRequest,
    DLPTokenizeResponse,
    DLPRestoreRequest,
    DLPRestoreResponse,
)
from backend.services.dlp_service import dlp_service, DLPVault, DLPTokenizer
from backend.services.audit_service import audit_service
from backend.services.identity_service import resolve_principal

router = APIRouter(tags=["Data Loss Prevention (DLP)"])


@router.post(
    "/api/v1/dlp/mask",
    response_model=DLPTokenizeResponse,
    status_code=status.HTTP_200_OK,
    summary="Anonymize sensitive PII entities in text",
    description=(
        "Scans text for sensitive PII entities (Emails, Phone numbers, Credit cards with Luhn check, "
        "SSNs, API keys, IP addresses, IBANs), deterministically replaces them with placeholders "
        "(e.g., [EMAIL_1]), and returns the reversible token vault."
    ),
)
def mask_endpoint(payload: DLPTokenizeRequest, request: Request) -> DLPTokenizeResponse:
    """
    HTTP route handler for PII tokenization.
    """
    request_id = getattr(request.state, "request_id", None)
    principal = resolve_principal(request=request)

    tokenizer = dlp_service
    if payload.categories:
        tokenizer = DLPTokenizer(enabled_categories=set(payload.categories))

    masked_text, vault = tokenizer.tokenize(payload.text)

    # Log audit event without recording sensitive values or tokens
    audit_service.log_event(
        action="dlp_mask",
        request_id=request_id,
        principal=principal,
        resource_type="dlp",
        decision="ALLOW",
        risk_score=0.0,
        attack_type="none",
    )

    return DLPTokenizeResponse(
        masked_text=masked_text,
        entities_detected=vault.detected_entities,
        vault=vault.reverse_map,
        total_entities=len(vault.detected_entities),
    )


@router.post(
    "/api/v1/dlp/restore",
    response_model=DLPRestoreResponse,
    status_code=status.HTTP_200_OK,
    summary="Restore anonymized placeholders to original values",
    description="Reverses [TYPE_N] placeholders back to original values using the provided vault.",
)
def restore_endpoint(payload: DLPRestoreRequest, request: Request) -> DLPRestoreResponse:
    """
    HTTP route handler for PII de-anonymization.
    """
    vault = DLPVault(reverse_map=payload.vault)
    restored = vault.restore(payload.masked_text)
    return DLPRestoreResponse(restored_text=restored)
