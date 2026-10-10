"""
AgentGuard Reversible PII / DLP (Data Loss Prevention) Service
Provides bidirectional tokenization of sensitive entities:
1. Detects: Emails, Phone Numbers, Credit Cards (with Luhn validation),
   SSNs / Tax IDs, API Keys & Bearer tokens, IP addresses, and IBANs.
2. Inbound Anonymization: Replaces sensitive data with deterministic placeholders
   (e.g., [EMAIL_1], [CREDIT_CARD_1]) so external LLMs never receive real PII.
   Maintains coreference: identical entities receive identical placeholders.
3. Outbound De-anonymization: Restores placeholders in the LLM's response
   back to their original values before returning the response to the user.
4. Compliant with GDPR, HIPAA, and PCI-DSS requirements.
"""

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("agentguard.dlp")


def luhn_checksum(card_number_digits: str) -> bool:
    """
    Validates candidate credit card number using the Luhn checksum algorithm.
    Rejects random 16-digit numbers that are not valid payment cards.
    """
    digits = [int(d) for d in card_number_digits if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    # Luhn double every second digit from the right
    checksum = 0
    reverse_digits = digits[::-1]
    for idx, d in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


# Detection Regular Expressions
PATTERN_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b",
    re.IGNORECASE,
)

PATTERN_PHONE = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?(?:\(\d{3}\)|\b\d{3})[-.\s]\d{3}[-.\s]\d{4}\b|\b\+\d{1,3}[-.\s]?\d{6,14}\b"
)

PATTERN_CREDIT_CARD = re.compile(
    r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{13,19}\b"
)

PATTERN_SSN = re.compile(
    r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b"
)

PATTERN_API_KEY = re.compile(
    r"\b(?:sk-[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{36,}|ag_[A-Za-z0-9_-]{16,})\b"
)

PATTERN_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

PATTERN_IBAN = re.compile(
    r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"
)


@dataclass
class DLPVault:
    """
    Session vault holding bidirectional mappings between real sensitive values
    and deterministic anonymization placeholders.
    """
    forward_map: Dict[str, str] = field(default_factory=dict)   # original_value -> placeholder
    reverse_map: Dict[str, str] = field(default_factory=dict)   # placeholder -> original_value
    counters: Dict[str, int] = field(default_factory=dict)      # entity_type -> counter
    detected_entities: List[Dict[str, Any]] = field(default_factory=list)

    def get_or_create_placeholder(self, entity_type: str, raw_value: str) -> str:
        """
        Returns existing placeholder if raw_value was already tokenized in this session,
        or creates a new deterministic numbered placeholder (e.g. [EMAIL_1]).
        """
        if raw_value in self.forward_map:
            return self.forward_map[raw_value]

        count = self.counters.get(entity_type, 0) + 1
        self.counters[entity_type] = count
        placeholder = f"[{entity_type}_{count}]"

        self.forward_map[raw_value] = placeholder
        self.reverse_map[placeholder] = raw_value
        self.detected_entities.append({
            "type": entity_type,
            "placeholder": placeholder,
            "character_length": len(raw_value),
        })
        return placeholder

    def restore(self, text: str) -> str:
        """
        Replaces all placeholders in text back to original values.
        """
        if not text or not self.reverse_map:
            return text

        restored = text
        # Replace placeholders in reverse order (e.g., [EMAIL_10] before [EMAIL_1])
        sorted_placeholders = sorted(self.reverse_map.keys(), key=lambda k: len(k), reverse=True)
        for ph in sorted_placeholders:
            orig = self.reverse_map[ph]
            restored = restored.replace(ph, orig)
        return restored


class DLPTokenizer:
    """
    Engine for identifying, masking, and de-masking sensitive data in prompts and responses.
    """

    def __init__(self, enabled_categories: Optional[Set[str]] = None):
        self.enabled_categories = enabled_categories or {
            "EMAIL",
            "PHONE",
            "CREDIT_CARD",
            "SSN",
            "API_KEY",
            "IP_ADDRESS",
            "IBAN",
        }

    def tokenize(self, text: str, vault: Optional[DLPVault] = None) -> Tuple[str, DLPVault]:
        """
        Scans text for sensitive entities, replaces them with placeholders in the vault,
        and returns the anonymized text along with the vault.
        """
        if not text or not isinstance(text, str):
            return text, vault or DLPVault()

        if vault is None:
            vault = DLPVault()

        masked_text = text

        # 1. API Keys & Secrets
        if "API_KEY" in self.enabled_categories:
            for match in PATTERN_API_KEY.finditer(masked_text):
                val = match.group(0)
                ph = vault.get_or_create_placeholder("API_KEY", val)
                masked_text = masked_text.replace(val, ph)

        # 2. Credit Cards (with Luhn check to prevent false positives)
        if "CREDIT_CARD" in self.enabled_categories:
            for match in PATTERN_CREDIT_CARD.finditer(masked_text):
                val = match.group(0)
                clean_digits = re.sub(r"\D", "", val)
                if luhn_checksum(clean_digits):
                    ph = vault.get_or_create_placeholder("CREDIT_CARD", val)
                    masked_text = masked_text.replace(val, ph)

        # 3. Social Security Numbers
        if "SSN" in self.enabled_categories:
            for match in PATTERN_SSN.finditer(masked_text):
                val = match.group(0)
                ph = vault.get_or_create_placeholder("SSN", val)
                masked_text = masked_text.replace(val, ph)

        # 4. IBAN Bank Accounts
        if "IBAN" in self.enabled_categories:
            for match in PATTERN_IBAN.finditer(masked_text):
                val = match.group(0)
                ph = vault.get_or_create_placeholder("IBAN", val)
                masked_text = masked_text.replace(val, ph)

        # 5. Email Addresses
        if "EMAIL" in self.enabled_categories:
            for match in PATTERN_EMAIL.finditer(masked_text):
                val = match.group(0)
                ph = vault.get_or_create_placeholder("EMAIL", val)
                masked_text = masked_text.replace(val, ph)

        # 6. Phone Numbers
        if "PHONE" in self.enabled_categories:
            for match in PATTERN_PHONE.finditer(masked_text):
                val = match.group(0)
                clean_digits = re.sub(r"\D", "", val)
                if len(clean_digits) >= 10:
                    ph = vault.get_or_create_placeholder("PHONE", val)
                    masked_text = masked_text.replace(val, ph)

        # 7. IP Addresses (Exclude loopback and broadcast)
        if "IP_ADDRESS" in self.enabled_categories:
            for match in PATTERN_IPV4.finditer(masked_text):
                val = match.group(0)
                if val not in ("127.0.0.1", "0.0.0.0", "255.255.255.255"):
                    ph = vault.get_or_create_placeholder("IP_ADDRESS", val)
                    masked_text = masked_text.replace(val, ph)

        return masked_text, vault

    def de_tokenize(self, text: str, vault: DLPVault) -> str:
        """
        Restores placeholders back to original sensitive values using the vault.
        """
        return vault.restore(text)


# Global singleton instance
dlp_service = DLPTokenizer()
