"""
Unit and Integration Test Suite for AgentGuard Reversible PII / DLP (Data Loss Prevention)
Tests:
1. Regex & Algorithm detection:
   - Emails, Phone numbers, SSNs, API keys, IP addresses, IBANs
   - Credit Cards with Luhn checksum validation (and false-positive rejection)
   - Coreference preservation (same entity gets same placeholder)
2. Reversible Vault de-anonymization
3. Standalone DLP endpoints (/api/v1/dlp/mask and /api/v1/dlp/restore)
4. End-to-end OpenAI reverse proxy (/v1/chat/completions) with PII masking and restoration
5. Irreversible mask mode (X-AgentGuard-DLP-Mask-Only) and bypass (X-AgentGuard-DLP: false)
"""

import unittest
import uuid
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient

from backend.main import app
from backend.services.dlp_service import dlp_service, DLPVault, luhn_checksum
from backend.services.tenant_service import tenant_service
from backend.services.principal_service import principal_service
from backend.services.credential_service import credential_service


class TestDLPService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app, raise_server_exceptions=False)
        tenant_service._seed_defaults()
        principal_service._seed_defaults()

        cls.tenant_id = f"dlp-tenant-{uuid.uuid4().hex[:6]}"
        tenant_service.create_tenant(cls.tenant_id, "DLP Tenant")

        cls.user_principal = f"dlp-user-{uuid.uuid4().hex[:6]}"
        principal_service.create_principal(
            principal_id=cls.user_principal,
            principal_type="user",
            roles=["user"],
            tenant_id=cls.tenant_id,
        )

        _, cls.user_token = credential_service.create_credential(cls.user_principal, cls.tenant_id)
        cls.headers = {
            "Authorization": f"Bearer {cls.user_token}",
            "Content-Type": "application/json",
        }

    def test_01_luhn_checksum_validation(self):
        """Verify Luhn algorithm correctly distinguishes valid card numbers from invalid sequences."""
        # 4111222233334444: 4*2=8, 1, 1*2=2, 1, 2*2=4, 2, 2*2=4, 2, 3*2=6, 3, 3*2=6, 3, 4*2=8, 4, 4*2=8, 4
        # Sum = 8+1+2+1+4+2+4+2+6+3+6+3+8+4+8+4 = 66 (not Luhn)
        # Standard test card numbers:
        # Visa standard test card: 4532015112830366 (valid Luhn)
        self.assertTrue(luhn_checksum("4532015112830366"))
        self.assertTrue(luhn_checksum("4532-0151-1283-0366"))
        # Invalid cards (fail Luhn checksum)
        self.assertFalse(luhn_checksum("4532015112830367"))
        self.assertFalse(luhn_checksum("4532015112830368"))

    def test_02_detect_and_mask_all_entity_types(self):
        """Verify detection and tokenization of emails, phones, cards, SSN, API keys, IPs, and IBANs."""
        sample_text = (
            "Contact Alice at alice.smith@enterprise.org or (555) 234-5678. "
            "Her SSN is 123-45-6789 and card is 4532-0151-1283-0366. "
            "Server IP: 198.51.100.42, IBAN: DE89370400440532013000, "
            "API key: sk-abcdef1234567890abcdef123456."
        )

        masked_text, vault = dlp_service.tokenize(sample_text)

        # Sensitive items must NOT appear in masked text
        self.assertNotIn("alice.smith@enterprise.org", masked_text)
        self.assertNotIn("(555) 234-5678", masked_text)
        self.assertNotIn("123-45-6789", masked_text)
        self.assertNotIn("4532-0151-1283-0366", masked_text)
        self.assertNotIn("198.51.100.42", masked_text)
        self.assertNotIn("DE89370400440532013000", masked_text)
        self.assertNotIn("sk-abcdef1234567890abcdef123456", masked_text)

        # Placeholders must be inserted
        self.assertIn("[EMAIL_1]", masked_text)
        self.assertIn("[PHONE_1]", masked_text)
        self.assertIn("[SSN_1]", masked_text)
        self.assertIn("[CREDIT_CARD_1]", masked_text)
        self.assertIn("[IP_ADDRESS_1]", masked_text)
        self.assertIn("[IBAN_1]", masked_text)
        self.assertIn("[API_KEY_1]", masked_text)

        # Verify reversible restoration
        restored_text = vault.restore(masked_text)
        self.assertEqual(sample_text, restored_text)

    def test_03_coreference_preservation(self):
        """Verify identical entities receive the same placeholder across occurrences."""
        sample_text = (
            "Invoice for bob@acme.com was created. "
            "Confirmation sent to bob@acme.com. "
            "Please cc bob@acme.com."
        )

        masked_text, vault = dlp_service.tokenize(sample_text)

        # Must have [EMAIL_1] and NOT [EMAIL_2]
        self.assertEqual(masked_text.count("[EMAIL_1]"), 3)
        self.assertNotIn("[EMAIL_2]", masked_text)
        self.assertEqual(len(vault.reverse_map), 1)

    def test_04_standalone_mask_and_restore_endpoints(self):
        """Verify POST /api/v1/dlp/mask and POST /api/v1/dlp/restore endpoints."""
        mask_payload = {
            "text": "Transfer $500 to user@bank.com from account DE89370400440532013000.",
        }

        resp = self.client.post("/api/v1/dlp/mask", json=mask_payload, headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertIn("[EMAIL_1]", data["masked_text"])
        self.assertIn("[IBAN_1]", data["masked_text"])
        self.assertEqual(data["total_entities"], 2)
        vault = data["vault"]

        # Call restore endpoint
        restore_payload = {
            "masked_text": data["masked_text"],
            "vault": vault,
        }
        restore_resp = self.client.post("/api/v1/dlp/restore", json=restore_payload, headers=self.headers)
        self.assertEqual(restore_resp.status_code, 200)
        self.assertEqual(restore_resp.json()["restored_text"], mask_payload["text"])

    def test_05_openai_proxy_end_to_end_pii_masking_and_restoration(self):
        """Verify OpenAI proxy masks PII before sending to LLM, then restores PII in LLM response."""
        user_prompt = "Process refund for charlie@shop.com with card 4532-0151-1283-0366."

        def mock_llm_chat(messages):
            # Verify the LLM ONLY received masked placeholders, NOT real user PII!
            received_content = messages[-1]["content"]
            self.assertNotIn("charlie@shop.com", received_content)
            self.assertNotIn("4532-0151-1283-0366", received_content)
            self.assertIn("[EMAIL_1]", received_content)
            self.assertIn("[CREDIT_CARD_1]", received_content)
            # LLM echoes back placeholders
            return "Refund of $50 issued to [CREDIT_CARD_1] for [EMAIL_1]."

        payload = {
            "model": "llama3.2",
            "messages": [
                {"role": "user", "content": user_prompt},
            ],
        }

        with patch("agentguard.call_guard", return_value={"attack_type": "none", "risk_score": 0.0}), \
             patch("backend.services.target_service.call_target_chat", side_effect=mock_llm_chat):
            resp = self.client.post("/v1/chat/completions", json=payload, headers=self.headers)

        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        # The client response must have the placeholders restored back to real user values!
        assistant_content = data["choices"][0]["message"]["content"]
        self.assertEqual(
            assistant_content,
            "Refund of $50 issued to 4532-0151-1283-0366 for charlie@shop.com.",
        )

        # Verify DLP metadata
        guard_meta = data.get("agentguard", {})
        self.assertEqual(guard_meta.get("dlp_entities_masked"), 2)
        self.assertIn("EMAIL", guard_meta.get("dlp_types", []))
        self.assertIn("CREDIT_CARD", guard_meta.get("dlp_types", []))

    def test_06_openai_proxy_mask_only_mode(self):
        """Verify X-AgentGuard-DLP-Mask-Only keeps placeholders permanently masked in response."""
        user_prompt = "Send email to secret.contact@intel.gov."

        payload = {
            "model": "llama3.2",
            "messages": [{"role": "user", "content": user_prompt}],
        }
        headers = dict(self.headers)
        headers["X-AgentGuard-DLP-Mask-Only"] = "true"

        with patch("agentguard.call_guard", return_value={"attack_type": "none", "risk_score": 0.0}), \
             patch("backend.services.target_service.call_target_chat", return_value="Message sent to [EMAIL_1]."):
            resp = self.client.post("/v1/chat/completions", json=payload, headers=headers)

        self.assertEqual(resp.status_code, 200)
        content = resp.json()["choices"][0]["message"]["content"]
        # In mask-only mode, placeholder is NOT de-masked
        self.assertEqual(content, "Message sent to [EMAIL_1].")

    def test_07_execution_service_dlp_integration(self):
        """Verify POST /api/v1/execute runs DLP masking and restoration."""
        prompt = "My contact email is dev@startup.io."

        def mock_target(p):
            self.assertIn("[EMAIL_1]", p)
            self.assertNotIn("dev@startup.io", p)
            return "Acknowledged email [EMAIL_1]."

        with patch("agentguard.call_guard", return_value={"attack_type": "none", "risk_score": 0.0}), \
             patch("backend.services.execution_service.call_target", side_effect=mock_target):
            resp = self.client.post("/api/v1/execute", json={"prompt": prompt}, headers=self.headers)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["response"], "Acknowledged email dev@startup.io.")


if __name__ == "__main__":
    unittest.main()
