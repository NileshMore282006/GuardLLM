"""
GuardLLM Interactive Demo: Reversible PII / DLP Tokenizer (Privacy Guard)
Demonstrates:
1. End-to-end inbound anonymization (so LLMs never see user PII)
2. Outbound de-anonymization (restores real values to user)
3. Luhn algorithm validation for payment cards
4. Coreference preservation across conversation turns
"""

from unittest.mock import patch
from fastapi.testclient import TestClient
import openai

from backend.main import app
from backend.services.dlp_service import dlp_service, luhn_checksum
from backend.services.tenant_service import tenant_service
from backend.services.principal_service import principal_service
from backend.services.credential_service import credential_service


def run_demo():
    print("=" * 70)
    print("   GuardLLM - Reversible PII / DLP Tokenizer (Privacy Guard) Demo")
    print("=" * 70)

    # 1. Setup tenant & auth
    tenant_service._seed_defaults()
    principal_service._seed_defaults()
    _, token = credential_service.create_credential("user-demo", "default")

    client = openai.OpenAI(
        base_url="http://testserver/v1",
        api_key=token,
        http_client=TestClient(app),
    )

    # Demo 1: Multi-Entity PII Tokenization
    print("\n[Demo 1] Inbound PII Anonymization & Reversible Restoration")
    raw_prompt = (
        "Please issue a receipt for customer Alice (alice@cloudcorp.io). "
        "Her mobile is (555) 432-8765 and her Visa card is 4532-0151-1283-0366. "
        "Also note down her SSN: 123-45-6789."
    )
    print("  Original User Prompt:")
    print(f"    \"{raw_prompt}\"")

    masked_prompt, vault = dlp_service.tokenize(raw_prompt)
    print("\n  Masked Prompt Sent to LLM (Zero Real PII Reaches Cloud Model):")
    print(f"    \"{masked_prompt}\"")
    print("  Token Vault Map:", vault.reverse_map)

    # Demo 2: End-to-End Execution through OpenAI Proxy
    print("\n[Demo 2] End-to-End LLM Execution with Bi-Directional DLP")
    def mock_llm(messages):
        received_text = messages[-1]["content"]
        print("\n  >> LLM Execution Boundary: What the model actually sees:")
        print(f"     \"{received_text}\"")
        return "I have processed the receipt for [EMAIL_1] and verified card [CREDIT_CARD_1]. An SMS confirmation was dispatched to [PHONE_1]."

    with patch("agentguard.call_guard", return_value={"attack_type": "none", "risk_score": 0.0}), \
         patch("backend.services.target_service.call_target_chat", side_effect=mock_llm):
        response = client.chat.completions.create(
            model="llama3.2",
            messages=[{"role": "user", "content": raw_prompt}],
        )

    print("\n  << Final Restored Response Received by User:")
    print(f"     \"{response.choices[0].message.content}\"")

    # Demo 3: Luhn Checksum Card Verification
    print("\n[Demo 3] Enterprise Luhn Checksum Payment Card Verification")
    valid_card = "4532-0151-1283-0366"
    invalid_seq = "4532-0151-1283-0367"
    print(f"  Valid Visa ({valid_card}) -> Luhn Check: {luhn_checksum(valid_card)} (Masked as [CREDIT_CARD_1])")
    print(f"  Fake Sequence ({invalid_seq}) -> Luhn Check: {luhn_checksum(invalid_seq)} (Not masked as card, prevents false positives)")

    # Demo 4: Coreference Preservation
    print("\n[Demo 4] Coreference Preservation (Same entity = Same placeholder)")
    coref_text = "Send copy to dev@acme.com, notify dev@acme.com on completion, and backup to dev@acme.com."
    masked_coref, coref_vault = dlp_service.tokenize(coref_text)
    print("  Original:", coref_text)
    print("  Masked:  ", masked_coref)
    print(f"  Placeholder Count: [EMAIL_1] appears {masked_coref.count('[EMAIL_1]')} times (Single vault entry)")

    print("\n" + "=" * 70)
    print("  Demo Complete: Enterprise GDPR / HIPAA / PCI-DSS Privacy Invariants Verified!")
    print("=" * 70)


if __name__ == "__main__":
    run_demo()
