import os
import unittest
from backend.services.chat_store import ChatStore


class TestChatStore(unittest.TestCase):
    def setUp(self):
        self.test_db = os.path.join("data", "test_chat.db")
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        self.store = ChatStore(db_path=self.test_db)

    def tearDown(self):
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except Exception:
                pass

    def test_seeded_conversations_exist(self):
        convs = self.store.list_conversations()
        self.assertGreaterEqual(len(convs), 3)
        ids = [c["conversation_id"] for c in convs]
        self.assertIn("conv-injection-audit", ids)
        self.assertIn("conv-dlp-stream", ids)
        self.assertIn("conv-hitl-queue", ids)

    def test_get_conversation_turns(self):
        conv = self.store.get_conversation("conv-injection-audit")
        self.assertIsNotNone(conv)
        self.assertEqual(conv["title"], "Direct Prompt Injection Check")
        self.assertEqual(len(conv["turns"]), 1)
        self.assertEqual(conv["turns"][0]["security"]["decision"], "BLOCK")

    def test_save_and_append_turn(self):
        cid = "conv-unit-test-1"
        self.store.save_turn(
            conversation_id=cid,
            turn_data={
                "id": "turn-test-1",
                "turn_number": 1,
                "user_message": "Hello AgentGuard!",
                "assistant_response": "Hello, how can I help you safely?",
                "decision": "ALLOW",
                "risk_score": 0.0,
                "attack_type": "none",
                "latency_ms": 12.5,
            },
            title="Custom Test Conversation",
        )

        conv = self.store.get_conversation(cid)
        self.assertIsNotNone(conv)
        self.assertEqual(conv["title"], "Custom Test Conversation")
        self.assertEqual(conv["turn_count"], 1)
        self.assertEqual(len(conv["turns"]), 1)
        self.assertEqual(conv["turns"][0]["userMessage"], "Hello AgentGuard!")

        # Append turn 2
        self.store.save_turn(
            conversation_id=cid,
            turn_data={
                "id": "turn-test-2",
                "turn_number": 2,
                "user_message": "Tell me a joke.",
                "assistant_response": "Why did the AI cross the road? To optimize the latency!",
                "decision": "ALLOW",
                "risk_score": 0.0,
                "attack_type": "none",
                "latency_ms": 10.0,
            },
        )
        updated = self.store.get_conversation(cid)
        self.assertEqual(updated["turn_count"], 2)
        self.assertEqual(len(updated["turns"]), 2)

    def test_delete_conversation(self):
        cid = "conv-to-delete"
        self.store.save_turn(
            conversation_id=cid,
            turn_data={"id": "turn-del-1", "user_message": "test", "decision": "ALLOW"},
        )
        self.assertIsNotNone(self.store.get_conversation(cid))
        deleted = self.store.delete_conversation(cid)
        self.assertTrue(deleted)
        self.assertIsNone(self.store.get_conversation(cid))


if __name__ == "__main__":
    unittest.main()
