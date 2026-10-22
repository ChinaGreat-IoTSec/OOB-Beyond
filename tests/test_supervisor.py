"""Supervisor selections must resolve only through request-local IDs."""

import unittest
from unittest.mock import patch

from agent.agents.supervisor import supervisor_node
from agent.states import BinaryTarget, FirmwareAuditState


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.targets = [
            BinaryTarget(file_path="/tmp/root a/usr/sbin/httpd", priority_score=8),
            BinaryTarget(file_path="/tmp/固件/root b/usr/sbin/httpd", priority_score=8),
        ]
        self.state = FirmwareAuditState(
            task_id="test", binary_targets=self.targets,
            selected_target=self.targets[0],
        )

    @patch("agent.agents.supervisor.ask_json")
    def test_id_preserves_exact_path(self, ask):
        ask.return_value = {"target_id": " T0002 ", "rationale": "second", "confidence": 0.8}
        result = supervisor_node(self.state)
        self.assertEqual(result["selected_target"], self.targets[1])
        self.assertIn("second", result["agent_decisions"][0].rationale)
        ask.assert_called_once()

    @patch("agent.agents.supervisor.ask_json")
    def test_exact_path_is_recovered(self, ask):
        ask.side_effect = [
            {"path": self.targets[1].file_path},
            {"target_id": "T0002", "rationale": "corrected", "confidence": "high"},
        ]
        result = supervisor_node(self.state)
        self.assertEqual(result["selected_target"], self.targets[1])
        self.assertEqual(ask.call_count, 1)

    @patch("agent.agents.supervisor.ask_json")
    def test_invalid_response_uses_explicit_rule_fallback(self, ask):
        for response in ({"target_id": "T9999"}, {"target_id": []}, [], {}):
            with self.subTest(response=response):
                ask.reset_mock()
                ask.return_value = response
                result = supervisor_node(self.state)
                self.assertEqual(result["selected_target"], self.targets[0])
                decision = result["agent_decisions"][0]
                self.assertEqual(decision.decision, "audit_rule_fallback")
                self.assertEqual(decision.confidence, 0)
                self.assertEqual(ask.call_count, 2)

    @patch("agent.agents.supervisor.ask_json")
    def test_ambiguous_suffix_requires_confirmation(self, ask):
        ask.side_effect = [
            {"path": "/usr/sbin/httpd", "rationale": "ambiguous"},
            {"target_id": "T0002", "rationale": "confirmed"},
        ]
        result = supervisor_node(self.state)
        self.assertEqual(result["selected_target"], self.targets[1])
        self.assertIn("confirmed", result["agent_decisions"][0].rationale)
        self.assertEqual(ask.call_count, 2)

    @patch("agent.agents.supervisor.ask_json")
    def test_unique_suffix_and_normalization(self, ask):
        for path in ("root b/usr/sbin/httpd", "/tmp/固件/root b/usr/./sbin/httpd"):
            with self.subTest(path=path):
                ask.return_value = {"selected_path": path}
                result = supervisor_node(self.state)
                self.assertEqual(result["selected_target"], self.targets[1])

    @patch("agent.agents.supervisor.ask_json")
    def test_empty_candidates_do_not_call_model(self, ask):
        result = supervisor_node(FirmwareAuditState(task_id="empty"))
        self.assertEqual(result["status"], "FAILED")
        ask.assert_not_called()

    @patch("agent.agents.supervisor.ask_json", side_effect=RuntimeError("offline"))
    def test_connection_failure_clears_preselection(self, ask):
        result = supervisor_node(self.state)
        self.assertIsNone(result["selected_target"])
        self.assertEqual(result["status"], "FAILED")
        ask.assert_called_once()
