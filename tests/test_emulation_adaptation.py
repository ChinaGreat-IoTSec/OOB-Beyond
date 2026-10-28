import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from agent.llm import load_env_file
from emulation.adaptation import adapt, health, observe


class AdaptationTests(unittest.TestCase):
    def test_transient_request_failure_retries_without_replaying_guest_command(self):
        requester = MagicMock(side_effect=[RuntimeError("Request timed out"), {"action": "need_user", "reason": "fixture"}])
        result = adapt(self.guest, self.config, self.report, lambda: None, MagicMock(), requester)
        self.assertEqual(requester.call_count, 2)
        self.guest.execute.assert_not_called()
        self.assertEqual(result["rounds"], 2)

    def test_transient_request_retry_limit_is_three_attempts(self):
        self.config["adapt_rounds"] = 10
        requester = MagicMock(side_effect=RuntimeError("Request timed out"))
        result = adapt(self.guest, self.config, self.report, lambda: None, MagicMock(), requester)
        self.assertFalse(result["success"])
        self.assertEqual(requester.call_count, 3)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.report = Path(self.directory.name)
        self.guest = MagicMock()
        self.config = {"adapt_timeout": 60, "adapt_rounds": 3, "goal": "start demo", "expect_process": ["demo"],
                       "expect_port": [8080], "observe_seconds": 5, "network": "local",
                       "profile": {"requirements": {}, "guest_ip_local": "10.0.2.15", "startup_script": "#!/bin/sh\n"}}

    def test_env_preserves_existing_configuration_and_strips_quotes(self):
        path = self.report / ".env"
        path.write_text('export IOT_AUDIT_MODEL = "fixture-model"\nIOT_AUDIT_REASONING_EFFORT=medium\n')
        with patch.dict(os.environ, {"IOT_AUDIT_MODEL": "existing"}, clear=True):
            load_env_file(path)
            self.assertEqual(os.environ["IOT_AUDIT_MODEL"], "existing")
            self.assertEqual(os.environ["IOT_AUDIT_REASONING_EFFORT"], "medium")

    def test_model_cannot_declare_success_without_health_checks(self):
        requester = MagicMock(return_value={"action": "verify"})
        self.guest.execute.return_value = {"exit_code": 1, "output": ""}
        result = adapt(self.guest, self.config, self.report, lambda: None, MagicMock(), requester)
        self.assertFalse(result["success"])
        self.assertEqual(requester.call_count, 3)

    def test_health_matches_exact_listener_port(self):
        self.guest.execute.side_effect = [{"exit_code": 0, "output": "123"},
                                         {"exit_code": 0, "output": "tcp 0 0 0.0.0.0:18080 0.0.0.0:* LISTEN\n"}]
        self.assertFalse(health(self.guest, ["demo"], [8080])["ok"])

    def test_observation_catches_service_exiting(self):
        readings = [{"ok": True}, {"ok": False, "failures": ["exit"]}]
        current = [0.0]
        def pause(duration):
            current[0] += duration
        with patch("emulation.adaptation.health", side_effect=readings):
            result = observe(self.guest, self.config, self.report, lambda: None, lambda: current[0], pause)
        self.assertFalse(result["ok"])

    def test_successful_changes_saved_as_unverified_draft_only(self):
        requester = MagicMock(side_effect=[{"action": "execute", "command": "echo started", "persist": True},
                                           {"action": "verify"}])
        self.guest.execute.return_value = {"exit_code": 0, "output": "started"}
        with patch("emulation.adaptation.observe", return_value={"ok": True}):
            result = adapt(self.guest, self.config, self.report, lambda: None, MagicMock(), requester)
        self.assertTrue(result["success"])
        metadata = json.loads((self.report / "adaptation-draft.json").read_text())
        self.assertFalse(metadata["replay_verified"])
        self.assertIn("echo started", (self.report / "adaptation-draft.sh").read_text())

    def test_model_failure_is_recorded_without_credentials(self):
        requester = MagicMock(side_effect=RuntimeError("failure fixture-secret"))
        with patch.dict(os.environ, {"OPENAI_API_KEY": "fixture-secret"}):
            result = adapt(self.guest, self.config, self.report, lambda: None, MagicMock(), requester)
        self.assertFalse(result["success"])
        self.assertNotIn("fixture-secret", (self.report / "llm-events.jsonl").read_text())

    def test_stop_propagates_instead_of_becoming_a_model_retry(self):
        requester = MagicMock(side_effect=InterruptedError())
        with self.assertRaises(InterruptedError):
            adapt(self.guest, self.config, self.report, lambda: None, MagicMock(), requester)

    def test_recovery_attempts_share_total_round_budget(self):
        requester = MagicMock(return_value={"action": "need_user", "reason": "missing dependency"})
        for _ in range(5):
            adapt(self.guest, self.config, self.report, lambda: None, MagicMock(), requester)
        self.assertEqual(requester.call_count, self.config["adapt_rounds"])


if __name__ == "__main__":
    unittest.main()
