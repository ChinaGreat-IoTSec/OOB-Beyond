import unittest
from pathlib import Path
from unittest.mock import patch

from agent.nodes.audit import audit_node
from agent.states import BinaryTarget, FirmwareAuditState
from tools.base import ToolResult


class GhidraEvidenceTests(unittest.TestCase):
    @patch("agent.nodes.audit.GhidraRunner.analyze")
    def test_script_failure_with_zero_exit_is_not_success(self, analyze):
        analyze.return_value = ToolResult(command=["analyzeHeadless"], return_code=0, stdout="Script error")
        result = audit_node(FirmwareAuditState(
            task_id="test", selected_target=BinaryTarget(file_path="fixture", priority_score=1),
        ))
        self.assertEqual(result["status"], "FAILED")

    @patch("agent.nodes.audit.GhidraRunner.analyze")
    def test_prefixed_pcode_evidence_reaches_assessment(self, analyze):
        analyze.return_value = ToolResult(
            command=["analyzeHeadless"], return_code=0,
            stdout='INFO script EVIDENCE_JSON|{"sink_function":"system","sink_address":"0x1000",'
                   '"arguments":[{"index":0,"source":"getenv"}]}\nEVIDENCE_COMPLETE|1\n',
        )
        result = audit_node(FirmwareAuditState(
            task_id="test", selected_target=BinaryTarget(file_path="fixture", priority_score=1),
        ))
        self.assertEqual(result["findings"][0].conclusion, "suspected")

    @patch("agent.nodes.audit.GhidraRunner.analyze")
    def test_structured_evidence_is_parsed(self, analyze):
        analyze.return_value = ToolResult(
            command=["analyzeHeadless"],
            return_code=0,
            stdout=(
                'EVIDENCE_JSON|{"sink_function":"system",'
                '"sink_address":"0x401234","callers":["handle_request"],'
                '"call_sites":["0x401200"],'
                '"input_sources":[{"function":"recv","address":"0x400100"}]}\nEVIDENCE_COMPLETE|1\n'
            ),
        )
        state = FirmwareAuditState(
            task_id="test",
            selected_target=BinaryTarget(file_path="/tmp/httpd", priority_score=8),
        )
        result = audit_node(state)
        self.assertEqual(result["status"], "AUDITED")
        self.assertEqual(len(result["static_evidence"]), 1)
        self.assertEqual(result["static_evidence"][0].callers, ["handle_request"])
        self.assertEqual(result["findings"][0].evidence_refs, ["system@0x401234"])

    @patch("agent.nodes.audit.GhidraRunner.analyze")
    def test_tool_failure_is_not_reported_as_audit_success(self, analyze):
        analyze.return_value = ToolResult(
            command=["analyzeHeadless"], return_code=1, stderr="import failed"
        )
        state = FirmwareAuditState(
            task_id="test",
            selected_target=BinaryTarget(file_path="/tmp/httpd", priority_score=8),
        )
        result = audit_node(state)
        self.assertEqual(result["status"], "FAILED")
        self.assertIn("Ghidra analysis failed: import failed", result["error_message"])


if __name__ == "__main__":
    unittest.main()
