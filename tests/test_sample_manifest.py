import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.sample_manifest import validate_sample
from tools.sample_manifest import CASE_EXPECTATIONS, SampleManifest


class SampleManifestTests(unittest.TestCase):
    def annotated_sample(self):
        return {
            "schema_version": "2", "sample_id": "safe-command",
            "artifact": "safe.bin", "sha256": "0" * 64,
            "split": "development", "vulnerability_type": "command_injection",
            "expected": "not_vulnerable", "scope": "run_command: system argument",
            "references": ["review.md"], "case_kind": "safe_argument",
            "origin": "synthetic",
            "evidence": [{"location": "run_command: system call", "observation": "literal command"}],
            "rationale": "External input does not affect the command argument",
            "limitations": "Only this call and command injection are covered",
        }

    def test_all_case_kinds_have_consistent_expectations(self):
        for case_kind, expected in CASE_EXPECTATIONS.items():
            with self.subTest(case_kind=case_kind):
                record = dict(self.annotated_sample(), case_kind=case_kind, expected=expected)
                self.assertEqual(SampleManifest.model_validate(record).expected, expected)

    def test_incomplete_or_conflicting_annotations_are_rejected(self):
        for update in (
            {"expected": "vulnerable"}, {"evidence": []},
            {"references": [" "]}, {"rationale": " "},
            {"limitations": ""}, {"case_kind": None}, {"origin": None},
            {"scope": " "}, {"schema_version": "1"},
            {"evidence": [{"location": " ", "observation": "literal"}]},
        ):
            with self.subTest(update=update):
                with self.assertRaises(ValueError):
                    SampleManifest.model_validate(dict(self.annotated_sample(), **update))

    def test_unknown_does_not_require_invented_evidence(self):
        record = dict(self.annotated_sample(), case_kind="insufficient_evidence",
                      expected="unknown", evidence=[], references=[])
        self.assertEqual(SampleManifest.model_validate(record).expected, "unknown")

    def test_sample_contract_and_artifact_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample.bin").write_bytes(b"fixture")
            manifest_path = root / "sample.json"
            baseline = {
                "schema_version": "1",
                "sample_id": "fixture",
                "artifact": "sample.bin",
                "sha256": hashlib.sha256(b"fixture").hexdigest(),
                "split": "development",
                "vulnerability_type": "command_injection",
                "expected": "unknown",
                "scope": "fixture only",
            }
            manifest_path.write_text(json.dumps(baseline))
            self.assertEqual(validate_sample(manifest_path, root).sample_id, "fixture")
            for update in (
                {"sha256": "0" * 64},
                {"artifact": "../outside.bin"},
                {"artifact": str(root / "sample.bin")},
                {"artifact": "missing.bin"},
                {"expected": "vulnerable"},
                {"schema_version": "2"},
                {"unexpected_field": True},
            ):
                with self.subTest(update=update):
                    manifest_path.write_text(json.dumps(dict(baseline, **update)))
                    with self.assertRaises(ValueError):
                        validate_sample(manifest_path, root)
            manifest_path.write_text(json.dumps(dict(
                baseline, expected="vulnerable", references=["local-reviewed-analysis"]
            )))
            self.assertEqual(validate_sample(manifest_path, root).expected, "vulnerable")


if __name__ == "__main__":
    unittest.main()
