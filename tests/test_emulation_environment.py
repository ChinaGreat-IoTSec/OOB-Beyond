import json
from pathlib import Path
import tempfile
import unittest

from emulation.environment import digest, resolve


class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "adapters").mkdir()
        (self.root / "environments").mkdir()
        self.source = self.root / "firmware.bin"
        self.source.write_bytes(b"synthetic test input")
        self.requirements = {"architecture": "mips", "endianness": "big", "bits": 32,
                             "abi": "o32", "machine": "malta", "control": "linux-serial-ssh-v1"}
        assets = {}
        for name in ("kernel", "system", "vendor", "script"):
            path = self.root / name
            path.write_text("echo synthetic\n")
            assets[name] = {"path": "../" + name, "sha256": digest(path)}
        self.adapter = {"schema_version": 1, "kind": "adapter", "id": "test-adapter",
                        "input_sha256": digest(self.source), "requirements": self.requirements,
                        "vendor_disk": assets["vendor"], "startup_script": assets["script"],
                        "network": {"local_ip": "10.0.2.15", "tap_ip": "192.168.100.2", "prefix": 24}}
        self.environment = {"schema_version": 1, "kind": "environment", "id": "shared-environment",
                            "requirements": self.requirements, "kernel": assets["kernel"], "system_disk": assets["system"]}

    def write(self, adapter=True, environment=True):
        if adapter:
            (self.root / "adapters/test.json").write_text(json.dumps(self.adapter))
        if environment:
            (self.root / "environments/test.json").write_text(json.dumps(self.environment))

    def test_clean_install_reports_missing_adapter_without_creating_assets(self):
        result = resolve(self.source, local=self.root)
        self.assertEqual(result["state"], "NEEDS_ADAPTER")
        self.assertTrue(result["next_steps"])
        self.assertEqual(list((self.root / "environments").iterdir()), [])

    def test_two_different_firmware_adapters_share_same_environment(self):
        self.write()
        first = resolve(self.source, local=self.root)
        self.source.write_bytes(b"another synthetic firmware")
        self.adapter["input_sha256"] = digest(self.source)
        self.adapter["id"] = "another-device"
        self.write(environment=False)
        second = resolve(self.source, local=self.root)
        self.assertEqual(first["state"], "PREPARED")
        self.assertEqual(second["state"], "PREPARED")
        self.assertEqual(first["profile"]["system_disk"], second["profile"]["system_disk"])
        self.assertNotEqual(first["adapter_id"], second["adapter_id"])
        self.assertEqual(first["reuse"], "local")

    def test_corrupt_environment_is_not_reused(self):
        self.write()
        (self.root / "system").write_text("changed")
        result = resolve(self.source, local=self.root)
        self.assertEqual(result["state"], "NEEDS_ENVIRONMENT")
        self.assertTrue(any("checksum mismatch" in message for message in result["diagnostics"]))

    def test_incompatible_environment_is_not_reused(self):
        self.environment["requirements"] = dict(self.requirements, endianness="little")
        self.write()
        self.assertEqual(resolve(self.source, local=self.root)["state"], "NEEDS_ENVIRONMENT")

    def test_duplicate_adapter_requires_explicit_selection(self):
        self.write()
        (self.root / "adapters/duplicate.json").write_text(json.dumps(self.adapter))
        self.assertEqual(resolve(self.source, local=self.root)["state"], "AMBIGUOUS_ADAPTER")
        self.assertEqual(resolve(self.source, self.root / "adapters/test.json", self.root)["state"], "PREPARED")

    def test_script_and_vendor_checksums_are_required(self):
        self.write()
        (self.root / "script").write_text("changed")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            resolve(self.source, local=self.root)

    def test_explicit_adapter_cannot_select_different_firmware(self):
        self.write()
        self.source.write_bytes(b"different")
        with self.assertRaisesRegex(ValueError, "does not match"):
            resolve(self.source, self.root / "adapters/test.json", self.root)

    def test_elf_observations_override_conflicting_adapter_claim(self):
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        header[18:20] = (62).to_bytes(2, "little")
        self.source.write_bytes(header)
        self.adapter["input_sha256"] = digest(self.source)
        self.write()
        with self.assertRaisesRegex(ValueError, "disagrees"):
            resolve(self.source, local=self.root)

    def test_unimplemented_backend_returns_explicit_gap(self):
        self.adapter["requirements"] = dict(self.requirements, architecture="arm", abi="eabi", machine="virt")
        self.write()
        self.assertEqual(resolve(self.source, local=self.root)["state"], "UNSUPPORTED_BACKEND")


if __name__ == "__main__":
    unittest.main()
