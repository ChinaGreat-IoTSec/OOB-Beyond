import tempfile
import unittest
from pathlib import Path

from agent.formats import identify_binary
from agent.graph import _after_ingest
from agent.nodes.ingest import ingest_node
from agent.states import FirmwareAuditState, FirmwareMeta


class BinaryFormatTests(unittest.TestCase):
    def test_formats_and_overrides(self):
        elf = bytearray(64)
        elf[:7] = b"\x7fELF\x02\x01\x01"
        elf[16:20] = b"\x03\x00\x3e\x00"
        pe = bytearray(256)
        pe[:2] = b"MZ"
        pe[60:64] = (64).to_bytes(4, "little")
        pe[64:70] = b"PE\x00\x00\x64\x86"
        pe[84:86] = (112).to_bytes(2, "little")
        pe[88:90] = b"\x0b\x02"
        macho = bytearray(32)
        macho[:8] = b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01"
        macho[12:16] = (6).to_bytes(4, "little")
        with tempfile.TemporaryDirectory() as directory:
            for name, content, expected in [
                ("lib.so.1", elf, "ELF"), ("driver.ko", elf, "ELF"),
                ("app.exe", pe, "PE"), ("lib.dll", pe, "PE"),
                ("driver.sys", pe, "PE"), ("lib.dylib", macho, "Mach-O"),
            ]:
                with self.subTest(name=name):
                    path = Path(directory) / name
                    path.write_bytes(content)
                    path.chmod(0o600)
                    self.assertEqual(identify_binary(path)[0], expected)
                    for requested, route in [("auto", "audit"), ("binary", "audit"), ("firmware", "unpack")]:
                        state = FirmwareAuditState(task_id="test", requested_input_type=requested,
                            firmware_meta=FirmwareMeta(firmware_path=str(path), file_size=0, sha256="0" * 64))
                        updated = state.model_copy(update=ingest_node(state))
                        self.assertEqual(_after_ingest(updated), route)
            for content in [b"text", b"MZ", b"\x7fELF", bytes(64)]:
                path = Path(directory) / "fake.exe"
                path.write_bytes(content)
                self.assertIsNone(identify_binary(path))


if __name__ == "__main__":
    unittest.main()
