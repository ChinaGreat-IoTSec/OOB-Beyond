import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from emulation.preparation import guest_path, inspect_rootfs, prepare_firmware, tree_identity, startup_script, preparation_workspace, asset_name
from tools.extraction import rootfs_candidates, squashfs_offsets
from tools.binwalk import BinwalkTool
from tools.unpackers import SasquatchTool


class PreparationTests(unittest.TestCase):
    def test_readable_workspace_reuses_identity_and_handles_collision(self):
        identity = "a" * 64
        workspace = preparation_workspace(self.local, self.source, identity)
        self.assertEqual(workspace.name, "firmware-" + identity[:12])
        self.assertEqual(workspace, preparation_workspace(self.local, Path("renamed.bin"), identity))
        collision = preparation_workspace(self.local, self.source, "a" * 12 + "b" * 52)
        self.assertNotEqual(workspace, collision)
        legacy = self.local / "prepared" / ("c" * 64)
        legacy.mkdir()
        self.assertEqual(legacy, preparation_workspace(self.local, self.source, "c" * 64))
        self.assertNotIn(" ", asset_name(Path("name with spaces.bin"), identity))

    def test_bootstrap_mounts_firmware_without_starting_a_service(self):
        script = startup_script(None, ())
        self.assertIn("mount /dev/sdb /firmware", script)
        self.assertNotIn("setsid", script)
        self.assertNotIn("pidof", script)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "rootfs"
        (self.root / "bin").mkdir(parents=True)
        (self.root / "lib").mkdir()
        (self.root / "etc").mkdir()
        header = bytearray(64)
        header[:6] = b"\x7fELF\x01\x02"
        struct.pack_into(">H", header, 18, 8)
        struct.pack_into(">I", header, 36, 0x1000)
        self.program = self.root / "bin/service"
        self.program.write_bytes(header)
        self.program.chmod(0o755)
        self.source = self.base / "firmware.bin"
        self.source.write_bytes(b"synthetic fixture")
        self.local = self.base / "local"

    def test_guest_absolute_symlinks_do_not_resolve_on_host(self):
        (self.root / "bin/alias").symlink_to("/bin/service")
        self.assertEqual(guest_path(self.root, "/bin/alias"), self.program)
        (self.root / "bin/loop").symlink_to("/bin/loop")
        with self.assertRaises(ValueError):
            guest_path(self.root, "/bin/loop")

    def test_rootfs_architecture_and_permissions(self):
        result = inspect_rootfs(self.root, "/bin/service")
        self.assertEqual(result["requirements"]["endianness"], "big")
        self.assertEqual(result["requirements"]["abi"], "o32")
        self.program.chmod(0o644)
        with self.assertRaises(ValueError):
            inspect_rootfs(self.root)

    def test_missing_dynamic_linker_blocks_preparation(self):
        content = bytearray(self.program.read_bytes())
        struct.pack_into(">I", content, 28, 64)
        struct.pack_into(">HH", content, 42, 32, 1)
        loader = b"/lib/missing.so\0"
        entry = bytearray(32)
        struct.pack_into(">II", entry, 0, 3, 96)
        struct.pack_into(">I", entry, 16, len(loader))
        self.program.write_bytes(content + entry + loader)
        with self.assertRaisesRegex(ValueError, "Dynamic linker"):
            inspect_rootfs(self.root)

    def test_rootfs_identity_detects_content_mode_and_link_changes(self):
        initial = tree_identity(self.root)[0]
        self.program.chmod(0o700)
        self.assertNotEqual(initial, tree_identity(self.root)[0])
        (self.root / "link").symlink_to("/etc/config")
        changed = tree_identity(self.root)[0]
        (self.root / "link").unlink()
        (self.root / "link").symlink_to("/etc/other")
        self.assertNotEqual(changed, tree_identity(self.root)[0])

    @unittest.skipUnless(shutil.which("mkfs.ext2") and shutil.which("debugfs"), "e2fsprogs required")
    def test_actual_disk_creation_reuse_and_generated_adapter(self):
        (self.root / "bin/alias").symlink_to("/bin/service")
        first = prepare_firmware(self.source, self.root, local=self.local)
        self.assertEqual(first["state"], "NEEDS_SERVICE")
        disk = Path(first["vendor_disk"])
        before = disk.stat().st_mtime_ns
        inspected = subprocess.run(["debugfs", "-R", "stat /bin/alias", str(disk)], capture_output=True, text=True, check=True)
        self.assertIn("/bin/service", inspected.stdout)
        second = prepare_firmware(self.source, self.root, "/bin/service", local=self.local)
        self.assertEqual(second["state"], "NEEDS_ENVIRONMENT")
        self.assertEqual(before, disk.stat().st_mtime_ns)
        adapter = json.loads(Path(second["adapter_path"]).read_text())
        self.assertEqual(adapter["vendor_disk"]["path"], str(disk))
        self.assertIn("chroot /firmware /bin/service", Path(adapter["startup_script"]["path"]).read_text())
        self.program.write_bytes(self.program.read_bytes() + b"new")
        third = prepare_firmware(self.source, self.root, local=self.local)
        self.assertNotEqual(third["vendor_disk"], first["vendor_disk"])

    def test_squashfs_magic_crosses_scan_boundary(self):
        self.source.write_bytes(b"x" * (1024 * 1024 - 2) + b"sqsh" + b"x")
        self.assertEqual(squashfs_offsets(self.source), [1024 * 1024 - 2])

    def test_rewritten_rootfs_is_not_selected(self):
        self.assertEqual(rootfs_candidates(self.base), [self.root])
        (self.root / ".oob-not-runtime-rootfs").touch()
        self.assertEqual(rootfs_candidates(self.base), [])

    def test_timeout_keeps_binary_tool_output_as_text(self):
        with patch("tools.base.subprocess.run", side_effect=subprocess.TimeoutExpired("binwalk", 1, output=b"partial", stderr=b"error")):
            result = BinwalkTool(timeout=1).execute([])
        self.assertTrue(result.timed_out)
        self.assertEqual(result.stdout, "partial")

    def test_sasquatch_receives_nonexistent_destination(self):
        destination = self.base / "new-parent/extracted"
        with patch.object(SasquatchTool, "execute") as execute:
            SasquatchTool().extract(self.source, destination)
        self.assertTrue(destination.parent.is_dir())
        self.assertFalse(destination.exists())
        self.assertEqual(execute.call_args.args[0][1], str(destination))


if __name__ == "__main__":
    unittest.main()
