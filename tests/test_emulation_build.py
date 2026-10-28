import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from emulation.build import prepare_environment, recipe
from emulation.environment import digest


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.local = self.root / "emulation/local"
        self.requirements = {"architecture": "mips", "endianness": "big", "bits": 32, "abi": "o32",
                             "machine": "malta", "control": "linux-serial-ssh-v1"}
        configs = self.root / "emulation/configs"
        configs.mkdir(parents=True)
        (configs / "mips32-be-malta_defconfig").write_text("fixture")
        (configs / "malta-network.fragment").write_text("fixture")
        archive = self.root / "emulation/downloads/buildroot-test.tar.xz"
        archive.parent.mkdir()
        archive.write_bytes(b"fixture archive")
        (configs / "buildroot.json").write_text(json.dumps({"version": "test", "sha256": digest(archive)}))
        source = self.root / "emulation/sources/buildroot-test"
        source.mkdir(parents=True)
        (source / "Makefile").write_text("fixture")

    def test_missing_environment_does_not_build_without_user_choice(self):
        with patch("emulation.build.subprocess.Popen") as launch:
            result = prepare_environment(self.requirements, root=self.root, local=self.local)
        self.assertEqual(result["state"], "NEEDS_ENVIRONMENT")
        launch.assert_not_called()

    def test_unsupported_recipe_does_not_build(self):
        with self.assertRaises(ValueError):
            recipe(dict(self.requirements, architecture="arm"), self.root)

    def test_build_registers_assets_and_reuses_cache(self):
        _, identity = recipe(self.requirements, self.root)
        images = self.root / "emulation/output" / identity / "images"
        def launch(*args, **kwargs):
            images.mkdir(parents=True, exist_ok=True)
            (images / "vmlinux").write_bytes(b"kernel fixture")
            (images / "rootfs.ext2").write_bytes(b"disk fixture")
            process = MagicMock()
            process.wait.return_value = 0
            return process
        disk_usage = shutil._ntuple_diskusage(100 * 1024 ** 3, 0, 100 * 1024 ** 3)
        with patch("emulation.build.shutil.which", return_value="available"), \
             patch("emulation.build.shutil.disk_usage", return_value=disk_usage), \
             patch("emulation.build.subprocess.Popen", side_effect=launch) as build, \
             patch("emulation.build.subprocess.run", side_effect=lambda command, **kwargs: shutil.copyfile(command[-2], command[-1])):
            result = prepare_environment(self.requirements, True, root=self.root, local=self.local)
            self.assertEqual(build.call_count, 2)
            repeated = prepare_environment(self.requirements, True, root=self.root, local=self.local)
            self.assertEqual(build.call_count, 2)
        self.assertEqual(result["state"], "ENVIRONMENT_AVAILABLE")
        self.assertEqual(result, repeated)
        registry = json.loads((self.local / "environments" / (identity + ".json")).read_text())
        self.assertEqual(digest(Path(registry["kernel"]["path"])), registry["kernel"]["sha256"])

    def test_build_failure_does_not_register_environment(self):
        process = MagicMock()
        process.wait.return_value = 2
        disk_usage = shutil._ntuple_diskusage(100 * 1024 ** 3, 0, 100 * 1024 ** 3)
        with patch("emulation.build.shutil.which", return_value="available"), \
             patch("emulation.build.shutil.disk_usage", return_value=disk_usage), \
             patch("emulation.build.subprocess.Popen", return_value=process):
            result = prepare_environment(self.requirements, True, root=self.root, local=self.local)
        self.assertEqual(result["state"], "BUILD_FAILED")
        self.assertFalse((self.local / "environments").exists())


if __name__ == "__main__":
    unittest.main()
