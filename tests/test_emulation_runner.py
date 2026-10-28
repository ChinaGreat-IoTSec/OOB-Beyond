import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch


SPEC = importlib.util.spec_from_file_location(
    "malta_runner", Path(__file__).resolve().parents[1] / "emulation/scripts/start_malta.py"
)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class EmulationRunnerTests(unittest.TestCase):
    def test_tap_uses_existing_interface_without_scripts_or_forwarding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = root / "emulation"
            (environment / "scripts").mkdir(parents=True)
            asset = root / "asset"
            asset.write_bytes(b"fixture")
            process = MagicMock()
            process.wait.return_value = 0
            process.poll.return_value = 0
            with patch.object(RUNNER, "__file__", str(environment / "scripts/start_malta.py")), \
                 patch.object(RUNNER.shutil, "which", return_value="available"), \
                 patch.object(RUNNER.Path, "read_text", return_value="0x1002\n"), \
                 patch.object(RUNNER.subprocess, "run"), \
                 patch.object(RUNNER.subprocess, "Popen", return_value=process) as launch, \
                 patch("sys.argv", ["runner", "--kernel", str(asset), "--system-disk", str(asset),
                                    "--vendor-disk", str(asset), "--network", "tap", "--tap-ifname", "labtap1"]):
                self.assertEqual(RUNNER.main(), 0)
            command = launch.call_args.args[0]
            self.assertEqual(command[command.index("-netdev") + 1],
                             "tap,id=tapnet,ifname=labtap1,script=no,downscript=no")
            self.assertIn("pcnet,netdev=tapnet", command)
            self.assertFalse(any("hostfwd" in argument for argument in command))
            self.assertEqual(list((environment / "runs").iterdir()), [])

    def test_invalid_or_missing_tap_does_not_launch(self):
        for name, flags in (("bad,script=x", "0x2"), ("oobtap0", "0x1"),
                            ("oobtap0", "invalid"), ("oobtap0", None)):
            with self.subTest(name=name, flags=flags), patch("sys.argv", [
                "runner", "--kernel", "missing", "--system-disk", "missing", "--vendor-disk", "missing",
                "--network", "tap", "--tap-ifname", name,
            ]), patch.object(RUNNER.Path, "read_text", return_value=flags,
                             side_effect=FileNotFoundError() if flags is None else None), \
                 patch.object(RUNNER.subprocess, "Popen") as launch:
                with self.assertRaises(SystemExit):
                    RUNNER.main()
                launch.assert_not_called()

    def test_local_network_is_loopback_only_and_restricted(self):
        self.check_network_binding("127.0.0.1", [])

    def test_local_network_can_bind_wsl_address(self):
        self.check_network_binding("172.28.10.20", ["--bind-address", "172.28.10.20"])

    def test_invalid_bind_address_does_not_launch(self):
        for address in ("localhost", "::1", "172.28.10.20,restrict=off"):
            with self.subTest(address=address), patch("sys.argv", [
                "runner", "--kernel", "missing", "--system-disk", "missing", "--vendor-disk", "missing",
                "--network", "local", "--bind-address", address,
            ]), patch.object(RUNNER.subprocess, "Popen") as launch:
                with self.assertRaises(SystemExit):
                    RUNNER.main()
                launch.assert_not_called()

    def check_network_binding(self, address, options):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = root / "emulation"
            (environment / "scripts").mkdir(parents=True)
            asset = root / "asset"
            asset.write_bytes(b"fixture")
            process = MagicMock()
            process.wait.return_value = 0
            process.poll.return_value = 0
            with patch.object(RUNNER, "__file__", str(environment / "scripts/start_malta.py")), \
                 patch.object(RUNNER.shutil, "which", return_value="available"), \
                 patch.object(RUNNER.subprocess, "run"), \
                 patch.object(RUNNER.subprocess, "Popen", return_value=process) as launch, \
                 patch("sys.argv", ["runner", "--kernel", str(asset), "--system-disk", str(asset),
                                    "--vendor-disk", str(asset), "--network", "local"] + options):
                self.assertEqual(RUNNER.main(), 0)
            command = launch.call_args.args[0]
            network = command[command.index("-netdev") + 1]
            self.assertIn("restrict=on", network)
            self.assertIn(f"hostfwd=tcp:{address}:18443-10.0.2.15:443", network)
            self.assertIn(f"hostfwd=tcp:{address}:18080-10.0.2.15:80", network)
            self.assertIn("pcnet,netdev=localnet", command)
            self.assertNotIn("-nic", command)

    def test_invalid_forwarded_ports_do_not_launch(self):
        for ports in [(80, 443), (18080, 18080), (18080, 65536)]:
            with self.subTest(ports=ports), patch("sys.argv", [
                "runner", "--kernel", "missing", "--system-disk", "missing", "--vendor-disk", "missing",
                "--network", "local", "--http-port", str(ports[0]), "--https-port", str(ports[1]),
            ]), patch.object(RUNNER.subprocess, "Popen") as launch:
                with self.assertRaises(SystemExit):
                    RUNNER.main()
                launch.assert_not_called()

    def test_timeout_stops_guest_before_deleting_overlays(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = root / "emulation"
            (environment / "scripts").mkdir(parents=True)
            assets = [root / name for name in ("kernel", "system", "vendor")]
            for asset in assets:
                asset.write_bytes(b"unchanged")
            process = MagicMock()
            process.wait.side_effect = [subprocess.TimeoutExpired("qemu", 1), 0]
            process.poll.return_value = None
            with patch.object(RUNNER, "__file__", str(environment / "scripts/start_malta.py")), \
                 patch.object(RUNNER.shutil, "which", return_value="available"), \
                 patch.object(RUNNER.subprocess, "run") as create, \
                 patch.object(RUNNER.subprocess, "Popen", return_value=process) as launch, \
                 patch("sys.argv", ["runner", "--kernel", str(assets[0]), "--system-disk", str(assets[1]),
                                    "--vendor-disk", str(assets[2]), "--timeout", "1"]):
                self.assertEqual(RUNNER.main(), 124)
            self.assertEqual(create.call_count, 2)
            process.terminate.assert_called_once()
            self.assertIn("none", launch.call_args.args[0])
            self.assertEqual(list((environment / "runs").iterdir()), [])
            self.assertEqual(len(list((root / "reports/emulation").glob("*/command.json"))), 1)
            self.assertTrue(all(asset.read_bytes() == b"unchanged" for asset in assets))

    def test_missing_assets_do_not_launch(self):
        with patch("sys.argv", ["runner", "--kernel", "/nonexistent/oob-kernel", "--system-disk", "missing",
                                "--vendor-disk", "missing"]), \
             patch.object(RUNNER.subprocess, "Popen") as launch:
            with self.assertRaises(SystemExit):
                RUNNER.main()
            launch.assert_not_called()
