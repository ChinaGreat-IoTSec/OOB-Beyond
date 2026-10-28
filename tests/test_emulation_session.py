import base64
import json
from pathlib import Path
import tempfile
import unittest
from argparse import Namespace
from unittest.mock import MagicMock, patch

from emulation import session
from emulation.environment import backend


RUNTIME = backend({"architecture": "mips", "bits": 32, "endianness": "big", "abi": "o32",
                   "machine": "malta", "control": "linux-serial-ssh-v1"})


class SessionTests(unittest.TestCase):
    def test_resume_requires_supported_worker_and_queues_existing_session(self):
        with tempfile.TemporaryDirectory() as temporary:
            reports = Path(temporary)
            session_id = "emu-123456789abc"
            report = reports / session_id
            report.mkdir()
            session.save(report / "config.json", {"adapt": True})
            state = {"state": "WAITING_ADAPTATION", "resume_supported": True}
            with patch.object(session, "REPORTS", reports), patch.object(session, "status", return_value=state), \
                 patch.object(session.os, "geteuid", return_value=1000):
                self.assertEqual(session.main(["resume", session_id]), 0)
                self.assertTrue((report / "resume.request").exists())
                (report / "resume.request").unlink()
                state["resume_supported"] = False
                self.assertNotEqual(session.main(["resume", session_id]), 0)
                self.assertFalse((report / "resume.request").exists())

    def test_missing_guest_address_is_restored_after_ssh_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            guest = MagicMock()
            guest.execute.return_value = {"exit_code": 0, "output": "eth0 has no IPv4"}
            failed = Namespace(returncode=255, stdout="", stderr="Connection timed out")
            passed = Namespace(returncode=0, stdout="OOB_SSH_READY", stderr="")
            config = {"network": "tap", "profile": {"guest_ip_tap": "192.168.100.2", "netmask": "255.255.255.0"}}
            with patch.object(session.subprocess, "run", side_effect=[failed, passed]):
                result = session.check_access(guest, ["ssh", "guest"], config, Path(temporary), lambda: None)
            self.assertTrue(result["ssh_verified"])
            self.assertEqual(result["access_mode"], "ssh")
            guest.execute.assert_any_call("ifconfig eth0 192.168.100.2 netmask 255.255.255.0 up", timeout=10)
            evidence = json.loads((Path(temporary) / "access.json").read_text())
            self.assertIn("Connection timed out", evidence["initial_error"])
            with patch.object(session.subprocess, "run", return_value=passed):
                session.check_access(guest, ["ssh", "guest"], config, Path(temporary), lambda: None)
            events = [json.loads(line) for line in (Path(temporary) / "access-events.jsonl").read_text().splitlines()]
            self.assertEqual(len(events), 2)
            self.assertIn("repair", events[0])
            self.assertNotIn("repair", events[1])

    def test_ssh_timeout_preserves_console_without_rewriting_present_address(self):
        with tempfile.TemporaryDirectory() as temporary:
            guest = MagicMock()
            guest.execute.return_value = {"exit_code": 0, "output": "inet 192.168.100.2/24"}
            config = {"network": "tap", "profile": {"guest_ip_tap": "192.168.100.2", "netmask": "255.255.255.0"}}
            with patch.object(session.subprocess, "run", side_effect=session.subprocess.TimeoutExpired("ssh", 20)) as probe:
                result = session.check_access(guest, ["ssh", "guest"], config, Path(temporary), lambda: None)
            self.assertEqual(probe.call_count, 2)
            self.assertFalse(result["ssh_verified"])
            self.assertIsNone(result["ssh"])
            self.assertEqual(result["access_mode"], "console")
            self.assertIn("console", result["access_warning"])
            self.assertFalse(any("ifconfig" in call.args[0] for call in guest.execute.call_args_list))

    def test_tap_rejects_host_forwarding_options_before_start(self):
        with self.assertRaisesRegex(ValueError, "direct guest access"):
            session.prepare(Namespace(network="tap", http_port=18080, https_port=None, ssh_port=None))

    def test_session_ids_cannot_escape_report_directory(self):
        for value in ("../secret", "emu-abc", "/tmp/test"):
            with self.assertRaises(ValueError):
                session.directory(value)

    def test_tap_has_no_forwarding_and_separate_consoles(self):
        config = {"profile": {"kernel": "kernel", "runtime": RUNTIME}, "network": "tap", "tap_ifname": "oobtap0"}
        command = session.qemu_command(config, Path("/tmp/run"), Path("/tmp/report"))
        self.assertEqual(command[command.index("-netdev") + 1],
                         "tap,id=net,ifname=oobtap0,script=no,downscript=no")
        self.assertFalse(any("hostfwd" in value for value in command))
        self.assertIn("chardev:user", command)
        self.assertIn("chardev:control", command)

    def test_local_ssh_is_loopback_only_and_distinct_from_vendor_ports(self):
        config = {"profile": {"kernel": "kernel", "runtime": RUNTIME}, "network": "local", "http_port": 18080,
                  "https_port": 18443, "ssh_port": 12222}
        command = session.qemu_command(config, Path("/tmp/run"), Path("/tmp/report"))
        network = command[command.index("-netdev") + 1]
        self.assertIn("restrict=on", network)
        self.assertIn("hostfwd=tcp:127.0.0.1:12222-10.0.2.15:2222", network)

    def test_guest_execution_returns_real_exit_code_and_records_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            channel = MagicMock()
            def reply(_):
                payload = channel.sendall.call_args.args[0].decode().split()[2]
                script = base64.b64decode(payload).decode()
                token = script.split("OOB_DONE_")[1].split(":")[0]
                return ("command failed\r\nOOB_DONE_" + token + ":7\r\n").encode()
            channel.recv.side_effect = reply
            guest = session.Guest(channel, Path(temporary), lambda: None)
            result = guest.execute("false")
            self.assertEqual(result["exit_code"], 7)
            record = json.loads((Path(temporary) / "actions.jsonl").read_text())
            self.assertEqual(record["command"], "false")

    def test_guest_disconnect_is_not_success(self):
        channel = MagicMock()
        channel.recv.return_value = b""
        guest = session.Guest(channel, Path("/tmp"), lambda: None)
        with self.assertRaises(RuntimeError):
            guest.until(b"ready", 1)

    def test_script_upload_is_chunked_and_failure_stops_transfer(self):
        guest = session.Guest(MagicMock(), Path("/tmp"), lambda: None)
        with patch.object(guest, "execute", return_value={"exit_code": 0}) as execute:
            guest.upload_script("echo sample\n" * 200)
            chunks = [call.args[0].split()[2] for call in execute.call_args_list[1:-1]]
            self.assertTrue(all(len(chunk) <= 512 for chunk in chunks))
            self.assertEqual(base64.b64decode("".join(chunks)).decode(), "echo sample\n" * 200)
        with patch.object(guest, "execute", return_value={"exit_code": 1}):
            with self.assertRaises(RuntimeError):
                guest.upload_script("exit 1")

    def test_failed_start_cleans_only_its_run_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reports = root / "reports"
            runs = root / "runs"
            session_id = "emu-123456789abc"
            report = reports / session_id
            report.mkdir(parents=True)
            runs.mkdir()
            unrelated = runs / "unrelated"
            unrelated.mkdir()
            (unrelated / "base").write_bytes(b"keep")
            session.save(report / "config.json", {"timeout": 600, "network": "local"})
            session.save(report / "status.json", {"state": "STARTING", "created": 0})
            with patch.object(session, "REPORTS", reports), patch.object(session, "RUNS", runs), \
                 patch.object(session.subprocess, "run", side_effect=OSError("fixture failure")):
                session.worker(session_id)
            state = json.loads((report / "status.json").read_text())
            self.assertTrue(state["cleaned"])
            self.assertIn(state["state"], session.TERMINAL)
            self.assertFalse((runs / session_id).exists())
            self.assertEqual((unrelated / "base").read_bytes(), b"keep")

    def test_ssh_uses_pinned_per_session_host_key(self):
        command = session.connection(Path("/tmp/evidence"), {"network": "tap"}, "192.168.100.2")
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("ServerAliveInterval=5", command)
        self.assertIn("ServerAliveCountMax=2", command)
        self.assertIn("2222", command)
        self.assertEqual(command[-1], "root@192.168.100.2")


if __name__ == "__main__":
    unittest.main()
