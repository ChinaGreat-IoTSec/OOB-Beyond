"""Persistent emulation sessions using local adapters and reusable environments."""

import argparse
import base64
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import select
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import termios
import time
import tty
import uuid

if __package__:
    from .environment import resolve
else:
    from environment import resolve


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports/emulation"
RUNS = ROOT / "emulation/runs"
TERMINAL = {"STOPPED", "FAILED", "EXPIRED"}


def save(path, data):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    temporary.replace(path)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def directory(session_id):
    if not re.fullmatch(r"emu-[0-9a-f]{12}", session_id):
        raise ValueError("Invalid session ID")
    return REPORTS / session_id


def status(session_id):
    report = directory(session_id)
    state = json.loads((report / "status.json").read_text())
    if state["state"] not in TERMINAL:
        try:
            descriptor = os.open(report / "owner.lock", os.O_RDWR)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if time.time() - state["created"] > 10:
                    state["state"] = "ORPHANED"
                    state["error"] = "Worker is not holding its lock; inspect processes before cleaning resources"
            finally:
                os.close(descriptor)
        except BlockingIOError:
            pass
        except FileNotFoundError:
            state["state"] = "ORPHANED"
            state["error"] = "Worker lock is missing; inspect the session before cleanup"
    return state


def prepare(args):
    if args.network == "tap" and any(port is not None for port in (args.http_port, args.https_port, args.ssh_port)):
        raise ValueError("TAP uses direct guest access; host port forwarding options only apply to local mode")
    if not args.firmware or not args.firmware.is_file():
        raise ValueError("Provide an existing firmware file")
    plan = prepare_inputs(args)
    if plan["state"] != "PREPARED":
        raise ValueError(json.dumps(plan, ensure_ascii=False, indent=2))
    profile = plan["profile"]
    for program in ("qemu-img", profile["runtime"]["executable"], "ssh-keygen", "ssh"):
        if not shutil.which(program):
            raise ValueError("Missing executable: " + program)
    if args.network == "tap":
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", args.tap_ifname):
            raise ValueError("Invalid TAP name")
        flags = int((Path("/sys/class/net") / args.tap_ifname / "tun_flags").read_text().strip(), 0)
        if not flags & 2:
            raise ValueError("Interface is not TAP")
    args.http_port = args.http_port if args.http_port is not None else 18080
    args.https_port = args.https_port if args.https_port is not None else 18443
    args.ssh_port = args.ssh_port if args.ssh_port is not None else 12222
    ports = (args.http_port, args.https_port, args.ssh_port)
    if any(not 1024 <= port <= 65535 for port in ports) or len(set(ports)) != 3:
        raise ValueError("Host ports must be distinct and between 1024 and 65535")
    if args.timeout < 60:
        raise ValueError("Session lifetime must be at least 60 seconds")
    return profile


def prepare_inputs(args):
    plan = resolve(args.firmware, getattr(args, "adapter", None))
    if plan["state"] == "NEEDS_ADAPTER" or getattr(args, "rootfs", None) or getattr(args, "service", None):
        from emulation.preparation import prepare_firmware
        print("Preparing firmware: extracting/checking rootfs and local disk cache...", file=sys.stderr, flush=True)
        plan = prepare_firmware(args.firmware, args.rootfs, args.service, args.service_arg, args.http_guest_port,
                                bootstrap=getattr(args, "adapt", False))
    if plan["state"] == "NEEDS_ENVIRONMENT":
        from emulation.build import prepare_environment
        result = prepare_environment(plan["requirements"], args.build_environment, args.build_timeout, args.jobs)
        if result["state"] != "ENVIRONMENT_AVAILABLE":
            return {**plan, **result}
        plan = resolve(args.firmware, plan["adapter_path"])
    if plan.get("adapter_path"):
        args.adapter = plan["adapter_path"]
    return plan


def start(args):
    profile = prepare(args)
    session_id = "emu-" + uuid.uuid4().hex[:12]
    report = directory(session_id)
    report.mkdir(parents=True, mode=0o700)
    os.chmod(report, 0o700)
    (report / "owner.lock").touch()
    configuration = dict(vars(args))
    configuration["firmware"] = str(args.firmware.resolve())
    configuration["profile"] = profile
    save(report / "config.json", configuration)
    save(report / "status.json", {"session_id": session_id, "state": "STARTING", "created": time.time(),
                                  "evidence": str(report), "limitations": profile["limitations"]})
    with (report / "worker.log").open("ab") as log:
        subprocess.Popen([sys.executable, "-m", "emulation.session", "--worker", session_id],
                         stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True, cwd=ROOT)
    return status(session_id)


class Guest:
    def __init__(self, channel, report, check):
        self.channel = channel
        self.report = report
        self.check = check
        self.channel.settimeout(0.25)

    def until(self, marker, timeout):
        deadline = time.monotonic() + timeout
        received = bytearray()
        while time.monotonic() < deadline:
            self.check()
            try:
                chunk = self.channel.recv(8192)
            except socket.timeout:
                continue
            if not chunk:
                raise RuntimeError("Guest control channel closed")
            with (self.report / "control.log").open("ab") as log:
                log.write(chunk)
            received.extend(chunk)
            if len(received) > 1024 * 1024:
                raise RuntimeError("Guest output exceeded 1 MiB; full stream retained in control.log")
            if marker in received:
                return bytes(received)
        raise TimeoutError("Guest response timed out")

    def execute(self, command, timeout=90):
        token = "OOB_DONE_" + uuid.uuid4().hex
        script = command + "\noob_result=$?\nprintf '\\n" + token + ":%s\\n' \"$oob_result\"\n"
        encoded = base64.b64encode(script.encode()).decode()
        self.channel.sendall(f"printf %s {encoded} | base64 -d > /tmp/oob-command.sh; sh /tmp/oob-command.sh\n".encode())
        output = self.until((token + ":").encode(), timeout)
        while not re.search(re.escape(token).encode() + rb":\d+\r?\n", output):
            output += self.until(b"\n", 5)
        match = re.search(re.escape(token).encode() + rb":(\d+)", output)
        result = {"exit_code": int(match.group(1)), "output": output.split(token.encode())[0].decode(errors="replace")}
        with (self.report / "actions.jsonl").open("a") as log:
            log.write(json.dumps({"time": time.time(), "command": command, **result}) + "\n")
        return result

    def upload_script(self, script):
        encoded = base64.b64encode(script.encode()).decode()
        if self.execute(": > /tmp/oob-adapter.b64")["exit_code"]:
            raise RuntimeError("Cannot initialize guest adapter transfer")
        for offset in range(0, len(encoded), 512):
            if self.execute(f"printf %s {encoded[offset:offset + 512]} >> /tmp/oob-adapter.b64")["exit_code"]:
                raise RuntimeError("Guest adapter transfer failed")
        if self.execute("base64 -d /tmp/oob-adapter.b64 > /tmp/oob-adapter.sh")["exit_code"]:
            raise RuntimeError("Guest adapter decoding failed")


def qemu_command(config, run, report):
    profile = config["profile"]
    runtime = profile["runtime"]
    command = [runtime["executable"], "-M", runtime["machine"], "-m", runtime["memory"], "-display", "none", "-monitor", "none",
               "-no-reboot", "-kernel", str(ROOT / profile["kernel"]),
               "-append", runtime["append"],
               "-chardev", f"socket,id=user,path={run / 'console.sock'},server=on,wait=off,logfile={report / 'serial.log'}",
               "-serial", "chardev:user", "-chardev",
               f"socket,id=control,path={run / 'guest.sock'},server=on,wait=on", "-serial", "chardev:control"]
    for index, name in enumerate(("system", "vendor")):
        command.extend(["-drive", f"file={run / (name + '.qcow2')},format=qcow2,if=ide,index={index}"])
    if config["network"] == "tap":
        network = f"tap,id=net,ifname={config['tap_ifname']},script=no,downscript=no"
    else:
        network = "user,id=net,restrict=on"
        for key, guest_port in (("http_port", (profile.get("http_probe") or {}).get("port")),
                                ("https_port", profile.get("https_port")), ("ssh_port", 2222)):
            if guest_port is None:
                continue
            network += f",hostfwd=tcp:127.0.0.1:{config[key]}-10.0.2.15:{guest_port}"
    return command + ["-netdev", network, "-device", runtime["nic"] + ",netdev=net"]


def connection(report, config, guest_ip):
    host = guest_ip if config["network"] == "tap" else "127.0.0.1"
    port = 2222 if config["network"] == "tap" else config["ssh_port"]
    return ["ssh", "-i", str(report / "id_ed25519"), "-p", str(port), "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2", "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=" + str(report / "known_hosts"), "root@" + host]


def check_access(guest, ssh, config, report, check):
    def probe():
        check()
        try:
            result = subprocess.run(ssh + ["printf OOB_SSH_READY"], capture_output=True, text=True, timeout=20)
            output = result.stdout + result.stderr
            verified = result.returncode == 0 and "OOB_SSH_READY" in result.stdout
        except (OSError, subprocess.TimeoutExpired) as error:
            output = str(error)
            verified = False
        (report / "ssh-check.log").write_text(output)
        return verified, output[-2000:]

    verified, error = probe()
    evidence = {"ssh_verified": verified, "initial_error": error if not verified else None}
    if not verified:
        diagnostic = guest.execute("ip -4 addr show dev eth0; ip route; netstat -lnt; pidof dropbear", timeout=15)
        evidence["diagnostic"] = diagnostic
        address = config["profile"]["guest_ip_" + config["network"]]
        addresses = guest.execute("ip -4 addr show dev eth0", timeout=10)
        if addresses["exit_code"] == 0 and not re.search(r"\binet " + re.escape(address) + r"/", addresses["output"]):
            command = f"ifconfig eth0 {address} netmask {config['profile']['netmask']} up"
            evidence["repair"] = guest.execute(command, timeout=10)
        verified, error = probe()
    evidence.update(ssh_verified=verified, error=error if not verified else None)
    save(report / "access.json", evidence)
    with (report / "access-events.jsonl").open("a") as stream:
        stream.write(json.dumps({"time": time.time(), **evidence}, ensure_ascii=False) + "\n")
    return {"ssh_verified": verified, "ssh": shlex.join(ssh) if verified else None,
            "access_mode": "ssh" if verified else "console",
            "access_warning": None if verified else "SSH unavailable; use console or emulate exec over the independent serial channel. See access.json and ssh-check.log.",
            "access_error": error if not verified else None}


def worker(session_id):
    os.umask(0o077)
    report = directory(session_id)
    config = json.loads((report / "config.json").read_text())
    state = json.loads((report / "status.json").read_text())
    run = RUNS / session_id
    process = None
    owner = (report / "owner.lock").open("a")
    try:
        fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        owner.close()
        return
    locks = [owner]
    channel = None
    server = None
    expiry = state["created"] + config["timeout"]

    def update(**changes):
        state.update(changes)
        state["updated"] = time.time()
        save(report / "status.json", state)

    def check():
        if (report / "stop.request").exists():
            raise InterruptedError("User requested stop")
        if time.time() >= expiry:
            raise TimeoutError("Session lifetime expired")
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"QEMU exited with code {process.returncode}; inspect qemu.log")

    try:
        RUNS.mkdir(parents=True, exist_ok=True)
        for path in ([RUNS / (config["tap_ifname"] + ".lock")] if config["network"] == "tap" else []):
            lock = path.open("a")
            locks.append(lock)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run.mkdir(mode=0o700)
        if len(str(run / "console.sock").encode()) >= 104:
            raise ValueError("Workspace path too long for UNIX sockets; use a shorter workspace path")
        update(worker_pid=os.getpid(), expires=expiry, state="BOOTING", resume_supported=bool(config.get("adapt")))
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(report / "id_ed25519")], check=True)
        for name, expected in config["profile"]["asset_hashes"].items():
            if digest(Path(config["profile"][name])) != expected:
                raise ValueError("Asset changed after preparation: " + name)
        for name, source in (("system", "system_disk"), ("vendor", "vendor_disk")):
            subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b",
                            str(ROOT / config["profile"][source]), str(run / (name + ".qcow2"))], check=True)
        command = qemu_command(config, run, report)
        save(report / "command.json", command)
        with (report / "qemu.log").open("ab") as log:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        update(qemu_pid=process.pid, console=f"python3 main.py emulate console {session_id}")
        deadline = time.monotonic() + 30
        channel = socket.socket(socket.AF_UNIX)
        while True:
            check()
            try:
                channel.connect(str(run / "guest.sock"))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    raise TimeoutError("QEMU control socket unavailable")
                time.sleep(0.1)
        guest = Guest(channel, report, check)
        guest.until(b"login:", 120)
        channel.sendall(b"root\n")
        guest.until(b"#", 20)
        channel.sendall(b"stty -echo\n")
        update(state="INITIALIZING")
        public_key = (report / "id_ed25519.pub").read_text().strip()
        setup = guest.execute("mkdir -p /root/.ssh; chmod 700 /root/.ssh; printf '%s\\n' " + shlex.quote(public_key) +
                              " > /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys; command -v dropbear")
        if setup["exit_code"]:
            raise RuntimeError("SSH missing; rebuild the session-capable Buildroot baseline")
        guest.upload_script(config["profile"]["startup_script"])
        result = guest.execute("sh /tmp/oob-adapter.sh", 90)
        startup_ok = result["exit_code"] == 0
        guest_ip = config["profile"]["guest_ip_" + config["network"]]
        network = f"ifconfig eth0 {guest_ip} netmask {config['profile']['netmask']} up"
        if config["network"] == "local":
            network += "; route add default gw 10.0.2.2 dev eth0"
        result = guest.execute(network)
        if result["exit_code"]:
            raise RuntimeError("Guest network setup failed")
        hostkey = guest.execute("dropbearkey -y -f /etc/dropbear/dropbear_ed25519_host_key")
        key = re.search(r"^ssh-ed25519 [A-Za-z0-9+/=]+", hostkey["output"], re.MULTILINE)
        if not key:
            generated = guest.execute("dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key")
            key = re.search(r"^ssh-ed25519 [A-Za-z0-9+/=]+", generated["output"], re.MULTILINE)
        if not key:
            raise RuntimeError("Could not obtain guest SSH host key over control channel")
        host = guest_ip if config["network"] == "tap" else "127.0.0.1"
        port = 2222 if config["network"] == "tap" else config["ssh_port"]
        (report / "known_hosts").write_text(f"[{host}]:{port} {key.group(0)}\n")
        ssh = connection(report, config, guest_ip)
        access = check_access(guest, ssh, config, report, check)
        update(state="WAITING_ADAPTATION", guest_ip=guest_ip, **access,
               next_steps=[f"python3 main.py emulate console {session_id}",
                           f'python3 main.py emulate exec {session_id} --command "ip addr; ip route; netstat -lnt"'] +
                          ([f"python3 main.py emulate resume {session_id} (when waiting/degraded)"] if config.get("adapt") else []),
               stop=f"python3 main.py emulate stop {session_id}")
        adaptation_result = None
        if config.get("adapt"):
            from emulation.adaptation import adapt
            adaptation_result = adapt(guest, config, report, check, update)
            access = check_access(guest, ssh, config, report, check)
        probe = config["profile"].get("http_probe")
        http_url = None
        evidence = {"status": None}
        http_ok = True
        if probe:
            http_port = probe["port"] if config["network"] == "tap" else config["http_port"]
            http_connection = http.client.HTTPConnection(host, http_port, timeout=10)
            try:
                http_connection.request("GET", probe["path"])
                response = http_connection.getresponse()
                evidence = {"status": response.status, "headers": response.getheaders(),
                            "body_prefix": response.read(4096).decode(errors="replace")}
                save(report / "http.json", evidence)
                http_url = f"http://{host}:{http_port}{probe['path']}"
            except (OSError, http.client.HTTPException) as error:
                http_ok = False
                save(report / "http.json", {"error": str(error)})
            finally:
                http_connection.close()
        server = socket.socket(socket.AF_UNIX)
        server.bind(str(run / "execute.sock"))
        server.listen(1)
        server.settimeout(0.25)
        service_ok = (adaptation_result["success"] if adaptation_result else
                      startup_ok and not config["profile"].get("adaptation_required", False))
        update(state="READY" if service_ok and http_ok else "WAITING_ADAPTATION",
               adaptation=adaptation_result, guest_ip=guest_ip, **access, http=http_url,
               http_status=evidence["status"],
               stop=f"python3 main.py emulate stop {session_id}")
        next_health = time.monotonic() + 10
        next_access = time.monotonic() + 30
        while True:
            check()
            if (report / "resume.request").exists():
                (report / "resume.request").unlink()
                from emulation.adaptation import adapt
                config["_adapt_rounds_used"] = 0
                config["_adapt_deadline"] = time.monotonic() + config["adapt_timeout"]
                config.setdefault("_adapt_history", []).append({"resume": "User requested continuation. Inspect current processes before starting anything; do not duplicate services."})
                recovered = adapt(guest, config, report, check, update)
                access = check_access(guest, ssh, config, report, check)
                update(state="READY" if recovered["success"] and http_ok else "WAITING_ADAPTATION",
                       adaptation=recovered, **access)
                next_health = time.monotonic() + 10
            if time.monotonic() >= next_access:
                update(**check_access(guest, ssh, config, report, check))
                next_access = time.monotonic() + 30
            if state["state"] == "READY" and config.get("adapt") and time.monotonic() >= next_health:
                from emulation.adaptation import health, append_event
                measurement = health(guest, config["expect_process"], config["expect_port"])
                append_event(report, "health.jsonl", {"time": time.time(), **measurement})
                if not measurement["ok"]:
                    update(state="DEGRADED", health_failures=measurement["failures"])
                    if (config.get("_adapt_rounds_used", 0) < config["adapt_rounds"] and
                            time.monotonic() < config.get("_adapt_deadline", 0)):
                        from emulation.adaptation import adapt
                        config.setdefault("_adapt_history", []).append({"health_regression": measurement})
                        recovered = adapt(guest, config, report, check, update)
                        access = check_access(guest, ssh, config, report, check)
                        update(state="READY" if recovered["success"] and http_ok else "WAITING_ADAPTATION",
                               adaptation=recovered, **access,
                               health_failures=[] if recovered["success"] else measurement["failures"])
                next_health = time.monotonic() + 10
            try:
                client, _ = server.accept()
            except socket.timeout:
                continue
            with client:
                client.settimeout(5)
                payload = b""
                while b"\n" not in payload:
                    chunk = client.recv(4096)
                    if not chunk or len(payload) + len(chunk) > 65536:
                        break
                    payload += chunk
                try:
                    request = json.loads(payload)
                    timeout = min(120, max(1, int(request.get("timeout", 30))))
                    result = guest.execute(str(request["command"]), timeout)
                except (ValueError, KeyError, TypeError) as error:
                    result = {"error": str(error)}
                client.sendall(json.dumps(result).encode() + b"\n")
    except InterruptedError:
        update(state="STOPPING")
    except Exception as error:
        update(state="EXPIRED" if time.time() >= expiry else "FAILED", error=str(error))
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for stream in (channel, server):
            if stream is not None:
                stream.close()
        if run.exists():
            shutil.rmtree(run)
        (report / "id_ed25519").unlink(missing_ok=True)
        update(state=state["state"] if state["state"] in TERMINAL else "STOPPED", cleaned=True,
               ssh=None, console=None, ssh_verified=False, access_mode=None, next_steps=[])
        for lock in locks:
            lock.close()


def attach(session_id):
    state = status(session_id)
    if state["state"] in TERMINAL or state["state"] == "ORPHANED":
        raise ValueError("Session is not running")
    if not sys.stdin.isatty():
        raise ValueError("Console attachment requires an interactive terminal")
    with socket.socket(socket.AF_UNIX) as channel:
        channel.connect(str(RUNS / session_id / "console.sock"))
        print("Console: press Enter for prompt; log in as root. Ctrl+] detaches without stopping QEMU.", flush=True)
        previous = termios.tcgetattr(sys.stdin)
        try:
            tty.setraw(sys.stdin.fileno())
            while True:
                readable, _, _ = select.select([channel, sys.stdin], [], [])
                if channel in readable:
                    output = channel.recv(8192)
                    if not output:
                        break
                    sys.stdout.buffer.write(output)
                    sys.stdout.buffer.flush()
                if sys.stdin in readable:
                    data = os.read(sys.stdin.fileno(), 1024)
                    if not data or b"\x1d" in data:
                        break
                    channel.sendall(data)
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, previous)


def main(argv=None):
    if os.geteuid() == 0:
        if not os.environ.get("SUDO_UID") or int(os.environ["SUDO_UID"]) == 0:
            raise SystemExit("Run as an ordinary user or via sudo from an ordinary account")
        account = pwd.getpwuid(int(os.environ["SUDO_UID"]))
        os.initgroups(account.pw_name, account.pw_gid)
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="Firmware path, or status/list/stop/console/exec/resume")
    parser.add_argument("session", nargs="?")
    parser.add_argument("--network", choices=("local", "tap"), default="local")
    parser.add_argument("--tap-ifname", default="oobtap0")
    parser.add_argument("--http-port", type=int, help="Local forwarding only; default 18080")
    parser.add_argument("--https-port", type=int, help="Local forwarding only; default 18443")
    parser.add_argument("--ssh-port", type=int, help="Local forwarding only; default 12222")
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--command", help="Guest shell command for exec; maximum execution time 120 seconds")
    parser.add_argument("--adapter", help="Trusted local adapter JSON; otherwise discover by input hash")
    parser.add_argument("--plan", action="store_true", help="Inspect requirements and reusable local assets without launching")
    parser.add_argument("--prepare", action="store_true", help="Extract firmware, inspect rootfs and prepare assets without booting")
    parser.add_argument("--rootfs", help="Use an existing extracted root filesystem")
    parser.add_argument("--service", help="Explicit executable path inside the guest rootfs")
    parser.add_argument("--service-arg", action="append", default=[], help="One service argument; repeat as needed")
    parser.add_argument("--http-guest-port", type=int, help="Optional HTTP probe port inside guest")
    parser.add_argument("--build-environment", action="store_true", help="Allow on-demand Buildroot source download/build if local environment is missing")
    parser.add_argument("--build-timeout", type=int, default=3600)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--adapt", action="store_true", help="Use the configured LLM to adapt a running guest")
    parser.add_argument("--goal", default="", help="Natural-language emulation objective")
    parser.add_argument("--expect-process", action="append", default=[], help="Required guest process; repeat for multiple processes")
    parser.add_argument("--expect-port", action="append", type=int, default=[], help="Required guest TCP listener; repeat as needed")
    parser.add_argument("--adapt-rounds", type=int, default=12)
    parser.add_argument("--adapt-timeout", type=int, default=600)
    parser.add_argument("--observe-seconds", type=int, default=60)
    args = parser.parse_args(argv)
    try:
        if args.adapt:
            from agent.llm import load_env_file
            load_env_file(ROOT / ".env")
            if not args.goal.strip() or not (args.expect_process or args.expect_port):
                raise ValueError("--adapt requires --goal and at least one --expect-process or --expect-port acceptance check")
            if any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name) for name in args.expect_process):
                raise ValueError("Invalid expected process name")
            if any(not 1 <= port <= 65535 for port in args.expect_port):
                raise ValueError("Invalid expected TCP port")
            if not 1 <= args.adapt_rounds <= 40 or not 30 <= args.adapt_timeout <= 3600 or not 5 <= args.observe_seconds <= 120:
                raise ValueError("Adaptation limits: 1–40 rounds, 30–3600 seconds, observation window 5–120 seconds")
            if not args.plan and not args.prepare and not os.getenv("OPENAI_API_KEY"):
                raise ValueError("OPENAI_API_KEY missing from existing .env/environment")
        if args.target == "list":
            result = [status(path.name) for path in sorted(REPORTS.glob("emu-*")) if (path / "status.json").exists()]
        elif args.target in {"status", "stop", "console", "exec", "resume"}:
            if not args.session:
                raise ValueError("Session ID required")
            result = status(args.session)
            if args.target == "resume":
                config = json.loads((directory(args.session) / "config.json").read_text())
                if not result.get("resume_supported"):
                    raise ValueError("This worker does not support resume; start a new session with updated code")
                if not config.get("adapt") or result["state"] not in {"WAITING_ADAPTATION", "DEGRADED"}:
                    raise ValueError("resume requires a waiting/degraded LLM adaptation session")
                (directory(args.session) / "resume.request").touch()
                result = {**result, "resume_requested": True}
            elif args.target == "stop" and result["state"] not in TERMINAL:
                if result["state"] == "ORPHANED":
                    raise ValueError("Orphaned worker; inspect processes manually before cleanup")
                (directory(args.session) / "stop.request").touch()
                deadline = time.monotonic() + 40
                while time.monotonic() < deadline:
                    result = status(args.session)
                    if result["state"] in TERMINAL and result.get("cleaned"):
                        break
                    time.sleep(0.25)
            elif args.target == "console":
                attach(args.session)
                return 0
            elif args.target == "exec":
                if result["state"] not in {"READY", "WAITING_ADAPTATION", "DEGRADED"} or not args.command:
                    raise ValueError("exec requires a ready/debuggable session and --command")
                with socket.socket(socket.AF_UNIX) as channel:
                    channel.settimeout(135)
                    channel.connect(str(RUNS / args.session / "execute.sock"))
                    channel.sendall(json.dumps({"command": args.command, "timeout": min(args.timeout, 120)}).encode() + b"\n")
                    with channel.makefile("r") as response:
                        result = json.loads(response.readline())
        else:
            args.firmware = Path(args.target).expanduser()
            if args.plan:
                result = resolve(args.firmware, args.adapter)
            elif args.prepare:
                result = prepare_inputs(args)
            else:
                result = start(args)
            if args.plan or args.prepare:
                result.pop("profile", None)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 1 if isinstance(result, dict) and (result.get("error") or result.get("exit_code", 0) or
                    result.get("state") in {"NEEDS_ADAPTER", "AMBIGUOUS_ADAPTER", "NEEDS_ENVIRONMENT", "UNSUPPORTED_BACKEND",
                                            "NEEDS_ROOTFS", "NEEDS_SERVICE", "NEEDS_DEPENDENCIES", "BUILD_FAILED"}) else 0
    except ImportError as error:
        print(f"Preparation dependencies missing ({error}); use venv/bin/python or install requirements.txt in your Python environment.", file=sys.stderr)
        return 1
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"Emulation error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        signal.signal(signal.SIGTERM, lambda *_: (directory(sys.argv[2]) / "stop.request").touch())
        signal.signal(signal.SIGINT, lambda *_: (directory(sys.argv[2]) / "stop.request").touch())
        worker(sys.argv[2])
    else:
        raise SystemExit(main())
