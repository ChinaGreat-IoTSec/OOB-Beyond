"""Run a bounded Malta console session using disposable disk overlays."""

import argparse
import ipaddress
import json
import re
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--system-disk", required=True, type=Path)
    parser.add_argument("--vendor-disk", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--network", choices=("none", "local", "tap"), default="none")
    parser.add_argument("--tap-ifname", default="oobtap0", help="Existing TAP owned by the current user")
    parser.add_argument("--bind-address", type=ipaddress.IPv4Address, default="127.0.0.1",
                        help="Host IPv4 address for local network forwards (default: 127.0.0.1)")
    parser.add_argument("--http-port", type=int, default=18080)
    parser.add_argument("--https-port", type=int, default=18443)
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("timeout must be positive")
    if args.network == "tap":
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,15}", args.tap_ifname):
            parser.error("TAP name must contain 1–15 letters, digits, underscores or hyphens")
        try:
            flags = int((Path("/sys/class/net") / args.tap_ifname / "tun_flags").read_text().strip(), 0)
        except (OSError, ValueError):
            parser.error("TAP is unavailable; create it with ip tuntap and assign it to your user first")
        if not flags & 0x2:
            parser.error("Selected interface is not a TAP device")
    if args.network == "local":
        if not all(1024 <= port <= 65535 for port in (args.http_port, args.https_port)):
            parser.error("forwarded ports must be between 1024 and 65535")
        if args.http_port == args.https_port:
            parser.error("HTTP and HTTPS host ports must differ")
    for path in (args.kernel, args.system_disk, args.vendor_disk):
        if not path.is_file():
            parser.error("Missing asset: " + str(path))
    for executable in ("qemu-img", "qemu-system-mips"):
        if not shutil.which(executable):
            parser.error("Missing executable: " + executable)
    root = Path(__file__).resolve().parents[1]
    runs = root / "runs"
    runs.mkdir(exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="malta-", dir=runs))
    reports = root.parent / "reports" / "emulation" / run.name
    reports.mkdir(parents=True)
    overlays = []
    process = None
    try:
        for name, source in (("system", args.system_disk), ("vendor", args.vendor_disk)):
            overlay = run / (name + ".qcow2")
            overlays.append(overlay)
            subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "raw",
                            "-b", str(source.resolve()), str(overlay)], check=True)
        command = [
            "qemu-system-mips", "-M", "malta", "-m", "256M",
            "-kernel", str(args.kernel.resolve()), "-display", "none", "-monitor", "chardev:console", "-no-reboot",
            "-chardev", "stdio,id=console,mux=on,signal=off,logfile=" + str(reports / "serial.log"),
            "-serial", "chardev:console",
            "-append", "rootwait root=/dev/sda console=ttyS0",
            "-drive", "file=" + str(overlays[0]) + ",format=qcow2,if=ide,index=0",
            "-drive", "file=" + str(overlays[1]) + ",format=qcow2,if=ide,index=1",
        ]
        if args.network == "local":
            command.extend([
                "-netdev", "user,id=localnet,restrict=on,"
                f"hostfwd=tcp:{args.bind_address}:{args.http_port}-10.0.2.15:80,"
                f"hostfwd=tcp:{args.bind_address}:{args.https_port}-10.0.2.15:443",
                "-device", "pcnet,netdev=localnet",
            ])
            print("After firmware startup: ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up", flush=True)
            print("Guest return route (if absent): route add default gw 10.0.2.2 dev eth0", flush=True)
            print(f"Browser: https://{args.bind_address}:{args.https_port}/ (guest outbound network restricted)", flush=True)
        elif args.network == "tap":
            command.extend([
                "-netdev", f"tap,id=tapnet,ifname={args.tap_ifname},script=no,downscript=no",
                "-device", "pcnet,netdev=tapnet",
            ])
            print(f"Using existing TAP {args.tap_ifname}; host addresses and routing are managed separately", flush=True)
            print("After firmware startup: ifconfig eth0 192.168.100.2 netmask 255.255.255.0 up", flush=True)
            print("Example host TAP address: 192.168.100.1/24; direct guest URL: http://192.168.100.2/", flush=True)
        else:
            command.extend(["-nic", "none"])
        (reports / "command.json").write_text(json.dumps(command, indent=2) + "\n")
        print("Session:", run, f"(network={args.network}; disk changes discarded on exit)", flush=True)
        print("Evidence:", reports, flush=True)
        process = subprocess.Popen(command)
        return process.wait(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        print("Session timeout; stopping QEMU")
        return 124
    except KeyboardInterrupt:
        return 130
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for overlay in overlays:
            overlay.unlink(missing_ok=True)
        run.rmdir()


if __name__ == "__main__":
    raise SystemExit(main())
