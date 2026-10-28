"""Read-only readiness checks; never build, boot or execute firmware."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main():
    root = Path(__file__).resolve().parents[1]
    config = json.loads((root / "configs/buildroot.json").read_text())
    archive = root / "downloads" / ("buildroot-" + config["version"] + ".tar.xz")
    source = root / "sources" / ("buildroot-" + config["version"])
    failures = []
    for command in ("make", "gcc", "g++", "git", "wget", "curl", "rsync", "cpio",
                    "unzip", "bc", "file", "patch", "perl", "python3", "flex", "bison",
                    "tar", "xz", "qemu-img", "qemu-mips", "qemu-system-mips"):
        if not shutil.which(command):
            failures.append("Missing command: " + command)
    for package in ("libncurses-dev", "libssl-dev"):
        result = subprocess.run(["dpkg-query", "-W", "-f=${Status}", package],
                                capture_output=True, text=True, check=False)
        if result.returncode or result.stdout != "install ok installed":
            failures.append("Missing package: " + package)
    if not archive.is_file() or hashlib.sha256(archive.read_bytes()).hexdigest() != config["sha256"]:
        failures.append("Source archive missing or SHA256 mismatch")
    if not (source / "configs" / config["candidate_defconfig"]).is_file():
        failures.append("Source tree or candidate defconfig missing")
    print("\n".join(failures) if failures else "Preparation checks passed; no build or emulation performed.")
    baseline = root / "images/mips32-be-malta"
    present = all((baseline / name).is_file() for name in ("vmlinux", "rootfs.ext2"))
    print("Kernel/disk assets: " + ("present; consult local validation record" if present else "not built/downloaded"))
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
