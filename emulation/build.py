"""On-demand Buildroot provider; only build the requested supported environment."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

from .environment import ROOT, LOCAL, asset, digest
from .preparation import write_json


def recipe(requirements, root=ROOT):
    supported = {"architecture": "mips", "endianness": "big", "bits": 32,
                 "abi": "o32", "machine": "malta", "control": "linux-serial-ssh-v1"}
    if requirements != supported:
        raise ValueError("No validated Buildroot recipe for these requirements; supply a compatible local environment")
    configuration = json.loads((root / "emulation/configs/buildroot.json").read_text())
    files = [root / "emulation/configs/mips32-be-malta_defconfig", root / "emulation/configs/malta-network.fragment"]
    files += [root / "emulation" / name for name in ("external.desc", "external.mk", "Config.in")
              if (root / "emulation" / name).is_file()]
    files += sorted(path for path in (root / "emulation/overlay").rglob("*") if path.is_file())
    fingerprint = hashlib.sha256(json.dumps(configuration, sort_keys=True).encode())
    for path in files:
        fingerprint.update(path.relative_to(root).as_posix().encode())
        fingerprint.update(path.read_bytes())
        fingerprint.update(str(path.stat().st_mode & 0o777).encode())
    return configuration, "buildroot-" + configuration["version"] + "-" + fingerprint.hexdigest()[:16]


def prepare_environment(requirements, allow_build=False, timeout=3600, jobs=4, root=ROOT, local=LOCAL):
    configuration, identity = recipe(requirements, root)
    if not allow_build:
        return {"state": "NEEDS_ENVIRONMENT", "requirements": requirements, "recipe": identity,
                "next_steps": ["No compatible local environment. Retry with --build-environment to download/build only this recipe.",
                               "Builds may take significant time and disk space; accepted images are cached and reused."]}
    missing = [program for program in ("make", "gcc", "g++", "git", "wget", "rsync", "cpio", "unzip", "bc",
                                       "file", "patch", "perl", "tar", "xz", "flex", "bison") if not shutil.which(program)]
    if missing:
        return {"state": "NEEDS_DEPENDENCIES", "missing": missing, "next_steps": [
            "Install missing build dependencies, then repeat the same command.",
            "On Ubuntu: sudo apt install build-essential git wget rsync cpio unzip bc file patch perl xz-utils flex bison libncurses-dev libssl-dev"]}
    if timeout < 1 or not 1 <= jobs <= 32:
        raise ValueError("Build timeout must be positive and jobs between 1 and 32")
    local.mkdir(parents=True, exist_ok=True)
    with (local / "build.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        assets = root / "emulation/images" / identity
        registration = assets / "environment.json"
        if registration.exists():
            manifest = json.loads(registration.read_text())
            asset(manifest["kernel"], assets)
            asset(manifest["system_disk"], assets)
        else:
            if shutil.disk_usage(local).free < 12 * 1024 ** 3:
                raise ValueError("Buildroot preparation requires at least 12 GiB free space for build intermediates")
            downloads = root / "emulation/downloads"
            sources = root / "emulation/sources"
            downloads.mkdir(parents=True, exist_ok=True)
            sources.mkdir(parents=True, exist_ok=True)
            archive = downloads / ("buildroot-" + configuration["version"] + ".tar.xz")
            if not archive.exists():
                temporary = archive.with_suffix(".partial")
                try:
                    print("Downloading pinned Buildroot source...", flush=True)
                    with urllib.request.urlopen(configuration["source_url"], timeout=60) as response, temporary.open("wb") as output:
                        shutil.copyfileobj(response, output)
                    if digest(temporary) != configuration["sha256"]:
                        raise ValueError("Downloaded Buildroot checksum mismatch")
                    temporary.replace(archive)
                finally:
                    temporary.unlink(missing_ok=True)
            if digest(archive) != configuration["sha256"]:
                raise ValueError("Cached Buildroot checksum mismatch; remove or replace the corrupt archive before retrying")
            source = sources / ("buildroot-" + configuration["version"])
            if not (source / "Makefile").is_file():
                with tempfile.TemporaryDirectory(dir=sources) as staging:
                    with tarfile.open(archive) as bundle:
                        bundle.extractall(staging, filter="data")
                    if source.exists():
                        raise ValueError("Incomplete Buildroot source directory exists; move it aside before retrying")
                    (Path(staging) / source.name).replace(source)
            output = root / "emulation/output" / identity
            output.mkdir(parents=True, exist_ok=True)
            log = output / "build.log"
            environment = os.environ.copy()
            environment["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            command = ["make", "-C", str(source), "O=" + str(output), "BR2_EXTERNAL=" + str(root / "emulation"),
                       "BR2_DL_DIR=" + str(downloads)]
            print(f"Building {identity}; progress log: {log}", flush=True)
            with log.open("a") as stream:
                for arguments in (["BR2_DEFCONFIG=" + str(root / "emulation/configs/mips32-be-malta_defconfig"), "defconfig"], [f"-j{jobs}"]):
                    try:
                        process = subprocess.Popen(command + arguments, stdout=stream, stderr=subprocess.STDOUT,
                                                   env=environment, start_new_session=True)
                        try:
                            return_code = process.wait(timeout=timeout)
                        except BaseException:
                            import signal
                            os.killpg(process.pid, signal.SIGTERM)
                            try:
                                process.wait(timeout=10)
                            except subprocess.TimeoutExpired:
                                os.killpg(process.pid, signal.SIGKILL)
                                process.wait()
                            raise
                    except subprocess.TimeoutExpired:
                        return {"state": "BUILD_FAILED", "log": str(log), "next_steps": [
                            "Build timed out; intermediates are retained. Retry with a larger --build-timeout."]}
                    if return_code:
                        return {"state": "BUILD_FAILED", "log": str(log), "next_steps": [
                            "Inspect build.log for missing dependencies or network errors, then retry; intermediates are retained."]}
            assets.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=assets.parent) as staging:
                temporary_assets = Path(staging) / "accepted"
                temporary_assets.mkdir()
                for name in ("vmlinux", "rootfs.ext2"):
                    subprocess.run(["cp", "--sparse=always", str(output / "images" / name), str(temporary_assets / name)], check=True)
                manifest = {"schema_version": 1, "kind": "environment", "id": identity, "requirements": requirements,
                            "kernel": {"path": str(assets / "vmlinux"), "sha256": digest(temporary_assets / "vmlinux")},
                            "system_disk": {"path": str(assets / "rootfs.ext2"), "sha256": digest(temporary_assets / "rootfs.ext2")},
                            "validation": "built; guest startup validation pending"}
                write_json(temporary_assets / "environment.json", manifest)
                temporary_assets.replace(assets)
        registry = local / "environments"
        registry.mkdir(parents=True, exist_ok=True)
        write_json(registry / (identity + ".json"), manifest)
        return {"state": "ENVIRONMENT_AVAILABLE", "environment_id": identity,
                "next_steps": ["Image checksums recorded. Guest boot/service validation is performed at session startup."]}
