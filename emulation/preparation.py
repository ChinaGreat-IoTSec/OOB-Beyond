"""Prepare local firmware disks and adapters without running firmware on the host."""

import fcntl
import json
import os
import re
from pathlib import Path, PurePosixPath
import shlex
import shutil
import stat
import struct
import subprocess
import tempfile

from .environment import LOCAL, backend, digest, inspect_input, resolve


def write_json(path, data):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    temporary.replace(path)


def asset_name(source, identity):
    name = re.sub(r"[^\w.-]+", "_", Path(source).stem).strip("._") or "firmware"
    return f"{name[:60]}-{identity[:12]}"


def preparation_workspace(local, source, identity):
    prepared = local / "prepared"
    prepared.mkdir(parents=True, exist_ok=True)
    legacy = prepared / identity
    if legacy.is_dir():
        return legacy
    for candidate in sorted(prepared.iterdir()):
        marker = candidate / "identity.json"
        if marker.is_file() and json.loads(marker.read_text()).get("input_sha256") == identity:
            return candidate
    candidate = prepared / asset_name(source, identity)
    if candidate.exists():
        candidate = prepared / (asset_name(source, identity) + "-" + identity[12:])
    candidate.mkdir(parents=True, exist_ok=True)
    write_json(candidate / "identity.json", {"input_sha256": identity, "source_name": source.name})
    return candidate


def guest_path(root, value):
    pending = list(PurePosixPath(value).parts)
    resolved = []
    links = 0
    while pending:
        component = pending.pop(0)
        if component in ("/", ".", ""):
            continue
        if component == "..":
            if not resolved:
                raise ValueError("Guest path escapes rootfs")
            resolved.pop()
            continue
        candidate = root.joinpath(*resolved, component)
        if candidate.is_symlink():
            links += 1
            if links > 40:
                raise ValueError("Too many guest symlinks")
            target = os.readlink(candidate)
            if target.startswith("/"):
                resolved = []
            pending = list(PurePosixPath(target).parts) + pending
        else:
            resolved.append(component)
    return root.joinpath(*resolved)


def interpreter(path):
    with path.open("rb") as stream:
        header = stream.read(64)
        if len(header) < 52 or header[:4] != b"\x7fELF" or header[4] not in (1, 2) or header[5] not in (1, 2):
            raise ValueError("Not a supported ELF header")
        order = "<" if header[5] == 1 else ">"
        if header[4] == 1:
            offset = struct.unpack_from(order + "I", header, 28)[0]
            size, count = struct.unpack_from(order + "HH", header, 42)
            minimum = 32
        else:
            offset = struct.unpack_from(order + "Q", header, 32)[0]
            size, count = struct.unpack_from(order + "HH", header, 54)
            minimum = 56
        if count > 256 or (count and size < minimum) or offset + count * size > path.stat().st_size:
            raise ValueError("Invalid ELF program headers")
        for index in range(count):
            stream.seek(offset + index * size)
            entry = stream.read(size)
            if struct.unpack_from(order + "I", entry)[0] == 3:
                address = struct.unpack_from(order + ("I" if header[4] == 1 else "Q"), entry, 4 if header[4] == 1 else 8)[0]
                length = struct.unpack_from(order + ("I" if header[4] == 1 else "Q"), entry, 16 if header[4] == 1 else 32)[0]
                if not 1 <= length <= 4096 or address + length > path.stat().st_size:
                    raise ValueError("Invalid ELF interpreter extent")
                stream.seek(address)
                return stream.read(length).rstrip(b"\0").decode("utf-8")
    return None


def inspect_rootfs(root, service=None):
    executables = []
    for folder in ("bin", "sbin", "usr/bin", "usr/sbin"):
        directory = guest_path(root, folder)
        if not directory.is_dir():
            continue
        for candidate in sorted(directory.iterdir()):
            path = guest_path(root, candidate.relative_to(root).as_posix())
            if path.is_file() and not path.is_symlink() and path.stat().st_mode & 0o111:
                observed = inspect_input(path)
                if observed["format"] == "elf":
                    executables.append(("/" + candidate.relative_to(root).as_posix(), path, observed))
    if not executables:
        raise ValueError("No executable ELF files found in rootfs bin/sbin directories")
    selected = guest_path(root, service) if service else None
    matches = [item for item in executables if selected is not None and item[1] == selected]
    if service and not matches:
        raise ValueError("Selected service must resolve to an executable ELF in rootfs bin/sbin directories")
    signatures = {(item[2]["architecture"], item[2]["endianness"], item[2]["bits"]) for item in executables}
    if len(signatures) != 1 and not service:
        raise ValueError("Multiple ELF architectures found; select the service using --service /guest/path")
    name, target, observed = (matches or executables)[0]
    if observed["architecture"] != "mips" or observed["bits"] != 32:
        raise ValueError(f"Detected {observed}; no automatic environment recipe for this architecture yet")
    with target.open("rb") as stream:
        header = stream.read(64)
    flags = int.from_bytes(header[36:40], observed["endianness"])
    if flags & 0x20 or (flags & 0xF000) not in (0, 0x1000):
        raise ValueError("MIPS ABI is not supported o32")
    loader = interpreter(target)
    if loader and not guest_path(root, loader).is_file():
        raise ValueError(f"Dynamic linker is missing inside rootfs: {loader}")
    requirements = {"architecture": "mips", "endianness": observed["endianness"], "bits": 32,
                    "abi": "o32", "machine": "malta", "control": "linux-serial-ssh-v1"}
    backend(requirements)
    return {"requirements": requirements, "representative": name, "interpreter": loader,
            "candidates": sorted(set(item[0] for item in executables))}


def tree_identity(root):
    import hashlib
    checksum = hashlib.sha256()
    total = 0
    count = 0
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        for name in sorted(directories + files):
            path = Path(current) / name
            metadata = path.lstat()
            count += 1
            if count > 200000:
                raise ValueError("Rootfs exceeds 200000 entries")
            record = [path.relative_to(root).as_posix(), metadata.st_mode, metadata.st_uid, metadata.st_gid]
            if stat.S_ISLNK(metadata.st_mode):
                record.append(os.readlink(path))
            elif stat.S_ISREG(metadata.st_mode):
                total += metadata.st_size
                if total > 4 * 1024 ** 3:
                    raise ValueError("Rootfs exceeds the current 4 GiB preparation limit")
                record.append(digest(path))
            elif not stat.S_ISDIR(metadata.st_mode):
                raise ValueError(f"Special file requires explicit preparation: {path.relative_to(root)}")
            checksum.update(json.dumps(record).encode())
    return checksum.hexdigest(), total, count


def create_disk(root, destination, total, count):
    if not shutil.which("mkfs.ext2"):
        raise ValueError("Missing mkfs.ext2; install e2fsprogs, then retry preparation")
    size = max(64 * 1024 ** 2, total * 2 + count * 16384 + 16 * 1024 ** 2)
    if shutil.disk_usage(destination.parent).free < size:
        raise ValueError(f"Insufficient disk space; preparation needs approximately {size // 1024 ** 2} MiB")
    temporary = destination.with_suffix(".partial")
    try:
        with temporary.open("wb") as output:
            output.truncate(size)
        result = subprocess.run(["mkfs.ext2", "-q", "-F", "-N", str(max(4096, count * 2)), "-d", str(root), str(temporary)],
                                capture_output=True, text=True, timeout=300)
        (destination.parent / "mkfs.log").write_text(result.stdout + result.stderr)
        if result.returncode:
            raise ValueError("Data-disk creation failed; inspect mkfs.log")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def startup_script(service, arguments):
    setup = """#!/bin/sh
set -eu
mkdir -p /firmware
mountpoint -q /firmware || mount /dev/sdb /firmware
for directory in proc dev tmp var; do mkdir -p "/firmware/$directory"; done
mountpoint -q /firmware/proc || mount -t proc proc /firmware/proc
mountpoint -q /firmware/dev || mount --bind /dev /firmware/dev
mountpoint -q /firmware/tmp || mount -t tmpfs tmpfs /firmware/tmp
mountpoint -q /firmware/var || mount -t tmpfs tmpfs /firmware/var
mkdir -p /firmware/var/run /firmware/var/log
"""
    if service is None:
        return setup
    command = shlex.join([service, *arguments])
    process = shlex.quote(PurePosixPath(service).name)
    return setup + f"setsid chroot /firmware {command} </dev/null >/tmp/vendor-service.log 2>&1 &\n" + \
        f"sleep 3\npidof {process} >/dev/null || {{ tail -n 80 /tmp/vendor-service.log; exit 1; }}\n"


def prepare_firmware(source, rootfs=None, service=None, arguments=(), http_port=None, local=LOCAL, bootstrap=False):
    from tools.extraction import extract_firmware, rootfs_candidates
    source = Path(source).expanduser().resolve()
    if not source.is_file():
        raise ValueError("Provide a firmware file; use --rootfs PATH to reuse an extracted filesystem")
    identity = digest(source)
    local.mkdir(parents=True, exist_ok=True)
    with (local / "preparation.lock").open("a") as registry_lock:
        fcntl.flock(registry_lock, fcntl.LOCK_EX)
        workspace = preparation_workspace(local, source, identity)
    workspace.mkdir(parents=True, exist_ok=True)
    with (workspace / "prepare.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if rootfs:
            selected = Path(rootfs).expanduser().resolve()
            if not selected.is_dir():
                raise ValueError("--rootfs must be an existing directory")
        else:
            extraction = workspace / "extracted"
            marker = workspace / "extraction.json"
            if not marker.exists() or json.loads(marker.read_text()).get("version") != 2:
                if extraction.exists():
                    shutil.rmtree(extraction)
                results = extract_firmware(source, extraction)
                write_json(workspace / "extraction-tools.json", [result.model_dump() for result in results])
                if digest(source) != identity:
                    raise ValueError("Firmware changed during extraction; retry with a stable input")
                if not rootfs_candidates(extraction):
                    return {"state": "NEEDS_ROOTFS", "evidence": str(workspace),
                            "tool_errors": [{"tool": result.command[0], "error": result.error or result.stderr[-1000:]}
                                            for result in results if not result.ok], "next_steps": [
                        "No root filesystem found. Check extraction-tools.json for missing tools/encryption.",
                        "Provide decrypted firmware or retry with --rootfs /path/to/extracted/rootfs."]}
                write_json(marker, {"input_sha256": identity, "version": 2})
            candidates = rootfs_candidates(extraction)
            if len(candidates) != 1:
                return {"state": "NEEDS_ROOTFS", "candidates": list(map(str, candidates)), "next_steps": [
                    "Select one root filesystem with --rootfs PATH; no candidate was chosen implicitly."]}
            selected = candidates[0]
        analysis = inspect_rootfs(selected, service)
        fingerprint, total, count = tree_identity(selected)
        disk = workspace / (asset_name(source, fingerprint) + ".ext2")
        for metadata in sorted(workspace.glob("*.json")):
            record = json.loads(metadata.read_text())
            if isinstance(record, dict) and record.get("rootfs_identity") == fingerprint:
                disk = metadata.with_suffix(".ext2")
                break
        metadata_path = disk.with_suffix(".json")
        if disk.exists() and (not metadata_path.exists() or json.loads(metadata_path.read_text()).get("rootfs_identity") != fingerprint):
            disk = workspace / (asset_name(source, fingerprint) + "-" + fingerprint[12:] + ".ext2")
            metadata_path = disk.with_suffix(".json")
        if not disk.exists() or not metadata_path.exists() or json.loads(metadata_path.read_text()).get("sha256") != digest(disk):
            create_disk(selected, disk, total, count)
            if tree_identity(selected)[0] != fingerprint:
                disk.unlink(missing_ok=True)
                raise ValueError("Rootfs changed during disk creation; retry after stopping modifications")
            write_json(metadata_path, {"sha256": digest(disk), "rootfs_identity": fingerprint})
        result = {"state": "NEEDS_SERVICE", "source": str(source), "rootfs": str(selected), "vendor_disk": str(disk),
                  "evidence": str(workspace), **analysis, "limitations": [
                      "Extracted ownership/device nodes may differ from the original firmware; no host sudo was used.",
                      "Dynamic linker presence is checked; complete library and hardware dependencies require guest validation."],
                  "next_steps": ["Choose the intended service using --service /guest/path (repeat --service-arg for arguments).",
                                 "No firmware service or init script has been executed on the host."]}
        write_json(workspace / "preparation.json", result)
        if not service and not bootstrap:
            return result
        if service and (not service.startswith("/") or "\n" in service):
            raise ValueError("Service must be an absolute guest path without newlines")
        if http_port is not None and (not 1 <= http_port <= 65535 or http_port == 2222):
            raise ValueError("Invalid HTTP guest port")
        adapters = local / "adapters"
        adapters.mkdir(exist_ok=True)
        prefix = "bootstrap-" if bootstrap else "auto-"
        adapter = adapters / (prefix + asset_name(source, identity) + ".json")
        for existing in sorted(adapters.glob(prefix + "*.json")):
            if json.loads(existing.read_text()).get("input_sha256") == identity:
                adapter = existing
                break
        if adapter.exists() and json.loads(adapter.read_text()).get("input_sha256") != identity:
            adapter = adapters / (prefix + asset_name(source, identity) + "-" + identity[12:] + ".json")
        script = adapter.with_suffix(".sh")
        script.write_text(startup_script(service, arguments))
        write_json(adapter, {"schema_version": 1, "kind": "adapter", "id": adapter.stem,
                   "adaptation_required": bootstrap,
                   "input_sha256": identity, "requirements": analysis["requirements"],
                   "vendor_disk": {"path": str(disk), "sha256": digest(disk)},
                   "startup_script": {"path": str(script), "sha256": digest(script)},
                   "network": {"local_ip": "10.0.2.15", "tap_ip": "192.168.100.2", "prefix": 24},
                   "http_probe": {"port": http_port, "path": "/"} if http_port else None,
                   "limitations": result["limitations"] + [
                       "Bootstrap only mounts firmware; service adaptation and independent verification are required." if bootstrap else
                       "Generated adapter checks service process presence only; hardware adaptation may still be needed."]})
        return resolve(source, adapter, local)
