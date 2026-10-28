"""Versioned local adapters, reusable environment assets and preparation plans."""

import hashlib
import ipaddress
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / "emulation/local"
REQUIREMENTS = ("architecture", "endianness", "bits", "abi", "machine", "control")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_manifest(path, kind):
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or data.get("schema_version") != 1 or data.get("kind") != kind:
        raise ValueError(f"{path}: expected {kind} schema_version 1")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", data.get("id", "")):
        raise ValueError(f"{path}: invalid id")
    requirements = data.get("requirements", {})
    if set(requirements) != set(REQUIREMENTS):
        raise ValueError(f"{path}: requirements must specify {', '.join(REQUIREMENTS)}")
    if any(not isinstance(requirements[key], str) or not requirements[key] for key in REQUIREMENTS if key != "bits"):
        raise ValueError(f"{path}: invalid requirements")
    if requirements["bits"] not in (32, 64) or requirements["endianness"] not in ("big", "little"):
        raise ValueError(f"{path}: invalid bit width or endianness")
    return data


def asset(specification, parent):
    if not isinstance(specification, dict) or not isinstance(specification.get("path"), str):
        raise ValueError("Asset must contain path and sha256")
    expected = specification.get("sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Asset sha256 must contain 64 lowercase hexadecimal characters")
    path = (parent / specification["path"]).resolve()
    if not path.is_file():
        raise ValueError(f"Missing local asset: {path}")
    if digest(path) != expected:
        raise ValueError(f"Asset checksum mismatch: {path}")
    return str(path)


def backend(requirements):
    if (requirements["architecture"] != "mips" or requirements["bits"] != 32 or
            requirements["abi"] != "o32" or requirements["machine"] != "malta" or
            requirements["control"] != "linux-serial-ssh-v1"):
        raise ValueError("No implemented backend for these requirements; no images will be downloaded or built")
    return {"executable": "qemu-system-mips" if requirements["endianness"] == "big" else "qemu-system-mipsel",
            "machine": "malta", "memory": "256M", "nic": "pcnet",
            "append": "rootwait root=/dev/sda console=ttyS0"}


def inspect_input(path):
    with path.open("rb") as stream:
        header = stream.read(64)
    result = {"format": "opaque", "size": path.stat().st_size}
    if header[:4] == b"\x7fELF" and len(header) >= 20 and header[4] in (1, 2) and header[5] in (1, 2):
        endian = "little" if header[5] == 1 else "big"
        machine = int.from_bytes(header[18:20], endian)
        result.update(format="elf", bits=32 if header[4] == 1 else 64, endianness=endian,
                      architecture={8: "mips", 40: "arm", 183: "aarch64", 3: "x86", 62: "x86_64"}.get(machine, "unknown"))
    return result


def check_observation(observation, requirements):
    for key in ("architecture", "bits", "endianness"):
        if key in observation and observation[key] != requirements[key]:
            raise ValueError(f"Input {key} disagrees with adapter requirements")


def resolve(source, adapter=None, local=LOCAL):
    source = Path(source).expanduser().resolve()
    if not source.is_file():
        raise ValueError("Provide an existing firmware or binary file; directory preparation is not implemented yet")
    source_hash = digest(source)
    observation = inspect_input(source)
    plan = {"schema_version": 1, "state": "NEEDS_ADAPTER", "source": str(source), "sha256": source_hash,
            "observed": observation, "local_store": str(local), "diagnostics": [],
            "next_steps": ["No matching local adapter. Retry with --prepare to extract and inspect this firmware.",
                           "Use --rootfs PATH to reuse extracted files; --service /guest/path selects the service to launch.",
                           "Run with --plan to inspect requirements without launching a VM; no build/download occurs."]}
    candidates = [Path(adapter).expanduser().resolve()] if adapter else sorted((local / "adapters").glob("*.json"))
    matches = []
    for path in candidates:
        try:
            data = read_manifest(path, "adapter")
            if data.get("input_sha256") == source_hash:
                matches.append((path, data))
            elif adapter:
                raise ValueError("Explicit adapter does not match input sha256")
        except (OSError, ValueError) as error:
            if adapter:
                raise ValueError(f"Adapter rejected: {error}") from error
            plan["diagnostics"].append(str(error))
    if len(matches) > 1:
        plan.update(state="AMBIGUOUS_ADAPTER", next_steps=["Multiple adapters match; select one using --adapter PATH."])
        return plan
    if not matches:
        return plan
    path, data = matches[0]
    requirements = data["requirements"]
    check_observation(observation, requirements)
    plan.update(adapter_id=data["id"], adapter_path=str(path), requirements=requirements,
                adaptation_required=data.get("adaptation_required", False))
    try:
        runtime = backend(requirements)
    except ValueError as error:
        plan.update(state="UNSUPPORTED_BACKEND", next_steps=[str(error)])
        return plan
    vendor = asset(data["vendor_disk"], path.parent)
    script_path = asset(data["startup_script"], path.parent)
    script = Path(script_path).read_text()
    if len(script.encode()) > 65536:
        raise ValueError("Adapter startup script exceeds 64 KiB")
    network = data["network"]
    if network.get("local_ip") != "10.0.2.15":
        raise ValueError("Local networking contract requires 10.0.2.15")
    tap_ip = str(ipaddress.IPv4Address(network["tap_ip"]))
    if not isinstance(network.get("prefix"), int) or not 1 <= network["prefix"] <= 30:
        raise ValueError("Network prefix must be between 1 and 30")
    probe = data.get("http_probe")
    if probe is not None:
        if not isinstance(probe, dict) or not isinstance(probe.get("port"), int) or not 1 <= probe["port"] <= 65535:
            raise ValueError("HTTP probe requires a valid port")
        if probe["port"] == 2222 or not isinstance(probe.get("path"), str) or not probe["path"].startswith("/"):
            raise ValueError("Invalid HTTP probe path or reserved SSH port")
        if any(character in probe["path"] for character in "\r\n"):
            raise ValueError("HTTP probe path contains a newline")
    https_port = data.get("https_port")
    if https_port is not None and (not isinstance(https_port, int) or not 1 <= https_port <= 65535 or https_port == 2222):
        raise ValueError("Invalid HTTPS port")
    plan.update(state="NEEDS_ENVIRONMENT", next_steps=[
        "No intact compatible local environment is registered. Existing unrelated images are not downloaded or copied.",
        "Register a trusted environment manifest in emulation/local/environments/; match all requirement fields and asset checksums.",
        "Retry with --build-environment to prepare only the matching supported Buildroot environment."])
    for environment_path in sorted((local / "environments").glob("*.json")):
        try:
            environment = read_manifest(environment_path, "environment")
            if environment["requirements"] != requirements:
                continue
            kernel = asset(environment["kernel"], environment_path.parent)
            system_disk = asset(environment["system_disk"], environment_path.parent)
        except (OSError, ValueError, KeyError) as error:
            plan["diagnostics"].append(f"{environment_path}: {error}")
            continue
        profile = {"id": data["id"], "environment_id": environment["id"], "requirements": requirements,
                   "adaptation_required": data.get("adaptation_required", False),
                   "kernel": kernel, "system_disk": system_disk, "vendor_disk": vendor, "runtime": runtime,
                   "startup_script": script, "guest_ip_local": "10.0.2.15", "guest_ip_tap": tap_ip,
                   "netmask": str(ipaddress.IPv4Network(f"0.0.0.0/{network['prefix']}").netmask),
                   "http_probe": probe, "https_port": https_port, "limitations": data.get("limitations", []),
                   "asset_hashes": {"kernel": environment["kernel"]["sha256"],
                                    "system_disk": environment["system_disk"]["sha256"],
                                    "vendor_disk": data["vendor_disk"]["sha256"]}}
        plan.update(state="PREPARED", environment_id=environment["id"], reuse="local",
                    next_steps=["Local environment validated; ready to start a session."], profile=profile)
        if profile["adaptation_required"]:
            plan["next_steps"].append("Bootstrap mounts firmware only. Use --adapt with a goal and acceptance checks, or debug the retained session manually.")
        return plan
    return plan
