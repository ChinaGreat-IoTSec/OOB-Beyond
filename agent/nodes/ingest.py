"""Firmware validation and metadata collection."""

import hashlib
from pathlib import Path

from agent.states import FirmwareAuditState, FirmwareMeta
from agent.agents.recovery import recover


def _detect_architecture(header: bytes) -> str | None:
    if header[:4] != b"\x7fELF" or len(header) < 20:
        return None
    machine = int.from_bytes(header[18:20], "little" if header[5] == 1 else "big")
    return {
        3: "x86",
        8: "MIPS",
        20: "PowerPC",
        40: "ARM",
        62: "x86_64",
        183: "AArch64",
    }.get(machine, f"ELF machine {machine}")


def ingest_node(state: FirmwareAuditState) -> dict:
    path = Path(state.firmware_meta.firmware_path) if state.firmware_meta else None
    if path is None or not path.exists():
        return recover(state, "IngestAgent", "input path does not exist")
    if path.is_dir():
        digest = hashlib.sha256()
        total_size = 0
        for child in sorted(item for item in path.rglob("*") if item.is_file()):
            total_size += child.stat().st_size
            digest.update(str(child.relative_to(path)).encode())
            digest.update(child.read_bytes())
        return {
            "firmware_meta": FirmwareMeta(
                firmware_path=str(path.resolve()), file_size=total_size,
                sha256=digest.hexdigest(), magic_bytes="directory",
            ),
            "status": "INGESTED",
            "logs": [f"ingested directory {path}"],
        }
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        header = stream.read(64)
        digest.update(header)
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "firmware_meta": FirmwareMeta(
            firmware_path=str(path.resolve()),
            file_size=path.stat().st_size,
            sha256=digest.hexdigest(),
            detected_arch=_detect_architecture(header),
            magic_bytes=header.hex(),
        ),
        "status": "INGESTED",
        "logs": [f"ingested {path.name} ({path.stat().st_size} bytes)"],
    }
