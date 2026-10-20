"""Firmware validation and metadata collection."""

import hashlib
from pathlib import Path

from agent.states import BinaryTarget, FirmwareAuditState, FirmwareMeta
from agent.agents.recovery import recover
from agent.formats import identify_binary


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
    requested = state.requested_input_type
    if requested == "directory" and not path.is_dir():
        return {"status": "FAILED", "error_message": "directory 模式要求输入目录"}
    if requested in {"binary", "firmware"} and not path.is_file():
        return {"status": "FAILED", "error_message": f"{requested} 模式要求输入普通文件"}
    if not path.is_dir() and not path.is_file():
        return {"status": "FAILED", "error_message": "仅支持普通文件或目录"}
    if path.is_dir():
        digest = hashlib.sha256()
        total_size = 0
        for child in sorted(item for item in path.rglob("*") if item.is_file()):
            total_size += child.stat().st_size
            digest.update(str(child.relative_to(path)).encode())
            digest.update(child.read_bytes())
        return {
            "input_type": "directory",
            "extract_dir": str(path.resolve()),
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
    binary = identify_binary(path)
    result = {
        "firmware_meta": FirmwareMeta(
            firmware_path=str(path.resolve()),
            file_size=path.stat().st_size,
            sha256=digest.hexdigest(),
            detected_arch=binary[1] if binary else None,
            magic_bytes=header.hex(),
        ),
        "status": "INGESTED",
        "logs": [f"ingested {path.name} ({path.stat().st_size} bytes)"],
    }
    if requested == "binary" and binary is None:
        return {"status": "FAILED", "error_message": "无法识别为受支持的 ELF、PE 或单架构 Mach-O；压缩模块、归档和裸二进制暂不支持直接审计"}
    if binary is not None and requested != "firmware":
        target = BinaryTarget(
            file_path=str(path.resolve()),
            architecture=binary[1],
            file_type=binary[0],
            priority_score=10,
            priority_reasons=["explicit user-selected binary input"],
        )
        result.update({
            "input_type": "binary",
            "binary_targets": [target],
            "selected_target": target,
        })
    else:
        result["input_type"] = "firmware"
    return result
