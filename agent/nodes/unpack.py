"""Recursive extraction with tool fallbacks."""

from pathlib import Path
import shutil
import tempfile

from agent.states import FirmwareAuditState
from tools.binwalk import BinwalkTool
from tools.unpackers import SasquatchTool, UnsquashfsTool
from agent.agents.recovery import recover


def _has_rootfs(directory: Path) -> bool:
    return any(path.is_dir() and (path / "bin").exists() for path in directory.rglob("*"))


def unpack_node(state: FirmwareAuditState) -> dict:
    firmware = Path(state.firmware_meta.firmware_path)  # type: ignore[union-attr]
    if firmware.is_dir():
        return {
            "status": "UNPACKED", "extract_dir": str(firmware),
            "logs": ["input is already an extracted filesystem directory"],
        }
    extract_dir = Path(tempfile.mkdtemp(prefix=f"iot-audit-{state.task_id}-"))
    result = BinwalkTool().extract(firmware, extract_dir)
    logs = [f"binwalk return code: {result.return_code}"]
    if not result.ok or not _has_rootfs(extract_dir):
        logs.append("binwalk did not produce a root filesystem; trying unsquashfs")
        fallback_dir = extract_dir / "fallback-rootfs"
        fallback = UnsquashfsTool().extract(firmware, fallback_dir)
        if not fallback.ok:
            fallback = SasquatchTool().extract(firmware, fallback_dir)
        logs.append(f"fallback return code: {fallback.return_code}")
    if not any(path.is_file() for path in extract_dir.rglob("*")):
        if firmware.read_bytes()[:4] == b"\x7fELF":
            shutil.copy2(firmware, extract_dir / firmware.name)
            return {
                "status": "UNPACKED", "extract_dir": str(extract_dir),
                "logs": logs + ["input is an ELF binary; direct audit mode enabled"],
            }
        recovery = recover(state, "UnpackAgent", "no files were extracted")
        recovery.update({"extract_dir": str(extract_dir), "logs": logs})
        return recovery
    return {"status": "UNPACKED", "extract_dir": str(extract_dir), "logs": logs}
