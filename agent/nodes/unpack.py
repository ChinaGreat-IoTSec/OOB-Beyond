"""Recursive extraction with tool fallbacks."""

from pathlib import Path
import tempfile

from agent.states import FirmwareAuditState
from tools.extraction import extract_firmware
from agent.agents.recovery import recover


def unpack_node(state: FirmwareAuditState) -> dict:
    firmware = Path(state.firmware_meta.firmware_path)  # type: ignore[union-attr]
    if firmware.is_dir():
        return {
            "status": "UNPACKED", "extract_dir": str(firmware),
            "logs": ["input is already an extracted filesystem directory"],
        }
    extract_dir = Path(tempfile.mkdtemp(prefix=f"iot-audit-{state.task_id}-"))
    try:
        results = extract_firmware(firmware, extract_dir)
    except ValueError as error:
        return {"status": "FAILED", "extract_dir": str(extract_dir), "error_message": str(error)}
    logs = [f"{result.command[0]} return code: {result.return_code}; {result.error or ''}" for result in results]
    if not any(path.is_file() for path in extract_dir.rglob("*")):
        recovery = recover(state, "UnpackAgent", "no files were extracted")
        recovery.update({"extract_dir": str(extract_dir), "logs": logs})
        return recovery
    return {"status": "UNPACKED", "extract_dir": str(extract_dir), "logs": logs}
