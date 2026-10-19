"""Run Ghidra and retain findings even when analysis is incomplete."""

from pathlib import Path
import re
import tempfile

from agent.states import AuditFinding, FirmwareAuditState
from tools.ghidra_runner import GhidraRunner
from agent.agents.recovery import recover


PATTERNS = {
    "strcpy": ("buffer_overflow", "high"),
    "sprintf": ("buffer_overflow", "high"),
    "system": ("command_injection", "critical"),
    "popen": ("command_injection", "critical"),
    "printf": ("format_string", "medium"),
}


def audit_node(state: FirmwareAuditState) -> dict:
    target = state.selected_target
    if target is None:
        return recover(state, "AuditAgent", "no target selected")
    project_dir = Path(tempfile.mkdtemp(prefix=f"ghidra-{state.task_id}-"))
    script_dir = Path(__file__).parents[2] / "tools"
    result = GhidraRunner().analyze(Path(target.file_path), project_dir, script_dir)
    findings: list[AuditFinding] = []
    output = f"{result.stdout}\n{result.stderr}"
    for match in re.finditer(r"SINK\|([^|]+)\|([^\s]+)", output):
        function = match.group(1).lower()
        pattern, severity = PATTERNS.get(function, ("unknown", "low"))
        findings.append(AuditFinding(
            target_binary=target.file_path,
            function_name=match.group(1),
            vulnerable_pattern=pattern,
            call_trace=[match.group(2)],
            severity=severity,
        ))
    logs = [f"Ghidra return code: {result.return_code}"]
    if not result.ok:
        logs.append(result.error or result.stderr[-500:] or "Ghidra analysis failed")
    return {"findings": findings, "status": "AUDITED", "logs": logs}
