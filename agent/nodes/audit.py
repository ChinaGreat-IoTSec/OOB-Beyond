"""Run Ghidra and retain findings even when analysis is incomplete."""

from pathlib import Path
import json
import tempfile

from agent.states import AuditFinding, FirmwareAuditState, StaticEvidence
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
    evidence: list[StaticEvidence] = []
    for line in result.stdout.splitlines():
        if not line.startswith("EVIDENCE_JSON|"):
            continue
        try:
            item = json.loads(line.split("|", 1)[1])
            evidence.append(StaticEvidence(
                target_binary=target.file_path,
                sink_function=str(item["sink_function"]),
                sink_address=str(item["sink_address"]),
                callers=[str(value) for value in item.get("callers", [])],
                call_sites=[str(value) for value in item.get("call_sites", [])],
                input_sources=[
                    str(source.get("function", source))
                    if isinstance(source, dict) else str(source)
                    for source in item.get("input_sources", [])
                ],
            ))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
    for item in evidence:
        function = item.sink_function.lower()
        pattern, severity = PATTERNS.get(function, ("unknown", "low"))
        findings.append(AuditFinding(
            target_binary=target.file_path,
            function_name=item.sink_function,
            vulnerable_pattern=pattern,
            call_trace=[*item.callers, *item.call_sites],
            severity=severity,
            evidence_refs=[f"{item.sink_function}@{item.sink_address}"],
        ))
    logs = [f"Ghidra return code: {result.return_code}"]
    if not result.ok:
        logs.append(result.error or result.stderr[-500:] or "Ghidra analysis failed")
        detail = result.error or result.stderr[-1000:] or "unknown Ghidra error"
        return {"findings": findings, "static_evidence": evidence,
                "status": "FAILED", "error_message": f"Ghidra analysis failed: {detail}",
                "logs": logs}
    logs.append(f"Ghidra structured evidence records: {len(evidence)}")
    return {"findings": findings, "static_evidence": evidence,
            "status": "AUDITED", "logs": logs}
