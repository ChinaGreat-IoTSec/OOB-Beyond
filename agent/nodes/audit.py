"""Run Ghidra and retain findings even when analysis is incomplete."""

from pathlib import Path
import json
import tempfile

from agent.states import AuditFinding, FirmwareAuditState, StaticEvidence
from tools.ghidra_runner import GhidraRunner
from agent.agents.recovery import recover
from agent.agents.vulnerability import assess


def audit_node(state: FirmwareAuditState) -> dict:
    target = state.selected_target
    if target is None:
        return recover(state, "AuditAgent", "no target selected")
    project_dir = Path(tempfile.mkdtemp(prefix=f"ghidra-{state.task_id}-"))
    script_dir = Path(__file__).parents[2] / "tools"
    result = GhidraRunner().analyze(Path(target.file_path), project_dir, script_dir)
    findings: list[AuditFinding] = []
    evidence: list[StaticEvidence] = []
    malformed = 0
    for line in result.stdout.splitlines():
        if "EVIDENCE_JSON|" not in line:
            continue
        try:
            item = json.loads(line.split("EVIDENCE_JSON|", 1)[1])
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
                arguments=item.get("arguments", []),
                analysis_gaps=item.get("analysis_gaps", []),
            ))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            malformed += 1
            continue
    findings = [assess(item) for item in evidence]
    logs = [f"Ghidra return code: {result.return_code}"]
    if malformed:
        logs.append(f"Malformed Ghidra evidence records skipped: {malformed}")
    if not result.ok:
        logs.append(result.error or result.stderr[-500:] or "Ghidra analysis failed")
        detail = result.error or result.stderr[-1000:] or "unknown Ghidra error"
        return {"findings": findings, "static_evidence": evidence,
                "status": "FAILED", "error_message": f"Ghidra analysis failed: {detail}",
                "logs": logs}
    if "EVIDENCE_COMPLETE|1" not in result.stdout:
        return {"findings": findings, "static_evidence": evidence,
                "status": "FAILED", "error_message": "Ghidra evidence script did not complete",
                "logs": logs + ["Missing evidence completion marker; results may be partial"]}
    logs.append(f"Ghidra structured evidence records: {len(evidence)}")
    return {"findings": findings, "static_evidence": evidence,
            "status": "AUDITED", "logs": logs}
