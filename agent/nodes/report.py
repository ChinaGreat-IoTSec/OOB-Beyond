"""Serialize the final audit state."""

import json
from pathlib import Path

from agent.states import FirmwareAuditState
from agent.agents.recovery import recover


def report_node(state: FirmwareAuditState) -> dict:
    output = Path(state.report_path or (Path(state.extract_dir or ".") / "audit-report.json"))
    payload = state.model_copy(update={"status": "AUDITED"}).model_dump(mode="json")
    try:
        output.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        return recover(state, "ReportAgent", f"unable to write report: {exc}")
    return {"logs": [f"report written to {output}"]}
