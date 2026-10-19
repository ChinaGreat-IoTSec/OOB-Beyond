"""LLM supervisor that selects the primary audit target."""

from agent.llm import ask_json
from agent.states import AgentDecision, FirmwareAuditState


def _confidence(value: object) -> float:
    if isinstance(value, str):
        levels = {"critical": 0.95, "high": 0.85, "medium": 0.65, "low": 0.35}
        if value.lower() in levels:
            return levels[value.lower()]
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def supervisor_node(state: FirmwareAuditState) -> dict:
    prompt = (
        "Select the highest value binary for IoT firmware security auditing.\n"
        "Choose only one path from the candidate list and explain why.\n"
        f"Candidates: {[target.model_dump() for target in state.binary_targets]}"
    )
    try:
        result = ask_json(
            "You are the SupervisorAgent coordinating firmware security specialists. "
            "Use only supplied evidence. Return path, rationale, confidence.",
            prompt,
        )
        selected_path = str(result.get("path", result.get("selected_path", "")))
        selected = next(
            (target for target in state.binary_targets if target.file_path == selected_path),
            state.binary_targets[0] if state.binary_targets else None,
        )
        decision = AgentDecision(
            agent="SupervisorAgent",
            decision="audit" if selected else "report",
            rationale=str(result.get("rationale", "")),
            confidence=_confidence(result.get("confidence", 0)),
        )
        return {"selected_target": selected, "agent_decisions": [decision]}
    except (RuntimeError, ValueError, TypeError) as exc:
        return {"status": "FAILED", "error_message": f"SupervisorAgent failed: {exc}"}
