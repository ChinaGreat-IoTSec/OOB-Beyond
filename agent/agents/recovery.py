"""Recovery agent used whenever a worker cannot complete its task."""

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


def recover(state: FirmwareAuditState, agent_name: str, error: str) -> dict:
    prompt = (
        f"Agent {agent_name} failed during an IoT firmware audit.\n"
        f"Error: {error}\n"
        f"Current state: {state.model_dump_json(exclude={'logs'})}"
    )
    try:
        result = ask_json(
            "You are a senior IoT security recovery agent. Diagnose the failure and "
            "recommend one safe next action. Never invent tool output.",
            prompt,
        )
        decision = AgentDecision(
            agent=f"{agent_name}RecoveryAgent",
            decision=str(result.get("action", "stop")),
            rationale=str(result.get("rationale", "")),
            confidence=_confidence(result.get("confidence", 0)),
        )
        return {
            "status": "FAILED",
            "error_message": error,
            "agent_decisions": [decision],
            "llm_diagnostics": [str(result)],
        }
    except (RuntimeError, ValueError, TypeError) as exc:
        return {
            "status": "FAILED",
            "error_message": error,
            "llm_diagnostics": [f"recovery agent unavailable: {exc}"],
        }
