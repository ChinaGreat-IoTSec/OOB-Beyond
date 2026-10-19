"""LangGraph workflow for firmware auditing."""

from langgraph.graph import END, START, StateGraph

from agent.nodes.audit import audit_node
from agent.nodes.ingest import ingest_node
from agent.nodes.report import report_node
from agent.nodes.triage import triage_node
from agent.nodes.unpack import unpack_node
from agent.agents.supervisor import supervisor_node
from agent.states import FirmwareAuditState


def _next(state: FirmwareAuditState) -> str:
    return "stop" if state.status == "FAILED" else "continue"


workflow = StateGraph(FirmwareAuditState)
workflow.add_node("ingest", ingest_node)
workflow.add_node("unpack", unpack_node)
workflow.add_node("triage", triage_node)
workflow.add_node("supervisor", supervisor_node)
workflow.add_node("audit", audit_node)
workflow.add_node("report", report_node)
workflow.add_edge(START, "ingest")
workflow.add_conditional_edges("ingest", _next, {"continue": "unpack", "stop": END})
workflow.add_conditional_edges("unpack", _next, {"continue": "triage", "stop": END})
workflow.add_conditional_edges("triage", _next, {"continue": "supervisor", "stop": END})
workflow.add_conditional_edges("supervisor", _next, {"continue": "audit", "stop": END})
workflow.add_conditional_edges("audit", _next, {"continue": "report", "stop": END})
workflow.add_edge("report", END)
app = workflow.compile()
