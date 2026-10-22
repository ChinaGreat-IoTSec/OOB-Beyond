"""Serialize the final audit state."""

import json
from datetime import datetime
from pathlib import Path

from agent.states import FirmwareAuditState
from agent.agents.recovery import recover


def _text(value: object) -> str:
    return str(value).replace("\n", " ").replace("\r", " ").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def readable_report(state: FirmwareAuditState, generated_at: str) -> str:
    meta = state.firmware_meta
    lines = [
        "# OOB Beyond（无界）审计报告", "",
        "## 审计概览", "",
        f"- 生成时间：{generated_at}",
        f"- 输入对象：{_text(meta.firmware_path) if meta else '未知'}",
        f"- 流程状态：{state.status}（不代表所有工具成功或漏洞已确认）",
        f"- 输入类型：请求 {state.requested_input_type} → 实际 {state.input_type}",
        f"- 候选目标：{len(state.binary_targets)} 个",
        f"- 本次选中目标：{_text(state.selected_target.file_path) if state.selected_target else '无'}",
        f"- 待验证线索：{len(state.findings)} 条",
        "", "危险函数引用仅是审计线索，严重性为初步规则标签；不能据此确认可利用漏洞。零线索也不代表安全。",
        "", "## 总控决策", "",
    ]
    for decision in state.agent_decisions:
        lines.append(f"- {_text(decision.agent)}：{_text(decision.rationale)}（置信度 {decision.confidence}）")
    if not state.agent_decisions:
        lines.append("没有保存的决策。")
    lines.extend(["", "## 待验证线索", "",
                  "| 编号 | 函数 | 类型 | 初步严重性 | 位置记录 |",
                  "| --- | --- | --- | --- | --- |"])
    for index, finding in enumerate(state.findings, 1):
        lines.append(f"| {index} | {_text(finding.function_name)} | {finding.vulnerable_pattern} | {finding.severity} | {_text(', '.join(finding.call_trace))} |")
    lines.extend(["", "## Ghidra 静态证据", ""])
    if state.static_evidence:
        for item in state.static_evidence:
            lines.append(
                f"- `{_text(item.sink_function)}@{_text(item.sink_address)}` "
                f"调用者：{_text(', '.join(item.callers) or '未发现')}；"
                f"调用位置：{_text(', '.join(item.call_sites) or '未发现')}；"
                f"输入 API 线索：{_text(', '.join(item.input_sources) or '未发现')}"
            )
    else:
        lines.append("没有解析到结构化 Ghidra 证据。")
    lines.extend(["", "## 工具与异常记录", "",
                  "当前仅保留部分节点日志，尚无完整工具执行证据；无法据此确认全部工具成功。", ""])
    for entry in [*state.logs, *state.llm_diagnostics]:
        lines.append(f"- {_text(entry)}")
    if state.error_message:
        lines.append(f"- 错误：{_text(state.error_message)}")
    lines.extend(["", "## 如何继续阅读", "",
                  "先查看概览和总控决策，再逐条核查线索的输入来源、调用位置及安全检查。",
                  "同名 JSON 保存完整候选列表（binary_targets）、目标（selected_target）、线索（findings）、元数据和决策；需要定位具体文件时再查阅。",
                  "", f"任务 ID：{state.task_id}",
                  f"SHA-256：{meta.sha256 if meta else '未知'}", ""])
    return "\n".join(lines)


def report_node(state: FirmwareAuditState) -> dict:
    output = Path(state.report_path or (Path(state.extract_dir or ".") / "audit-report.json"))
    generated_at = datetime.now().astimezone().isoformat()
    payload = {
        "summary": {
            "generated_at": generated_at,
            "status": state.status,
            "candidate_count": len(state.binary_targets),
            "finding_count": len(state.findings),
            "interpretation": "Unverified leads, not confirmed vulnerabilities",
        },
        **state.model_dump(mode="json"),
    }
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        output.with_suffix(".md").write_text(
            readable_report(state, generated_at), encoding="utf-8"
        )
    except OSError as exc:
        return recover(state, "ReportAgent", f"unable to write report: {exc}")
    return {"logs": [f"report written to {output}"]}
