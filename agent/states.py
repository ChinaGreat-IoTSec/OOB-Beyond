"""Typed data contracts shared by the audit graph."""

from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, validate_assignment=True
    )


class FirmwareMeta(StrictModel):
    firmware_path: str
    file_size: int = Field(ge=0)
    sha256: str = Field(min_length=64, max_length=64)
    detected_arch: Optional[str] = None
    magic_bytes: str = ""


class BinaryTarget(StrictModel):
    file_path: str
    architecture: Optional[str] = None
    file_type: str = "unknown"
    priority_score: int = Field(ge=1, le=10)
    priority_reasons: List[str] = Field(default_factory=list)


class AuditFinding(StrictModel):
    target_binary: str
    function_name: Optional[str] = None
    vulnerable_pattern: Literal[
        "buffer_overflow", "command_injection", "format_string", "unknown"
    ]
    call_trace: List[str] = Field(default_factory=list)
    severity: Literal["info", "low", "medium", "high", "critical"]


class AgentDecision(StrictModel):
    agent: str
    decision: str
    rationale: str
    confidence: float = Field(ge=0, le=1)


class FirmwareAuditState(StrictModel):
    task_id: str
    requested_input_type: Literal["auto", "binary", "firmware", "directory"] = "auto"
    input_type: Literal["firmware", "elf", "binary", "directory"] = "firmware"
    firmware_meta: Optional[FirmwareMeta] = None
    extract_dir: Optional[str] = None
    report_path: Optional[str] = None
    binary_targets: List[BinaryTarget] = Field(default_factory=list)
    selected_target: Optional[BinaryTarget] = None
    findings: List[AuditFinding] = Field(default_factory=list)
    status: Literal[
        "INITIALIZED", "INGESTED", "UNPACKED", "TRIAGED", "AUDITED", "FAILED"
    ] = "INITIALIZED"
    error_message: Optional[str] = None
    logs: List[str] = Field(default_factory=list)
    agent_decisions: List[AgentDecision] = Field(default_factory=list)
    llm_diagnostics: List[str] = Field(default_factory=list)

