# Role & Context
You are an expert Python systems architect and offensive security engineer specializing in embedded firmware auditing.
We are developing a modular, agentic IoT security auditing pipeline in a Linux/WSL environment.

# Tech Stack & Dependencies
- Python 3.10+
- LangGraph & LangChain Core (State machine orchestration)
- Pydantic v2 (Strict state typing and data contracts)
- Rich (CLI logging)
- External CLI Toolchain (Available in $PATH): `binwalk`, `sasquatch`, `unsquashfs`, `jefferson`, `analyzeHeadless` (Ghidra 11.x)

# Project Architecture & Directory Layout
Create a production-grade, maintainable Python project with the following file tree:

iot_agent_workspace/
├── agent/
│   ├── __init__.py
│   ├── states.py            # Complete Pydantic v2 data models for pipeline state
│   ├── graph.py             # LangGraph workflow definition, edges, conditional routing
│   └── nodes/               # Modular node implementations
│       ├── __init__.py
│       ├── ingest.py        # File validation, hashing, header inspection
│       ├── unpack.py        # Binwalk execution with fallback to sasquatch/unsquashfs
│       ├── triage.py        # Attack surface discovery (Web daemons, CGI, hardcoded keys)
│       ├── audit.py         # Headless Ghidra orchestrator & cross-reference extractor
│       └── report.py        # Finding summarization and JSON serialization
├── tools/
│   ├── __init__.py
│   ├── base.py              # Abstract Base Tool with timeout, subprocess, and sandbox controls
│   ├── binwalk.py           # Tool wrapper for binwalk extraction
│   ├── unpackers.py         # Dedicated unpacker wrappers (sasquatch, unsquashfs, jefferson)
│   └── ghidra_runner.py     # analyzeHeadless caller with automatic -deleteProject lifecycle
└── main.py                  # CLI entrypoint supporting argument parsing and pipeline invocation

# Core Implementation Requirements

### 1. `agent/states.py`
Define strict Pydantic models:
- `FirmwareMeta`: firmware path, file size, sha256, detected arch.
- `BinaryTarget`: file path, architecture, file type, priority score (1-10), reasons for priority (e.g., binds port, contains system calls).
- `AuditFinding`: target_binary, function_name, vulnerable_pattern (buffer_overflow, command_injection, format_string), call_trace, severity.
- `FirmwareAuditState(BaseModel)`:
    - `task_id: str`
    - `firmware_meta: Optional[FirmwareMeta]`
    - `extract_dir: Optional[str]`
    - `binary_targets: List[BinaryTarget]`
    - `selected_target: Optional[BinaryTarget]`
    - `findings: List[AuditFinding]`
    - `status: Literal["INITIALIZED", "INGESTED", "UNPACKED", "TRIAGED", "AUDITED", "FAILED"]`
    - `error_message: Optional[str]`
    - `logs: List[str]`

### 2. `tools/base.py` & Tool Execution
- Implement an abstract `BaseAuditTool` class with standard `execute()` utilizing `subprocess.run`.
- Guarantee timeout handling (default 300s), standard stream capturing (`stdout`, `stderr`), and typed output using a `ToolResult` Pydantic model.
- `ghidra_runner.py` MUST always append `-deleteProject` to Ghidra `analyzeHeadless` execution to avoid filling WSL disk space.

### 3. Node Logic & Error Handling
- **Ingest**: Verify the file exists, compute SHA-256, read the first 64 bytes for magic bytes.
- **Unpack**: Run binwalk recursively (`-e -M`). If binwalk fails or produces no rootfs, gracefully attempt fallback extraction via `sasquatch`/`unsquashfs`.
- **Triage**: Search the extracted filesystem for common IoT targets: `httpd`, `boa`, `uhttpd`, `mini_httpd`, `*.cgi`, and services listening on network ports. Sort targets by attack surface weight.
- **Audit**: For the highest-priority binary, trigger Ghidra in headless mode via a stub script to parse dangerous sinks (`strcpy`, `system`, `popen`, `sprintf`). If Ghidra fails, record the error in state without crashing the whole graph.
- **Report**: Synthesize all collected metadata and findings into a clean, structured JSON format saved to disk.

### 4. `agent/graph.py`
- Wire all nodes via `StateGraph(FirmwareAuditState)`.
- Implement conditional edges: if any step produces `status == "FAILED"` or unrecoverable error, route directly to `END`.
- Clean compilation and export of the compiled graph runnable (`app = workflow.compile()`).

### 5. `main.py`
- Accept `--firmware <path>` as a CLI argument.
- Instantiate `FirmwareAuditState` with a unique UUID.
- Stream execution status to the terminal using `rich.console` or `rich.progress`.

Please write clean, modular, self-contained Python code for all files listed in the tree above, adhering strictly to PEP 8 standards with full type annotations.
