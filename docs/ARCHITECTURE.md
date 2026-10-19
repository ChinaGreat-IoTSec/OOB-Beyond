# IoT Firmware Security Agent Architecture

## Purpose

This project provides an interactive, multi-agent security auditing system for IoT firmware. Users describe an audit task in natural language. A supervisor agent creates a structured plan and coordinates specialist agents that use deterministic security tools.

## System boundary

```text
User
  ↕ natural language
Interactive session
  ↕ intent and task plan
SupervisorAgent
  ↕ structured TaskEnvelope / AgentResult
Specialist agents
  ↕ validated ToolRequest / ToolResult
Security toolchain
  ↓
Evidence, findings, and reports
```

The LLM is responsible for intent interpretation, planning, routing, explanation, and recovery decisions. File hashing, format detection, command construction, timeout enforcement, tool execution, and evidence storage remain deterministic and auditable.

## Agents

| Agent | Responsibility |
| --- | --- |
| `SupervisorAgent` | Interpret the user task, create a plan, route work, and summarize results |
| `IntakeAgent` | Validate inputs, calculate hashes, and identify file formats and architectures |
| `UnpackAgent` | Select unpackers, validate extraction, and handle extraction failures |
| `TriageAgent` | Discover services, scripts, binaries, credentials, and attack surface |
| `StaticAnalysisAgent` | Run Ghidra and future binary analysis backends |
| `SecretScanAgent` | Detect credentials, keys, certificates, tokens, and debug artifacts |
| `VulnerabilityAgent` | Correlate evidence and assess vulnerability patterns and severity |
| `RecoveryAgent` | Diagnose failures and propose retry, fallback, or user action |
| `EvidenceAgent` | Persist commands, logs, hashes, locations, and call traces |
| `ReportAgent` | Produce structured JSON and future HTML/SARIF reports |

The current implementation contains the supervisor and recovery prototypes. Intake, unpack, triage, audit, and report are implemented as LangGraph worker nodes and will be migrated to independent agents in later phases.

## Communication protocol

The supervisor-to-agent boundary uses structured messages. A task request contains a task ID, agent type, action, input artifacts, constraints, and requested outputs. An agent result contains status, observations, evidence, findings, errors, next action, and confidence.

LLM output is never executed directly. The supervisor validates the proposed action against an allowlist, and the tool runner validates every command before execution.

## Input modes

The runtime accepts:

- Firmware image files
- Individual ELF binaries
- Extracted filesystem directories
- Natural-language audit requests in the interactive session

## Execution lifecycle

```text
CREATED → PLANNING → RUNNING → COMPLETED
                    ↓       ↘
                RECOVERING   WAITING_USER
                    ↓           ↓
                 RUNNING      RUNNING
```

Terminal states are `COMPLETED`, `FAILED`, and `CANCELLED`. Each agent has its own execution state so an individual failure can be retried or delegated without losing the overall task.

## Security requirements

- Never commit `.env`, API keys, firmware samples, or local reports.
- Invoke external tools without a shell.
- Enforce subprocess timeouts and capture stdout and stderr.
- Keep firmware analysis read-only unless the user explicitly enables a controlled action.
- Associate findings with reproducible evidence.
- Record the model and provider used for each LLM decision once per-agent model routing is implemented.

## Development phases

1. Stabilize the interactive runtime, task state, events, and typed contracts.
2. Implement natural-language intent parsing and structured supervisor-to-agent dispatch.
3. Add evidence-driven secret scanning and vulnerability confirmation.
4. Add persistence, parallel analysis, resumable tasks, API access, and additional report formats.
5. Add independent model and provider configuration for each agent.

## Release strategy

The project version is stored in `VERSION`. Releases use semantic versioning and Git tags:

```text
VERSION=0.1.0
git tag -a v0.1.0 -m "Initial multi-agent audit prototype"
git push origin v0.1.0
```

Patch releases contain fixes, minor releases add backward-compatible capabilities, and major releases may change agent protocols or report schemas.
