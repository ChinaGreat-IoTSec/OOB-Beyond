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
| `VulnerabilityAnalysisAgent` | Discover candidates, correlate static evidence, trace data flows, and assess findings within the current binary or firmware |
| `RecoveryAgent` | Diagnose failures and propose retry, fallback, or user action |
| `EvidenceAgent` | Persist commands, logs, hashes, locations, and call traces |
| `ReportAgent` | Produce structured JSON and future HTML/SARIF reports |

The current implementation contains the supervisor and recovery prototypes. Intake, unpack, triage, audit, and report are implemented as LangGraph worker nodes and will be migrated to independent agents in later phases.

## Vulnerability analysis boundary

Detection and assessment are combined in `VulnerabilityAnalysisAgent`. The first implementation focuses on evidence that can be confirmed within the current binary or firmware image: files, functions, callers, input sources, data-flow edges, configuration, IPC, and dangerous sinks. Product-wide impact, affected-version analysis, and external deployment scope are outside the first implementation.

Detection and assessment are responsibilities within one analysis loop, not separate agents or duplicated rule passes. Candidate discovery, argument/data-flow tracing, guard validation, and conclusion generation share evidence. Length checks belong to guard validation: verify the checked value, destination capacity, terminator requirements, arithmetic, and whether the check constrains every path reaching the operation. A check's presence alone cannot suppress a candidate. Deterministic analysis resolves supported conditions; optional LLM assistance handles remaining semantic questions without replacing evidence or treating missing evidence as safety.

The agent must distinguish `confirmed`, `probable`, `suspected`, `not_vulnerable`, and `insufficient_evidence`. It must never turn a dangerous API reference into a confirmed vulnerability without an evidence chain.

Dynamic analysis is a later validation stage. It may use QEMU, an emulator, a containerized runtime, or authorized hardware to execute a trigger and collect runtime evidence. Static analysis must remain useful when no dynamic environment is available.

### Implemented deterministic prototype

`tools/ScanSinks.py` emits per-call records using Ghidra decompiler P-code. Exact sink names and resolved thunks replace substring matching; non-call references and thunk-internal forwarding sites are excluded. Argument extraction follows COPY/CAST chains up to 12 steps, reads NUL-terminated literals from read-only memory (4096-byte limit), identifies direct getenv/NVRAM return values, and attempts exact-base stack-array capacity recovery from decompiler symbols. At most 200 callers are decompiled, with 30 seconds per caller; unsupported relations, exhausted budgets and extraction failures remain explicit gaps. No buffer capacity is inferred from stack-frame size.

`agent/agents/vulnerability.py` consumes these records without sample annotations or LLM calls. It compares strcpy literal length plus NUL against inferred capacity, compares snprintf's upper bound against capacity without claiming it is the actual output length, and flags direct input-return values used as shell commands. Literal commands are not automatically safe because shell expansion and the execution environment remain unchecked. Inferred capacity cannot prove safety or exploitability. This prototype emits leads, suspected issues or insufficient evidence; confirmed and safe conclusions are intentionally not emitted yet.

The audit node invokes assessment and reports conclusions, scope and evidence gaps. A script completion marker is required even when the Ghidra process exits with zero, preventing script failures from appearing as successful empty scans. Automatic evidence-driven follow-up, guard validation, cross-function/memory data-flow, indirect calls, and declarative rule loading remain future work.

Synthetic integration fixture: `tests/fixtures/vulnerability_cases.c`. Compile with `gcc -O0 -g -fno-builtin -o /tmp/oob-vulnerability-fixture tests/fixtures/vulnerability_cases.c`, then audit the binary normally. Do not execute the vulnerable functions. The fixture covers literal-copy boundaries, bounded formatting, an oversized bound with short actual output, environment-derived commands and literal commands. These tests do not establish real-firmware accuracy.

## Sample and implementation separation

Sample additions must not require edits to agent orchestration or detector code. Keep four independently evolving layers: audit orchestration, analysis engines, declarative rules/function models, and evaluation data. Rules describe general vulnerability conditions, never sample IDs, hashes, CVEs, or sample-specific addresses as detection shortcuts. New analysis primitives may still require engine changes; configuration cannot replace missing data-flow capabilities.

The evaluation corpus lives outside the runtime. Only artifact paths and ordinary analysis options enter an audit; expected conclusions and annotated locations remain evaluator-only. Development and held-out evaluation sets must separate related firmware families and patched/unpatched pairs to reduce leakage. Unknown ground truth is excluded from accuracy metrics. A negative label applies only to its stated vulnerability and scope, not to the entire binary.

Implemented foundation: `tools/sample_manifest.py` validates versioned JSON manifests, relative artifact paths, SHA-256 identity, and required reference presence for known expectations. It does not verify the reference's truth, run audits, or calculate detection accuracy. It is not imported by runtime agents. Real samples and private annotations can live in ignored `samples/local/` or outside the repository.

Example manifest (replace the hash with the actual file hash):

```json
{
  "schema_version": "2",
  "sample_id": "httpd-baseline",
  "artifact": "httpd",
  "sha256": "REPLACE_WITH_ACTUAL_SHA256",
  "split": "development",
  "vulnerability_type": "command_injection",
  "expected": "unknown",
  "scope": "HTTP command execution handling; not yet annotated",
  "case_kind": "insufficient_evidence",
  "origin": "real_world",
  "references": [],
  "evidence": [],
  "rationale": "No reviewed evidence is available yet",
  "limitations": "Execution baseline only; excluded from accuracy evaluation",
  "notes": "Execution smoke test only; not an accuracy benchmark"
}
```

Validate with `venv/bin/python -m tools.sample_manifest samples/local/httpd.json --artifact-root firmware`.

Version 2 supports the following annotation categories. Version 1 manifests remain readable for compatibility, but lack these stronger annotation requirements.

| case_kind | expected | Purpose |
| --- | --- | --- |
| known_vulnerability | vulnerable | Known vulnerable path |
| safe_argument | not_vulnerable | Dangerous API with a proven safe argument |
| effective_guard | not_vulnerable | Effective protection for the specified path |
| ineffective_guard | vulnerable | Protection present but ineffective |
| insufficient_evidence | unknown | Unresolved evidence; not a safe result |

For known conclusions, provide nonblank references and at least one evidence entry with `location` (function, call site, or source line) and `observation`. Every version 2 record requires `origin` (`real_world` or `synthetic`), a local `scope`, `rationale`, and `limitations`. A safe record must explain why the particular dangerous argument or path is protected, not declare the whole binary safe. An ineffective-guard record needs evidence that the vulnerability actually remains; merely uncertain protection belongs to `insufficient_evidence`. Validation checks structure and identity, not the semantic truth of annotations. Human review is still needed.

Prepare samples by identifying the file and hash, choosing a vulnerability type and local scope, recording the evidence and reference, and then selecting the category. For patched pairs, create two manifests with separate hashes and explain the changed protection in their annotations. A patch alone is not proof of safety. Start with a real vulnerability, effective protection, and ineffective protection for one vulnerability class; synthetic cases can supplement unavailable real controls.

Near-term analysis design (not implemented): deterministic rules retain uncertain candidates; program slicing requires data/control dependencies; retrieval combines structured filters and semantic similarity; a default of 2–3 examples is optional and bounded by a token budget; LLM conclusions must cite current-target evidence rather than retrieved examples. These are independent of corpus validation.

Deferred, not a prerequisite: full corpus/index/rule version management, automatic rule promotion, and a batch accuracy evaluator. Rule externalization and function models also remain pending. Timeouts and unsupported analysis must never be counted as safe results.

## Cross-file and cross-process analysis target

Vulnerability analysis must be able to expand beyond the initially selected binary. When a network-facing service calls a shared library function, the analysis should follow that dependency. When a backend reads a value through NVRAM helpers, the analysis should search for writers and external sources. The same chain should cover frontend requests, CGI handlers, Unix or TCP sockets, environment variables, temporary files, and other IPC boundaries.

The target data-flow record is:

```text
source file / function / input
        ↓
transport or shared state
        ↓
intermediate files, processes, libraries, and functions
        ↓
sink file / function / security effect
```

Each edge must record its evidence location and confidence, and distinguish observed relationships from LLM hypotheses. A chain that crosses multiple files must list the ordered file and function sequence. If analysis of one component fails, the chain remains partial and the report records the exact break point.

## Communication protocol

The supervisor-to-agent boundary uses structured messages. A task request contains a task ID, agent type, action, input artifacts, constraints, and requested outputs. An agent result contains status, observations, evidence, findings, errors, next action, and confidence.

The audit supervisor validates structured target selections. The optional emulation adapter accepts only execute/verify/need_user actions: execute commands are length-checked and dispatched through the private guest serial channel, never a host shell. This is guest root command execution, not a guest command allowlist or a guarantee against incorrect guest modifications. Firmware observations are treated as untrusted data. Acceptance checks and execution budgets are controlled by the tool rather than the model.

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
2. Improve the primary audit flow: candidate discovery, structured static evidence, `VulnerabilityAnalysisAgent`, cross-file data-flow analysis, multi-target auditing, and evidence-based reports.
3. Implement natural-language intent parsing and structured supervisor-to-agent dispatch.
4. Add dynamic analysis and trigger validation backends.
5. Add the independent `AngrExplorationAgent` flow. It reads a vulnerability task JSON/YAML, performs path validation and symbolic value solving, and does not receive or unpack firmware.
6. Add persistence, parallel analysis, resumable tasks, API access, and additional report formats.
7. Add independent model and provider configuration for each agent.

## Reusable emulation environment

### Goal and current boundary

A fresh installation should eventually guide a user from firmware input through dependency checks, extraction, environment selection/preparation, startup, diagnosis and terminal access without requiring an external procedure. Human assistance and unsupported-device outcomes remain legitimate, explicit results. Local successful cases are reusable caches, not prerequisites bundled with the public tool.

Currently implemented: independent sessions, a versioned adapter/environment protocol, shared firmware extraction, rootfs inspection, local data-disk creation/cache, explicit service selection and generated adapters, conservative environment matching, checksums, an opt-in Buildroot provider, guest script injection, SSH/console access, bounded LLM adaptation and cleanup. The unified natural-language interface remains pending. Fresh installations no longer require a private device case for preparation, but unsupported filesystems/architectures, encryption and vendor dependencies still require explicit intervention. Cold construction of all environments and arbitrary-firmware startup are not claimed as validated.

### Public tool versus private local assets

Transient model request failures are retried up to three consecutive attempts within the shared time/round budget; executed guest actions are not replayed. The `emulate resume ID` entry queues continuation in an existing waiting/degraded worker, preserving recent context and guest state while renewing the adaptation budget, not the session lifetime. Older workers explicitly reject resume. Management checks append to access-events.jsonl so successful later probes do not erase recovery evidence. Startup prompts favor bounded service attempts over repeated broad scans and distinguish subcommand errors from a compound command's final exit code.

For a user-facing walkthrough, see the [HG532 emulation guide](EMULATION.md). It documents commands and acceptance limits without distributing firmware or local case assets.

The public source includes the session manager, environment resolver, backend rules, Buildroot configurations, generic control/SSH overlay, templates and synthetic tests. Firmware-specific scripts, hashes, paths, vendor data disks, successful-case records and environment registrations stay in ignored local storage. No real-device case is required to run unit tests.

- `emulation/local/adapters/`: local trusted adapter JSON and scripts.
- `emulation/local/environments/`: local reusable environment registrations.
- `emulation/images/`: retained kernels and system/vendor disks.
- `emulation/runs/`: private temporary session overlays and sockets.
- `reports/emulation/`: private session state, logs and evidence.
- `emulation/sources/`, `downloads/`, `output/`: local Buildroot source, cache and build intermediates.

Do not publish these local directories or session SSH keys. `transfer/` contains only public code/configuration/templates/tests. Prebuilt generic environments may be offered separately for selective download; no complete image collection is bundled with the tool.

### Preparation protocol v1

`emulation/environment.py` separates input observations, adapter selection and environment reuse. Inspect without starting QEMU:

```sh
python3 main.py emulate firmware/example.bin --plan
python3 main.py emulate firmware/example.bin --adapter /path/to/trusted-adapter.json --plan
```

The read-only plan reports observed format/ELF architecture, registered requirements, selected local environment, diagnostics and next steps. ELF architecture observations cannot be overridden by a conflicting adapter. Opaque firmware architecture is not guessed from its filename; use the preparation path to inspect extracted executables.

States are PREPARED, NEEDS_ADAPTER, AMBIGUOUS_ADAPTER, NEEDS_ENVIRONMENT and UNSUPPORTED_BACKEND. Incomplete plans return a nonzero CLI exit status. No asset download, build or VM start occurs during planning.

Both manifest types require `schema_version: 1`, `kind`, `id` and `requirements`. Exact requirement matching uses architecture, endianness, bits, ABI, machine and control contract. This is a conservative declared compatibility check, not proof that proprietary hardware or kernel dependencies are satisfied. Runtime validation remains necessary. Environment selection uses deterministic manifest order and skips incompatible, missing or corrupt candidates with diagnostics.

Adapter manifests associate an input SHA-256 with requirements, a raw vendor disk, a startup script, network settings, optional HTTP readiness probe/HTTPS port and limitations. Hashes identify a particular local adaptation; they do not define which firmware the public tool is allowed to accept. Multiple adapters for the same input require explicit selection. Scripts are trusted executable guest instructions; firmware text is not treated as configuration automatically.

Environment manifests describe reusable kernel and raw system-disk assets. Assets specify a path relative to the manifest (absolute local paths are also supported) and SHA-256. Two different adapters with identical requirements reuse the same validated asset paths without copying a full base disk. Only per-session qcow2 layers are created. Asset integrity is checked during preparation and again before worker startup.

Templates are in `emulation/templates/*.json.example`; placeholders must be replaced before manual use. The preparation pipeline and Buildroot provider now generate this same protocol. Manual manifests remain available for custom adaptation; future LLM adjustment should also use this protocol instead of adding device-specific branches to the manager.

The current backend supports the MIPS32/o32 Malta layout with IDE system/vendor disks and PCnet. The big-endian baseline has runtime validation; little-endian command selection has unit coverage only. Other architecture/platform combinations return UNSUPPORTED_BACKEND. The `linux-serial-ssh-v1` contract means a Linux guest with user console ttyS0, manager login on ttyS1, root serial login, BusyBox/base64/network tools and key-only Dropbear on TCP 2222. It is not a universal QEMU hardware abstraction.

### On-demand environment preparation

For a new input use the Python environment with project dependencies installed:

```sh
venv/bin/python main.py emulate firmware/example.bin --prepare
venv/bin/python main.py emulate firmware/example.bin --prepare --service /usr/sbin/httpd --service-arg=-f --http-guest-port 80
```

The first command reuses cached preparation when valid, otherwise calls the shared `tools/extraction.py` pipeline also used by static auditing. It runs the existing Binwalk wrapper, then bounded SquashFS signature/offset discovery with unsquashfs/sasquatch fallbacks. If Binwalk reports rewriting symlink targets, that output is excluded from runtime rootfs selection and filesystem-specific extraction is attempted. Tool results remain in `extraction-tools.json`. Other filesystem extractors may be invoked by Binwalk; dedicated offset fallback currently covers SquashFS only.

The tool identifies candidate root filesystems and asks for `--rootfs PATH` when absent or ambiguous. This option also reuses a user-provided extraction. It resolves absolute symlinks inside the guest root, reads ELF architecture/ABI and PT_INTERP without executing firmware, and checks that the selected executable's dynamic linker exists. Full DT_NEEDED/library/hardware validation is not yet implemented. Mixed architectures require explicit service selection. Generated runtime preparation currently supports MIPS32/o32; other architectures fail with a stated backend gap.

Data disks are created locally using `mkfs.ext2 -d` without host root. Cache identity includes file content, modes, ownership and symlinks; corrupt disks are regenerated and rootfs changes select a new disk. Device nodes/other special files require explicit preparation; missing nodes or altered ownership from extraction are reported as limitations rather than silently declared equivalent. Rootfs size/entry limits and free-space checks apply before disk creation. Paths, hashes, tool logs, rootfs and generated adapters remain under ignored `emulation/local/`.

Preparation returns NEEDS_ROOTFS or NEEDS_SERVICE with actionable choices; it never guesses a service or runs vendor init on the host. Selecting `--service /guest/path` and optional repeated `--service-arg` generates a guest-only mount/start script. An optional `--http-guest-port` adds HTTP reachability verification. The generic script checks process presence after startup; it cannot replace vendor-specific initialization, configuration or hardware adaptation. Use `--adapter PATH` for an existing custom adaptation. New starts perform this preparation automatically; `--prepare` stops before booting, and `--plan` remains read-only.

Compatible local environment registrations are always preferred. If absent, retry with `--build-environment` to opt into source download/build for the one matching recipe; currently only the MIPS32 big-endian Malta recipe is available:

```sh
venv/bin/python main.py emulate firmware/example.bin --prepare --service /usr/sbin/httpd --build-environment --jobs 4 --build-timeout 7200
```

The provider checks host tools and free space, verifies the pinned source archive SHA-256, extracts it, configures a recipe-specific output directory, runs make with a clean PATH and saves build.log. Recipe identity covers Buildroot metadata, configuration, external-tree definitions and overlay contents/modes. Build failures/timeouts retain intermediates for retry; cancellation terminates the build process group. Successful artifacts are stored separately and checksummed into the environment registry. They are marked built, not boot-validated: session startup performs actual guest checks. No administrator package installation occurs automatically; missing prerequisites return an install suggestion. The provider's registration/reuse/failure paths have automated tests; a full fresh network download and cold toolchain build were not rerun during this change.

The future optional prebuilt-image provider will use the same requirement matching. Image collections are not downloaded eagerly. Tool versions and environment versions are independent. Cache inventory/quotas and crash-safe garbage collection remain future work.

Buildroot is an offline preparation backend, not something to rebuild for each firmware. The pinned source release/checksum is in `emulation/configs/buildroot.json`. `python3 emulation/scripts/check_environment.py` checks local prerequisites. The external tree is `emulation/`; configure its Malta defconfig using `BR2_EXTERNAL` and `BR2_DEFCONFIG`, a separate output directory, shared download directory and a clean Linux PATH. Current configuration includes Dropbear, a second serial getty, networking tools and bridge support. The overlay contains no vendor service startup scripts.

Store an accepted kernel and system disk in local asset storage and register their checksums. Never overwrite an image used by an active session. Buildroot incremental targets can retain files removed from an overlay; remove obsolete vendor files from the build target or perform a clean target rebuild before accepting a generic image. Verify image contents. Retain useful build/download caches separately from accepted runtime assets.

### Managed sessions and user access

Start using a locally discovered or explicitly selected trusted adapter:

```sh
python3 main.py emulate firmware/example.bin
python3 main.py emulate firmware/example.bin --network tap --tap-ifname oobtap0
```

Preparation runs in the foreground with diagnostics/build logs; once assets are ready, startup returns a session ID and the worker runs in the background. The worker boots the selected environment, installs a per-session SSH public key, uploads the adapter script in bounded chunks through ttyS1, executes it, restores network settings and checks SSH plus any configured HTTP probe. The adapter must return nonzero if required service startup fails. Without an HTTP probe, READY means adapter success and SSH access, not web-service verification. A returned HTTP status is connectivity evidence, not vulnerability confirmation.

Replace SESSION with the identifier:

```sh
python3 main.py emulate list
python3 main.py emulate status SESSION
python3 main.py emulate console SESSION
python3 main.py emulate exec SESSION --command 'uname -m' --timeout 15
python3 main.py emulate stop SESSION
```

READY status supplies a verified SSH command. Host keys are pinned using keys collected through the control serial channel. SSH enters the generic Linux system; the adapter determines where vendor files are mounted. Console is independent of Agent commands; Ctrl+] detaches without stopping QEMU. Session lifetime defaults to 1800 seconds and is configurable at startup. Guest commands have a maximum 120-second deadline; command timeout fails/stops the session to avoid uncontrolled continuing work.

### LLM-assisted guest adaptation

Use the existing project `.env` configuration: OPENAI_API_KEY, OPENAI_BASE_URL, IOT_AUDIT_MODEL and IOT_AUDIT_REASONING_EFFORT (medium when unspecified). The shared model client and environment loader are reused; emulation does not maintain another credential/model configuration. Credentials are inherited by the worker, never placed in session JSON, the guest or model prompts. Model event logs record request outcome, model name and reasoning setting, not API keys.

```sh
venv/bin/python main.py emulate firmware/example.bin --adapt --goal "Start and maintain the target network service" --expect-process httpd --expect-port 80
```

When no adapter exists, preparation generates a bootstrap that mounts the extracted firmware but does not start a vendor service. At least one process or TCP-listener acceptance condition must be specified independently of the model. Existing custom adapters can still initialize the guest; the fresh-adaptation test uses only a generated bootstrap and generic environment, never local successful-case instructions.

The worker establishes the management/control channels and enters ADAPTING. The model receives the user's goal, environment contract, management IP and bounded recent guest observations. It may request one execute, verify or need_user action per turn. Commands are limited to 2000 characters and run only through the guest serial channel, with a 30-second maximum command deadline. Shell commands have guest root privileges; there is no model tool for host filesystem access, sudo or host networking. The model is instructed to treat firmware contents as evidence rather than instructions. A timed-out command triggers serial interruption/recovery; unrecoverable control-channel failure stops the session.

Default limits are 12 model calls, a 600-second adaptation time budget and a 60-second observation window; override using --adapt-rounds, --adapt-timeout and --observe-seconds. Request timeouts and no-progress detection are enforced. Initial attempts and health-regression recovery share the total budget. A model verify action invokes deterministic process/listener sampling every five seconds across the observation window. The model cannot change these checks or set READY itself. Checks establish sampled process/listener availability, not hardware equivalence or vulnerability confirmation.

Successful adaptation is followed by SSH verification and any configured HTTP probe. SSH failure triggers serial diagnostics, restoration of the configured eth0 management address if missing, and one retry. No host networking or guest firewall is changed. If SSH remains unavailable, access_mode is console with an explicit error and console/exec commands; SSH alone no longer blocks READY. Management access is checked again every thirty seconds outside active adaptation, with the latest diagnostics in access.json. Service readiness and optional HTTP acceptance remain separate from management access. While READY, process/port health is sampled every ten seconds. Regression changes status to DEGRADED and invokes further adaptation only if budget remains. A model error, unresolved dependency or exhausted adaptation budget retains the working base VM as WAITING_ADAPTATION for user SSH/console/exec access. Without recovery budget a degraded session remains available for manual inspection. Infrastructure failures (QEMU exit, missing control channel or unusable base system), explicit stop and session expiry still clean up. Exec requests are supported in READY, WAITING_ADAPTATION and DEGRADED; during active adaptation use the independent console/SSH instead of competing for the command channel.

Local evidence includes llm-events.jsonl (request success/failure), adaptation.jsonl (model actions), actions.jsonl/control.log (executed commands and results), health.jsonl (independent checks) and adaptation-result.json. Successful executed commands can produce adaptation-draft.sh plus metadata marking replay_verified=false. The draft may contain diagnostic commands and is not automatically registered as a trusted reusable adapter; a fresh-session replay check is still needed. All generated firmware data, model traces and drafts remain local and excluded from transfer/GitHub. Reaching READY once does not establish indefinite stability; inspect later health status.

Local mode uses restricted QEMU user networking and loopback forwards: host 12222 to management SSH 2222, host 18080 to the adapter's HTTP probe port if present, and host 18443 to its declared HTTPS port if present. Override with distinct `--ssh-port`, `--http-port`, `--https-port`. The manager configures 10.0.2.15 and the 10.0.2.2 default return route after vendor startup. Legacy application TLS compatibility is separate from network reachability.

TAP mode uses an existing user-owned interface and direct guest access; forwarding options are rejected. Check host routes for conflicts before creating a dedicated subnet. For an adapter using guest 192.168.100.2/24, the user may run these host administrator commands:

```sh
sudo ip tuntap add dev oobtap0 mode tap user "$(id -un)"
sudo ip addr add 192.168.100.1/24 dev oobtap0
sudo ip link set dev oobtap0 up
```

The manager does not alter host default routes, bridges or firewall rules. It locks the selected TAP against reuse by other managed sessions; older manual QEMU processes are outside this registry. Windows access through WSL requires separate routing/firewall setup. A sudo invocation drops to the invoking ordinary account before session execution; privileged provisioning is not automated yet. Direct root startup without an ordinary sudo caller is rejected.

Stop, infrastructure failure and expiry terminate QEMU before removing session overlays and private client keys. Vendor service failure retains a debuggable base session instead. Base images, host TAPs and evidence remain. Once no session uses a dedicated TAP, it can be removed with `sudo ip tuntap del dev oobtap0 mode tap`. SIGTERM/SIGINT request worker shutdown. SIGKILL or host crashes may leave orphaned resources; status diagnoses missing worker locks but automatic recovery is not implemented. The backend requires Linux and UNIX socket paths of supported length.

New preparation directories and disk files use a sanitized firmware stem plus a 12-character content hash. Generated adapters retain an `auto-` or `bootstrap-` prefix. Full hashes remain in metadata for identity checks; renamed inputs reuse matching caches and existing hash-only paths remain supported without moving active assets. Short-hash collisions use the remaining hash as a suffix.

The older `emulation/scripts/start_malta.py` remains a manual console utility for prepared assets, not the managed Agent entry. New firmware-specific behavior belongs in local adapters, not that runner or the generic Buildroot overlay.

## Release strategy

The project version is stored in `VERSION`. Releases use semantic versioning and Git tags:

```text
VERSION=0.1.0-beta.2
git tag -a v0.1.0-beta.2 -m "OOB Beyond 0.1.0-beta.2"
git push origin v0.1.0-beta.2
```

Patch releases contain fixes, minor releases add backward-compatible capabilities, and major releases may change agent protocols or report schemas.

Beta releases remain prereleases on GitHub. See CHANGELOG.md for user-facing changes and validation limits.
