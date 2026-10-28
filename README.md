<div align="center">

# OOB Beyond（无界）

**AI-assisted Multi-Agent IoT Firmware Security Audit Framework**

**OOB IoT Sec Labs 开源安全研究工具**

</div>

OOB Beyond（无界）是由 [OOB IoT Sec Labs](https://oobsec.cn) 开发的交互式多 Agent IoT 固件安全审计框架，面向嵌入式系统、固件、文件系统和二进制安全研究。

项目结合 LLM、LangGraph、Binwalk 和 Ghidra，完成固件导入、解包、攻击面发现、静态扫描和报告生成。当前交互入口接受路径与命令，LLM 用于候选目标选择和部分异常诊断；自然语言任务规划与 LLM 漏洞研判仍在开发中。

> 当前版本：`0.1.0-beta.2`，处于内测阶段。更新内容见 [CHANGELOG.md](CHANGELOG.md)。

## 核心能力

- 支持固件镜像、ELF / PE / 单架构 Mach-O 二进制和已解包目录
- 输入已识别的二进制时直接审计指定文件；目录输入直接进入候选筛选
- 交互式审计会话和一次性命令行调用
- SupervisorAgent 使用 LLM 选择优先审计目标
- 候选目标优先用唯一 ID 匹配，并兼容原路径、规范化路径和唯一后缀；歧义或无效选择请求模型纠正一次，仍无法确定时按规则排序兜底，报告明确注明依据，不沿用模型原理由。模型连接错误仍明确报错。
- Intake、Unpack、Triage、Audit、Report 等专业工作节点
- RecoveryAgent 负责工具错误和异常诊断
- 支持 Binwalk、SquashFS 工具和 Ghidra Headless
- 发现 Web 服务、CGI、启动服务和网络 API 线索
- 输出 Markdown 阅读报告和结构化 JSON 数据
- Ghidra 输出 Sink 地址、调用者、调用位置和输入 API 线索
- 确定性漏洞分析原型：逐调用点比较 `strcpy` 字面量长度（包含终止符）与推断栈数组容量，比较 `snprintf` 大小参数与容量，追踪直接 `getenv` / NVRAM 返回值到 `system` / `popen`；报告保留判断依据和证据缺口，不依赖 LLM
- 支持 OpenAI 兼容 API 和可配置推理级别

当前参数分析限于函数内部分 P-code 关系；栈数组容量依赖反编译类型恢复，未知容量不会被当作安全。尚未实现完整跨函数数据流、防护有效性证明和路径可达性验证，因此结果仍为线索、疑似或证据不足，不代表已确认可利用漏洞。

## 快速开始

安装 Python 依赖：

```bash
python -m venv venv
venv/bin/pip install -r requirements.txt
```

复制模型配置模板：

```bash
cp .env.example .env
```

根据实际模型服务修改 `.env`：

```env
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_API_KEY=your-api-key
IOT_AUDIT_MODEL=gpt-4.1-mini
IOT_AUDIT_REASONING_EFFORT=medium
```

启动交互式工作台：

```bash
venv/bin/python main.py
```

也可以直接分析固件：

```bash
venv/bin/python main.py --firmware ./firmware.bin
```

交互式输入支持：

```text
audit> ./firmware.bin
audit> ./httpd
audit> ./extracted-rootfs
audit> scan
audit> q
```

## 输入类型

`--input` 与兼容参数 `--firmware` 接收相同的输入路径。`--input-type` 默认 `auto`，显式类型优先：

```bash
venv/bin/python main.py --input firmware/nsppe --input-type binary
venv/bin/python main.py --input firmware/router.bin --input-type firmware
venv/bin/python main.py --input rootfs/ --input-type directory
```

- `auto`：目录进入目标筛选，已识别的 ELF、PE、单架构 Mach-O 直接审计，其他普通文件尝试固件解包。
- `binary`：支持 ELF（可执行文件、`.so`、`.ko`、ELF `.o`）、PE（`.exe`、`.dll`、`.sys`、`.efi`）和单架构 Mach-O（含 `.dylib`）；直接审计指定文件，不调用 Supervisor 选择目标。按文件头识别，不依赖扩展名或执行权限。文件需未压缩；归档 `.a/.lib`、Universal Mach-O、裸二进制和脚本暂不支持直接审计。
- `firmware`：即使文件是 ELF，也执行解包；失败时不会改为单文件审计。
- `directory`：必须是目录，跳过解包。

交互模式可输入 `type binary` 等切换后续任务的类型，再输入文件路径。终端和报告记录请求类型与实际类型。裸二进制的架构与加载地址配置尚未支持。

```text
固件镜像 → 解包 → 目标筛选 → LLM 选择目标 → Ghidra 扫描 → 报告
已解包目录 ────→ 目标筛选 → LLM 选择目标 → Ghidra 扫描 → 报告
单个二进制 ───────────────────────────→ Ghidra 扫描 → 报告
```

架构与演进方向见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。当前单个二进制的正常分析流程不调用 LLM。

## 阅读审计报告

新报告保存在运行目录的 `reports/` 中，命名为 `目标名称_审计报告_YYYYMMDD_HHMMSS_微秒`（本地时间）。每次生成同名 `.md` 和 `.json`：Markdown 用于阅读摘要、总控决策和待验证线索，JSON 保留完整候选目标及详细数据。危险函数引用不等于已确认漏洞；当前日志也不能完整证明所有工具成功执行。

## 独立固件仿真

完整操作示例见 [HG532 仿真使用指南](docs/EMULATION.md)，包含 TAP 配置、模型适配、console/SSH 接入和服务验证。

仿真入口独立于静态审计。先检查输入、本地适配和可复用环境：

```bash
python3 main.py emulate firmware/example.bin --plan
```

返回 `PREPARED` 后，去掉 `--plan` 即可启动。使用 `python3 main.py emulate status 会话ID` 查看进度；达到 `READY` 后，复制 SSH 命令接入，或使用 `python3 main.py emulate console 会话ID`。使用 `python3 main.py emulate stop 会话ID` 停止并清理临时磁盘。默认 local 模式无需配置 TAP；使用已有 TAP 时添加 `--network tap --tap-ifname oobtap0`。

工具不捆绑真实固件、设备专用脚本或完整基础镜像库。本地适配和镜像登记放在忽略目录 `emulation/local/`；模板位于 `emulation/templates/`。基础镜像按环境需求复用，专用脚本在运行时注入。

首次使用可自动解包、识别 rootfs 和架构、制作并缓存数据盘；使用已安装项目依赖的 Python 环境：

```bash
venv/bin/python main.py emulate firmware/example.bin --prepare
```

工具会列出服务候选，请用 `--service /固件内程序路径` 选择需要启动的程序；可重复使用 `--service-arg` 传参。已有解包目录可指定 `--rootfs PATH`。基础环境优先复用本地资产，缺失时添加 `--build-environment` 允许按需下载 Buildroot 源码并构建。准备成功后去掉 `--prepare` 启动会话。

也可使用现有 `.env` 中的模型配置进行 guest 内自动适配，明确目标和独立验收条件：

```bash
venv/bin/python main.py emulate firmware/example.bin --adapt --goal "启动并保持目标网络服务运行" --expect-process httpd --expect-port 80
```

模型只能通过 guest 控制通道执行命令；启动与后续恢复共用轮数/时间预算。进程和端口需通过持续观察才会报告 `READY`；未解决的问题保留为 `WAITING_ADAPTATION`，运行后退化显示 `DEGRADED`，可通过 SSH/console 或 `exec` 接管。SSH 失败时通过串口检查网络，恢复丢失的预定 eth0 管理地址并复测；仍失败则报告 `access_mode: console`、错误和接入命令，不单独阻止服务进入 READY。每 30 秒重新检查管理接入；`access.json` 保留最近检查的诊断信息。查看会话目录的 `llm-events.jsonl`、`adaptation.jsonl` 和 `health.jsonl` 可核对调用与验证结果。适配草案仅保留本地，未经全新会话重放验证，不自动注册为成功适配。

当前自动构建配方支持 MIPS32 大端 Malta，不保证所有固件都能运行。专有硬件依赖仍可能需要人工参与；统一自然语言交互界面尚未接入。默认会话时限 1800 秒，详见 [架构文档](docs/ARCHITECTURE.md#managed-sessions-and-user-access)。

临时模型请求错误在总预算内最多连续尝试三次。失败后可用 `venv/bin/python main.py emulate resume 会话ID` 在同一虚拟机继续适配，保留历史并重新授予适配预算，不延长会话寿命；仅新版 worker 的等待/退化会话支持。管理接入历史保存在 `access-events.jsonl`。

## 外部工具

完整分析需要在 `PATH` 中安装：

- `binwalk`
- `sasquatch`
- `unsquashfs`
- `jefferson`
- Ghidra 11.x 的 `analyzeHeadless`

## License

本项目采用 [MIT License](LICENSE)。
