<div align="center">

# OOB Beyond（无界）

**AI-assisted Multi-Agent IoT Firmware Security Audit Framework**

**OOB IoT Sec Labs 开源安全研究工具**

</div>

OOB Beyond（无界）是由 [OOB IoT Sec Labs](https://oobsec.cn) 开发的交互式多 Agent IoT 固件安全审计框架，面向嵌入式系统、固件、文件系统和二进制安全研究。

项目结合 LLM、LangGraph、Binwalk 和 Ghidra，完成固件导入、解包、攻击面发现、静态扫描和报告生成。当前交互入口接受路径与命令，LLM 用于候选目标选择和部分异常诊断；自然语言任务规划与 LLM 漏洞研判仍在开发中。

> 当前版本：`0.1.0-beta.1`，处于内测阶段。

## 核心能力

- 支持固件镜像、ELF / PE / 单架构 Mach-O 二进制和已解包目录
- 输入已识别的二进制时直接审计指定文件；目录输入直接进入候选筛选
- 交互式审计会话和一次性命令行调用
- SupervisorAgent 使用 LLM 选择优先审计目标
- Intake、Unpack、Triage、Audit、Report 等专业工作节点
- RecoveryAgent 负责工具错误和异常诊断
- 支持 Binwalk、SquashFS 工具和 Ghidra Headless
- 发现 Web 服务、CGI、启动服务和网络 API 线索
- 输出 Markdown 阅读报告和结构化 JSON 数据
- 支持 OpenAI 兼容 API 和可配置推理级别

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

## 外部工具

完整分析需要在 `PATH` 中安装：

- `binwalk`
- `sasquatch`
- `unsquashfs`
- `jefferson`
- Ghidra 11.x 的 `analyzeHeadless`

## License

本项目采用 [MIT License](LICENSE)。
