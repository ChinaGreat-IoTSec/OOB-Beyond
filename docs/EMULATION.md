# 固件仿真实例：HG532

本文介绍如何使用 OOB Beyond（无界）启动独立固件仿真、让模型进行适配、接入虚拟机并验证服务。示例目标为 HG532 的 mic/upnp 服务，不涉及漏洞利用。不同固件版本可能有不同依赖，示例不保证所有 HG532 镜像均可运行。

工具负责解包、生成数据盘、复用或按需构建基础环境、启动 QEMU，并通过 guest 串口让模型执行有预算限制的调整。真实固件、设备适配、镜像和运行记录由用户本地保存，不随源码提供。

## 1. 准备环境

在 Linux 或 WSL2 的项目根目录执行命令。先按 [README](../README.md#快速开始) 安装 Python 依赖并配置 `.env`；已有配置无需覆盖。仿真复用 `OPENAI_API_KEY`、`OPENAI_BASE_URL`、`IOT_AUDIT_MODEL`、`IOT_AUDIT_REASONING_EFFORT`，默认推理强度为 medium。模型需要能访问配置的服务地址。

Ubuntu 的基本运行依赖可由用户安装：

```bash
sudo apt install -y qemu-system-mips qemu-utils e2fsprogs openssh-client iproute2 binwalk squashfs-tools
```

某些厂商修改过的 SquashFS 还需要安装兼容的 Sasquatch 并加入 PATH。若解包失败，查看准备目录中的 `extraction-tools.json`，不要把缺失的 rootfs 当作成功结果。

首次需要构建基础环境时，安装构建依赖：

```bash
sudo apt install -y build-essential git wget rsync cpio unzip bc file patch perl xz-utils flex bison libncurses-dev libssl-dev
```

当前自动构建配方支持 MIPS32 大端 Malta。基础环境是通用内核和 Buildroot 根文件系统，固件自身放在独立数据盘中。兼容资产存在时直接复用，不为每个固件重复构建。首次构建需要联网、时间和磁盘空间；工具会检查依赖和空间并提供错误信息。完整冷构建在不同新系统上的成功率仍需验证。

将你有权使用的 HG532 固件放入 `firmware/`，下文统一使用 `firmware/hg532.bin`，请替换为实际文件名。固件不会被修改。

## 2. 选择网络

### TAP：直接访问虚拟机 IP

本例采用 TAP，宿主地址为 `192.168.100.1/24`，guest 管理地址为 `192.168.100.2`。先确认该网段不与已有网络或 VPN 冲突，且没有其他运行中的虚拟机占用接口：

```bash
ip addr show
```

仅在尚未创建接口时执行：

```bash
sudo ip tuntap add dev oobtap0 mode tap user "$(id -un)"
```

配置宿主 TAP 地址并启用接口：

```bash
sudo ip addr replace 192.168.100.1/24 dev oobtap0
sudo ip link set oobtap0 up
```

这里不修改宿主默认路由，也不把上网网卡加入桥接。工具使用已有 TAP，不自动执行宿主 sudo 网络操作。TAP 模式不能附带 `--http-port`、`--https-port` 或 `--ssh-port`。

在 WSL2 内执行测试可直接访问 guest IP；Windows 浏览器能否访问该网段取决于 Windows/WSL 路由，不能由 WSL 内访问成功推断。

### local：无需 TAP

若不准备 TAP，可从启动命令中去掉 `--network tap --tap-ifname oobtap0`。默认 local 模式使用 loopback 转发：HTTP 18080、HTTPS 18443、管理 SSH 12222。可用三个对应参数更换宿主端口。默认不转发 37215，验证该服务可用串口在 guest 内发起请求。

## 3. 启动模型适配

```bash
venv/bin/python main.py emulate firmware/hg532.bin --network tap --tap-ifname oobtap0 --adapt --goal '准备必要运行目录和依赖后，先启动upnp，再启动mic。记录启动顺序和输出，避免重复启动；若upnp退出或等待mic，记录实际情况。通过无副作用的正常请求验证服务可用性，不进行漏洞利用，保留管理网络。' --expect-process mic --expect-port 37215 --adapt-rounds 20 --adapt-timeout 600 --observe-seconds 60 --timeout 3600 --build-environment --build-timeout 14400
```

这条命令允许缺少兼容基础镜像时按需构建；已有镜像时复用。`--build-timeout 14400` 为构建最多等待 4 小时，`--adapt-timeout 600` 为模型适配总预算 10 分钟，`--timeout 3600` 为会话寿命 1 小时。达到预算不代表适配成功。

不需要先执行 `--prepare`。若只想准备而不启动，在同一命令末尾添加 `--prepare`，准备完成后去掉该参数重新执行。只读查看已有适配与环境可使用：

```bash
venv/bin/python main.py emulate firmware/hg532.bin --plan
```

首次显示 `NEEDS_ADAPTER` 是没有设备适配缓存，不等于工具无法解包；正常启动的 `--adapt` 流程会继续准备。准备失败时按输出中的 `next_steps` 处理。

“先 upnp 后 mic”是本例的验证要求，不是所有版本的通用启动规则。模型可能观察到独立 upnp 退出，随后 mic 派生新的 upnp。不要只凭进程名判断生命周期，也不要在模型调整时重复手动启动服务。

启动返回 `session_id` 和 `STARTING`，表示后台任务已创建，不代表服务就绪。下文的 `emu-实际编号` 均需替换成真实会话编号。

## 4. 查看进度与结果

```bash
venv/bin/python main.py emulate list
venv/bin/python main.py emulate status emu-实际编号
```

| 状态 | 含义与下一步 |
| --- | --- |
| STARTING / BOOTING / INITIALIZING | 正在启动虚拟机、挂载固件并初始化控制通道 |
| ADAPTING | 模型正在操作，查看动作与模型调用记录 |
| READY | 配置的服务检查通过，结合 access_mode 选择接入方式 |
| WAITING_ADAPTATION | 服务适配未完成，查看 adaptation.reason 并使用 console/exec 排查 |
| DEGRADED | 后续服务健康检查失败；有剩余预算时可能继续适配 |
| FAILED | 基础设施或控制通道失败，查看状态错误和日志 |
| STOPPED / EXPIRED | 已停止或到期，不再接受终端接入 |
| ORPHANED | worker 状态异常，先检查残留进程，不要盲目删除运行文件 |

查看模型调用、执行动作以及最终结果：

```bash
tail -F reports/emulation/emu-实际编号/llm-events.jsonl
```

```bash
tail -F reports/emulation/emu-实际编号/adaptation.jsonl
```

```bash
cat reports/emulation/emu-实际编号/adaptation-result.json
```

日志在对应阶段才生成，`tail -F` 初次提示文件不存在可等待生成；Ctrl+C 仅结束日志查看。`actions.jsonl` 保存命令结果，`health.jsonl` 保存独立进程/端口检查，`worker.log`、`qemu.log` 和 `control.log` 用于排查基础环境。

本例的自动验收是 mic 存在、TCP 37215 监听且通过 60 秒观察，不强制 upnp 常驻。模型要求的协议请求仍需核对实际输出。`adaptation-result.json` 是阶段结果，当前状态应以 `status` 为准；READY 不等于完整设备功能或漏洞验证成功。

## 5. 接入虚拟机

SSH 可用时，复制 `status` 返回的 `ssh` 命令执行。工具使用独立会话密钥和固定校验的 guest 主机公钥；不要改为关闭主机公钥检查。

生成的 SSH 命令包含 `ServerAliveInterval=5` 和 `ServerAliveCountMax=2`，服务端无响应时通常约十余秒断开。TAP 下停止 QEMU 不一定立即通知已有 SSH 客户端；旧连接不会自动获得新保活选项。若终端仍停留，可按 Enter 后输入 `~.` 主动断开。宿主 SSH 进程短暂存在不代表虚拟机仍在运行，应结合 status 的 STOPPED/cleaned 和 QEMU 进程判断。

无论 SSH 是否可用，都可以通过独立串口 console 接入：

```bash
venv/bin/python main.py emulate console emu-实际编号
```

按 Enter 获取提示符，以 `root` 登录。按 **Ctrl+]** 断开 console，虚拟机继续运行。该终端是 Buildroot 基础系统，固件根文件系统挂载于 `/firmware`，必要时使用 `chroot /firmware /bin/sh` 进入固件环境。

也可通过管理串口执行一次性命令：

```bash
venv/bin/python main.py emulate exec emu-实际编号 --command "ip addr; ip route; netstat -lnt; pidof mic; pidof upnp"
```

`exec` 支持 READY、WAITING_ADAPTATION、DEGRADED；ADAPTING 时不与模型争用控制通道。单次命令最长 120 秒。

### SSH 失败怎么办

新版工具在 SSH 失败后通过串口读取诊断，若 eth0 丢失预定管理地址则恢复并复测。仍失败时提供 `access_mode: console`、`access_error`、`access_warning` 和 `next_steps`，不再仅因 SSH 不可达阻止服务进入 READY。非适配阶段每 30 秒重新检查管理接入。

```bash
cat reports/emulation/emu-实际编号/access.json
```

固件可能修改地址、路由或防火墙。工具只自动恢复缺失的预定 eth0 地址，不盲目修改防火墙或宿主路由。复杂问题使用状态给出的 console/exec 接管。模型适配预算耗尽不会无限调用模型。运行中的旧 worker 不会随源码修改自动升级，需要新会话使用新逻辑。

### 模型超时后继续适配

模型请求遇到超时、连接错误或限流等临时错误时，在剩余总预算内最多连续尝试三次；重试也计入轮数，不重放已经执行的 guest 命令。仍失败则保留虚拟机和历史，不自动宣称服务已经就绪。

修复模型服务或网络问题后，对 WAITING_ADAPTATION/DEGRADED 会话执行：

```bash
venv/bin/python main.py emulate resume emu-实际编号
```

这会为同一会话重新授予一轮配置的适配预算，保留近期历史和磁盘状态，但不延长虚拟机总寿命。命令返回 resume_requested 后，用 status 查看后续进度。旧版 worker 不支持热升级，命令会提示创建新会话。适配期间请不要与模型同时手工修改服务。

管理接入的历史检查和恢复动作追加到 `access-events.jsonl`；`access.json` 仅表示最近一次检查。验证自动恢复时应检查历史记录，而不是仅看当前 SSH 可达。

## 6. 验证实际服务

在宿主 Linux/WSL 终端发起正常只读请求：

```bash
curl -v --max-time 10 http://192.168.100.2:37215/upnpdev.xml
```

或在虚拟机内请求，区分服务故障和 TAP 网络故障：

```bash
venv/bin/python main.py emulate exec emu-实际编号 --command "wget -S -T 5 -O /tmp/upnpdev.xml http://127.0.0.1:37215/upnpdev.xml && head -c 500 /tmp/upnpdev.xml"
```

这个路径适用于提供该设备描述的版本，其他版本需按实际配置选择路径。有效设备描述 XML 是比“端口监听”更强的功能证据；HTTP 401/404 只能说明服务返回了响应，不代表目标功能已验证。

如果 upnp 会退出，等待退出后重复同一只读请求，并核对进程、日志和响应，确认是否按需唤起。退出码 0 不等于功能正常；端口仍监听也不等于请求一定有人处理。

Web 登录页面可从 `http://192.168.100.2/` 尝试访问。HTTP 307 表示重定向，旧固件 HTTPS 可能因 TLS 版本或重协商兼容性被现代客户端拒绝；不要把此类错误直接归因于 QEMU 或 UPnP 服务。

## 7. 停止、复用和提交范围

```bash
venv/bin/python main.py emulate stop emu-实际编号
```

停止会清理临时磁盘层、socket 和会话私钥，保留诊断记录。运行期间写入 guest 的更改不会自动写回通用镜像或固件数据盘。再次启动会复用准备缓存，但模型生成的 `adaptation-draft.sh` 尚未经过全新会话回放，不会自动成为可信设备适配。

新准备目录使用“固件名-12位短哈希”，数据盘采用 rootfs 指纹，适配文件保留 bootstrap/auto 前缀。完整哈希保存在元数据中；旧的纯哈希缓存仍兼容。希望测试无设备缓存的适配时，先停止对应会话，再按适配 JSON 和状态中的路径核对并清理该固件缓存；不要删除通用环境登记或正在使用的镜像，也不要仅凭文件名批量清理。

公开仓库保留程序、通用构建配置、测试及本文。`firmware/` 内的真实固件、`emulation/local/`、镜像、构建缓存、运行目录、`reports/`、`.env` 和密钥仅保留本地，不复制到 GitHub。有关实现边界与环境协议，见 [架构文档](ARCHITECTURE.md)。
