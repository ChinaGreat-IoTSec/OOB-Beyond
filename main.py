"""Interactive entrypoint for the multi-agent firmware audit system."""

import argparse
from datetime import datetime
import os
from pathlib import Path
import re
import uuid

from rich.console import Console

from agent.graph import app
from agent.states import FirmwareAuditState, FirmwareMeta


def _load_env_file() -> None:
    env_file = Path(".env")
    if not env_file.is_file():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        key = key.strip()
        if separator and key and key not in os.environ:
            os.environ[key] = value.strip().strip('"').strip("'")


def run_audit(source: Path, console: Console, input_type: str = "auto") -> int:
    if not source.exists():
        console.print(f"[red]路径不存在:[/red] {source}")
        return 1
    task_id = str(uuid.uuid4())
    target_name = re.sub(r'[^\w.-]+', '_', source.resolve().name)[:100]
    timestamp = datetime.now().astimezone().strftime('%Y%m%d_%H%M%S_%f')
    report_path = Path.cwd() / "reports" / f"{target_name}_审计报告_{timestamp}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    initial = FirmwareAuditState(
        task_id=task_id,
        requested_input_type=input_type,
        firmware_meta=FirmwareMeta(
            firmware_path=str(source.resolve()), file_size=0, sha256="0" * 64
        ),
        report_path=str(report_path),
    )
    final = initial
    for update in app.stream(initial, stream_mode="updates"):
        for node_name, node_state in update.items():
            if isinstance(node_state, dict):
                final = final.model_copy(update=node_state)
            console.print(f"[cyan]{node_name}[/cyan]: {final.status}")
            if node_name == "ingest" and final.status != "FAILED":
                console.print(f"输入类型：请求 {final.requested_input_type} → 实际 {final.input_type}")
    if final.error_message:
        console.print(f"[red]{final.error_message}[/red]")
        return 1
    console.print(f"[green]complete[/green]: {final.status}; report: {report_path}")
    console.print(f"阅读报告：{report_path.with_suffix('.md')}", markup=False)
    return 0


def interactive(console: Console, input_type: str = "auto") -> int:
    console.print("[bold]IoT 多 Agent 固件审计工作台[/bold]")
    console.print("输入文件或目录路径分析；输入 scan 查看当前目录，输入 q 退出。")
    console.print("输入 type auto|binary|firmware|directory 切换后续任务的输入类型。")
    while True:
        try:
            command = console.input("[bold cyan]audit> [/bold cyan]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return 0
        if not command:
            continue
        if command.lower() in {"q", "quit", "exit"}:
            return 0
        if command.startswith("type "):
            requested = command[5:].strip()
            if requested in {"auto", "binary", "firmware", "directory"}:
                input_type = requested
                console.print(f"输入类型已设置为 {input_type}")
            else:
                console.print("类型必须为 auto、binary、firmware 或 directory")
            continue
        if command.lower() == "scan":
            for index, path in enumerate(sorted(Path.cwd().iterdir()), 1):
                console.print(f"{index}. {path}")
            continue
        run_audit(Path(command).expanduser(), console, input_type)


def main() -> int:
    _load_env_file()
    parser = argparse.ArgumentParser(description="Interactive IoT firmware audit agent")
    version_file = Path(__file__).with_name("VERSION")
    version = version_file.read_text(encoding="utf-8").strip() if version_file.is_file() else "0.0.0"
    parser.add_argument("--version", action="version", version=version)
    parser.add_argument("--input", "--firmware", dest="source", type=Path, help="optional initial file or directory")
    parser.add_argument("--input-type", choices=["auto", "binary", "firmware", "directory"], default="auto", help="explicit type overrides auto detection; binary supports ELF, PE and thin Mach-O")
    args = parser.parse_args()
    console = Console()
    return run_audit(args.source, console, args.input_type) if args.source else interactive(console, args.input_type)


if __name__ == "__main__":
    raise SystemExit(main())
