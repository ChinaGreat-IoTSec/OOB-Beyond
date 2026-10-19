"""Ghidra headless project lifecycle."""

from pathlib import Path
from typing import Optional

from .base import BaseAuditTool, ToolResult


class GhidraRunner(BaseAuditTool):
    def __init__(self, ghidra_path: str = "analyzeHeadless", timeout: int = 900) -> None:
        super().__init__(timeout)
        self.ghidra_path = ghidra_path

    @property
    def executable(self) -> str:
        return self.ghidra_path

    def analyze(self, binary: Path, project_dir: Path, script_dir: Optional[Path] = None) -> ToolResult:
        project_dir.mkdir(parents=True, exist_ok=True)
        project_name = f"audit_{binary.name}"
        args = [str(project_dir), project_name, "-import", str(binary)]
        if script_dir:
            args.extend(["-scriptPath", str(script_dir), "-postScript", "ScanSinks.py"])
        args.append("-deleteProject")
        return self.execute(args)
