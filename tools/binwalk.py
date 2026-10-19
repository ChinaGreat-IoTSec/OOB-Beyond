"""Binwalk wrapper."""

from pathlib import Path

from .base import BaseAuditTool, ToolResult


class BinwalkTool(BaseAuditTool):
    @property
    def executable(self) -> str:
        return "binwalk"

    def extract(self, firmware: Path, output_dir: Path) -> ToolResult:
        output_dir.mkdir(parents=True, exist_ok=True)
        return self.execute(["-e", "-M", "-C", str(output_dir), str(firmware)])
