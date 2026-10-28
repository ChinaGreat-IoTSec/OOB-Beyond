"""Fallback filesystem unpacker wrappers."""

from pathlib import Path

from .base import BaseAuditTool, ToolResult


class SasquatchTool(BaseAuditTool):
    @property
    def executable(self) -> str:
        return "sasquatch"

    def extract(self, image: Path, output_dir: Path) -> ToolResult:
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        return self.execute(["-d", str(output_dir), str(image)])


class UnsquashfsTool(BaseAuditTool):
    @property
    def executable(self) -> str:
        return "unsquashfs"

    def extract(self, image: Path, output_dir: Path) -> ToolResult:
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        return self.execute(["-d", str(output_dir), str(image)])


class JeffersonTool(BaseAuditTool):
    @property
    def executable(self) -> str:
        return "jefferson"

    def extract(self, image: Path, output_dir: Path) -> ToolResult:
        output_dir.mkdir(parents=True, exist_ok=True)
        return self.execute(["-d", str(output_dir), str(image)])
