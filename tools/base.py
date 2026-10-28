"""Safe, typed subprocess execution for external audit tools."""

from abc import ABC, abstractmethod
import os
from pathlib import Path
import subprocess
from typing import Mapping, Optional, Sequence

from pydantic import BaseModel, ConfigDict


class ToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    command: list[str]
    return_code: Optional[int]
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.return_code == 0 and not self.timed_out and self.error is None


class BaseAuditTool(ABC):
    """Base class that never invokes a shell and always captures output."""

    def __init__(self, timeout: int = 300) -> None:
        self.timeout = timeout

    @property
    @abstractmethod
    def executable(self) -> str:
        """Return the executable name."""

    def execute(
        self,
        args: Sequence[str],
        *,
        cwd: Optional[Path] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> ToolResult:
        command = [self.executable, *map(str, args)]
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        try:
            completed = subprocess.run(
                command,
                cwd=str(cwd) if cwd else None,
                env=merged_env,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=self.timeout,
                check=False,
            )
            return ToolResult(
                command=command,
                return_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
            )
        except subprocess.TimeoutExpired as exc:
            return ToolResult(
                command=command,
                return_code=None,
                stdout=exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout or "",
                stderr=exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr or "",
                timed_out=True,
                error=f"command timed out after {self.timeout}s",
            )
        except OSError as exc:
            return ToolResult(
                command=command, return_code=None, error=f"unable to execute tool: {exc}"
            )
