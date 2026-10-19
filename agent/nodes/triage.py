"""Discover likely network-facing binaries and scripts."""

from pathlib import Path
import stat

from agent.states import BinaryTarget, FirmwareAuditState
from agent.agents.recovery import recover


SERVICE_NAMES = {"httpd", "boa", "uhttpd", "mini_httpd"}


def triage_node(state: FirmwareAuditState) -> dict:
    root = Path(state.extract_dir or "")
    if not root.is_dir():
        return recover(state, "TriageAgent", "extraction directory is unavailable")
    targets: list[BinaryTarget] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        reasons: list[str] = []
        name = path.name.lower()
        if name in SERVICE_NAMES:
            reasons.append("known web daemon")
        if name.endswith(".cgi"):
            reasons.append("CGI endpoint")
        if "/etc/init.d/" in path.as_posix() or "/etc/rc.d/" in path.as_posix():
            reasons.append("startup service")
        try:
            executable = bool(path.stat().st_mode & stat.S_IXUSR)
            if executable:
                reasons.append("executable")
            if executable and path.stat().st_size <= 20 * 1024 * 1024:
                sample = path.read_bytes()
                if any(token in sample for token in (b"bind", b"listen", b"socket")):
                    reasons.append("network API reference")
        except OSError:
            continue
        if not reasons:
            continue
        score = min(
            10,
            4
            + (3 if name in SERVICE_NAMES else 0)
            + (2 if name.endswith(".cgi") else 0)
            + (1 if "network API reference" in reasons else 0),
        )
        targets.append(BinaryTarget(file_path=str(path), priority_score=score, priority_reasons=reasons))
    targets.sort(key=lambda target: (-target.priority_score, target.file_path))
    return {
        "binary_targets": targets,
        "selected_target": targets[0] if targets else None,
        "status": "TRIAGED",
        "logs": [f"triage discovered {len(targets)} candidate targets"],
    }
