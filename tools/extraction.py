"""Shared firmware extraction and bounded SquashFS fallback discovery."""

import os
from pathlib import Path
import shutil

from .binwalk import BinwalkTool
from .unpackers import SasquatchTool, UnsquashfsTool


def rootfs_candidates(directory):
    candidates = []
    for current, directories, _ in os.walk(directory, followlinks=False):
        path = Path(current)
        if (path / ".oob-not-runtime-rootfs").exists():
            directories[:] = []
            continue
        names = set(directories)
        directories[:] = [name for name in directories if not (path / name).is_symlink()]
        if ("bin" in names or "sbin" in names) and ("etc" in names or "lib" in names):
            candidates.append(path)
    return candidates


def squashfs_offsets(firmware):
    found = set()
    with firmware.open("rb") as stream:
        position = 0
        overlap = b""
        while block := stream.read(1024 * 1024):
            content = overlap + block
            for signature in (b"hsqs", b"sqsh", b"shsq", b"qshs"):
                start = 0
                while (index := content.find(signature, start)) >= 0:
                    found.add(position - len(overlap) + index)
                    if len(found) > 16:
                        raise ValueError("Too many SquashFS signatures; provide an extracted rootfs explicitly")
                    start = index + 1
            position += len(block)
            overlap = block[-3:]
    return sorted(found)


def extract_firmware(firmware, destination):
    destination.mkdir(parents=True, exist_ok=True)
    results = [BinwalkTool().extract(firmware, destination / "binwalk")]
    if "changing link target" in results[0].stderr:
        (destination / "binwalk/.oob-not-runtime-rootfs").write_text("Binwalk rewrote guest symlinks; use filesystem-specific extraction for runtime preparation.\n")
    if not rootfs_candidates(destination):
        offsets = sorted(set([0] + squashfs_offsets(firmware)))
        for offset in offsets:
            image = firmware
            carved = destination / f"carved-{offset}.img"
            if offset:
                with firmware.open("rb") as source, carved.open("wb") as output:
                    source.seek(offset)
                    shutil.copyfileobj(source, output)
                image = carved
            try:
                for tool in (UnsquashfsTool(), SasquatchTool()):
                    output = destination / f"{tool.executable}-{offset}"
                    results.append(tool.extract(image, output))
                    if rootfs_candidates(output):
                        break
            finally:
                carved.unlink(missing_ok=True)
    return results
