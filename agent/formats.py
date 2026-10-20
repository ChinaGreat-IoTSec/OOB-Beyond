"""Bounded header inspection for directly analyzable native binaries."""

from pathlib import Path


def identify_binary(path: Path) -> tuple[str, str | None] | None:
    with path.open("rb") as stream:
        header = stream.read(64)
        size = path.stat().st_size
        if header[:4] == b"\x7fELF":
            if len(header) < 52 or header[4] not in (1, 2) or header[5] not in (1, 2):
                return None
            if header[4] == 2 and len(header) < 64:
                return None
            endian = "little" if header[5] == 1 else "big"
            machine = int.from_bytes(header[18:20], endian)
            kind = int.from_bytes(header[16:18], endian)
            if kind not in (1, 2, 3):
                return None
            arch = {3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64",
                    40: "ARM", 62: "x86_64", 183: "AArch64", 243: "RISC-V"}.get(machine)
            return "ELF", arch
        if header[:2] == b"MZ" and len(header) == 64:
            offset = int.from_bytes(header[60:64], "little")
            if offset < 64 or offset + 26 > size:
                return None
            stream.seek(offset)
            pe_header = stream.read(26)
            if pe_header[:4] != b"PE\x00\x00":
                return None
            optional_size = int.from_bytes(pe_header[20:22], "little")
            magic = int.from_bytes(pe_header[24:26], "little")
            minimum = {0x10b: 96, 0x20b: 112}.get(magic)
            if minimum is None or optional_size < minimum or offset + 24 + optional_size > size:
                return None
            machine = int.from_bytes(pe_header[4:6], "little")
            arch = {0x14c: "x86", 0x8664: "x86_64", 0x1c0: "ARM",
                    0x1c4: "ARM", 0xaa64: "AArch64"}.get(machine)
            return "PE", arch
        magics = {b"\xce\xfa\xed\xfe": ("little", 28),
                  b"\xcf\xfa\xed\xfe": ("little", 32),
                  b"\xfe\xed\xfa\xce": ("big", 28),
                  b"\xfe\xed\xfa\xcf": ("big", 32)}
        if header[:4] in magics:
            endian, minimum = magics[header[:4]]
            if len(header) < minimum:
                return None
            kind = int.from_bytes(header[12:16], endian)
            if kind not in (1, 2, 6, 8, 11):
                return None
            machine = int.from_bytes(header[4:8], endian)
            arch = {7: "x86", 0x1000007: "x86_64", 12: "ARM",
                    0x100000c: "AArch64", 18: "PowerPC"}.get(machine)
            return "Mach-O", arch
    return None
