"""Container-format abstraction shared by the ELF and Mach-O readers.

The Bun payload reader (`bun.py`) needs to know only where the payload
section starts and how long it is. Both container readers expose that
as a `BunSection` via `bun_section()`, so `bun.locate()` is written
once against this abstraction rather than against either format.

This module deliberately imports neither reader — `context.parse()`
owns the dispatch — so the container readers can depend on it without
a cycle.
"""

import dataclasses

ELF_MAGIC = b"\x7fELF"
MACHO_MAGIC_64 = b"\xcf\xfa\xed\xfe"
MACHO_CIGAM_64 = b"\xfe\xed\xfa\xcf"
FAT_MAGIC = b"\xca\xfe\xba\xbe"
FAT_CIGAM = b"\xbe\xba\xfe\xca"

FORMAT_ELF = "elf"
FORMAT_MACHO = "macho"


class UnsupportedContainerError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class BunSection:
    """The section holding the Bun standalone payload, named `.bun` on
    ELF and `__BUN,__bun` on Mach-O. `size` covers the u64 length
    prefix plus the payload, and excludes any segment-level alignment
    padding that follows."""

    index: int
    offset: int
    size: int


def sniff(buf: bytes) -> str:
    """Return the container format of `buf`, or raise
    `UnsupportedContainerError` naming what was found instead."""
    magic = bytes(buf[:4])
    if magic == ELF_MAGIC:
        return FORMAT_ELF
    if magic == MACHO_MAGIC_64:
        return FORMAT_MACHO
    if magic == MACHO_CIGAM_64:
        raise UnsupportedContainerError(
            "big-endian Mach-O is not supported"
        )
    if magic in (FAT_MAGIC, FAT_CIGAM):
        raise UnsupportedContainerError(
            "universal (fat) Mach-O binaries are not supported; extract "
            "the native slice first with "
            "`lipo -thin <arch> <binary> -output <slice>`"
        )
    raise UnsupportedContainerError(
        f"unrecognised container magic {magic!r}; expected ELF or "
        "64-bit Mach-O"
    )
