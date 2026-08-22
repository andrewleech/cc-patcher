"""Bun standalone-payload framing.

Layout inside the payload section (`.bun` on ELF, `__BUN,__bun` on
Mach-O):

  [u64 payload_len][payload bytes][Offsets struct (32B)][TRAILER (16B)]

Where the payload bytes contain (in order):
  - JSC bytecode cache (module[0].bytecode region)
  - Module data regions (name strings, contents, etc), each referenced
    by a payload-relative StringPointer in the modules table
  - The modules table (`Offsets.modules_ptr`): an array of 52-byte
    CompiledModuleGraphFile records

The Offsets struct + trailer sit at the very end; the modules table
sits between the JS payload data and the Offsets struct.

Layout references:
  - https://github.com/oven-sh/bun standalone_graph/StandaloneModuleGraph.rs
  - inv-string-pointers.md
"""

import dataclasses
import struct
import typing

from .binfmt import BunSection

TRAILER = b"\n---- Bun! ----\n"
OFFSETS_STRUCT = struct.Struct("<QIIIIII")
STRING_POINTER_STRUCT = struct.Struct("<II")
MODULE_RECORD_SIZE = 52
MODULE_FIELD_NAMES = (
    "name", "contents", "sourcemap",
    "bytecode", "module_info", "bytecode_origin_path",
)

ENCODING_BINARY = 0
ENCODING_LATIN1 = 1
ENCODING_UTF8 = 2


class BunFormatError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class StringPtr:
    offset: int
    length: int


@dataclasses.dataclass(frozen=True)
class ModuleRecord:
    index: int
    base: int
    name: StringPtr
    contents: StringPtr
    sourcemap: StringPtr
    bytecode: StringPtr
    module_info: StringPtr
    bytecode_origin_path: StringPtr
    encoding: int
    loader: int
    module_format: int
    side: int

    def fields(self) -> tuple[tuple[str, StringPtr], ...]:
        return (
            ("name", self.name),
            ("contents", self.contents),
            ("sourcemap", self.sourcemap),
            ("bytecode", self.bytecode),
            ("module_info", self.module_info),
            ("bytecode_origin_path", self.bytecode_origin_path),
        )

    def file_offset_of_field(self, field_name: str) -> int:
        return self.base + MODULE_FIELD_NAMES.index(field_name) * 8


class BunContainer(typing.Protocol):
    """The container-format surface `locate()` needs: where the Bun
    payload section is. Implemented by `elf.ElfLayout` and
    `macho.MachOLayout`."""

    def bun_section(self) -> BunSection: ...


@dataclasses.dataclass(frozen=True)
class BunFraming:
    bun_section_idx: int
    bun_offset: int
    bun_size: int
    payload_start: int
    payload_len: int
    trailer_offset: int
    offsets_struct_offset: int
    byte_count: int
    modules_ptr: StringPtr
    compile_exec_argv_ptr: StringPtr
    entry_point_id: int
    flags: int
    modules: tuple[ModuleRecord, ...]


def locate(buf: bytes, container: BunContainer) -> BunFraming:
    bun = container.bun_section()
    payload_len = struct.unpack_from("<Q", buf, bun.offset)[0]
    if payload_len != bun.size - 8:
        raise BunFormatError(
            f"payload_len {payload_len} != section size - 8 ({bun.size - 8})"
        )

    payload_start = bun.offset + 8
    payload_end = payload_start + payload_len
    trailer_offset = payload_end - len(TRAILER)
    if buf[trailer_offset:payload_end] != TRAILER:
        raise BunFormatError("Bun trailer magic not found at expected location")

    offsets_struct_offset = trailer_offset - OFFSETS_STRUCT.size
    (
        byte_count, mods_off, mods_len, entry_id,
        argv_off, argv_len, flags,
    ) = OFFSETS_STRUCT.unpack_from(buf, offsets_struct_offset)

    if byte_count != offsets_struct_offset - payload_start:
        raise BunFormatError(
            f"Offsets.byte_count {byte_count} disagrees with computed "
            f"{offsets_struct_offset - payload_start}"
        )
    if mods_len % MODULE_RECORD_SIZE:
        raise BunFormatError(
            f"modules table length {mods_len} not a multiple of "
            f"{MODULE_RECORD_SIZE}"
        )

    modules = []
    for i in range(mods_len // MODULE_RECORD_SIZE):
        base = payload_start + mods_off + i * MODULE_RECORD_SIZE
        sps = tuple(
            StringPtr(*STRING_POINTER_STRUCT.unpack_from(buf, base + f * 8))
            for f in range(6)
        )
        modules.append(ModuleRecord(
            index=i, base=base,
            name=sps[0], contents=sps[1], sourcemap=sps[2],
            bytecode=sps[3], module_info=sps[4], bytecode_origin_path=sps[5],
            encoding=buf[base + 48], loader=buf[base + 49],
            module_format=buf[base + 50], side=buf[base + 51],
        ))

    return BunFraming(
        bun_section_idx=bun.index,
        bun_offset=bun.offset,
        bun_size=bun.size,
        payload_start=payload_start,
        payload_len=payload_len,
        trailer_offset=trailer_offset,
        offsets_struct_offset=offsets_struct_offset,
        byte_count=byte_count,
        modules_ptr=StringPtr(mods_off, mods_len),
        compile_exec_argv_ptr=StringPtr(argv_off, argv_len),
        entry_point_id=entry_id,
        flags=flags,
        modules=tuple(modules),
    )
