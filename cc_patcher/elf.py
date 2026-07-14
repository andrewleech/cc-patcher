"""ELF64 read+write surface, little-endian only.

Provides immutable `ElfLayout` (parsed header + section table + program
table) and the byte offsets within each header type used by the
applier to rewrite size/offset fields in place.

The kernel only consults program headers at load time; section headers
are linker/debugger metadata. The applier still updates section
headers because the Bun standalone loader walks them to find `.bun`.
"""

import dataclasses
import struct

ELF64_EHDR_STRUCT = struct.Struct("<16sHHIQQQIHHHHHH")
ELF64_PHDR_STRUCT = struct.Struct("<IIQQQQQQ")
ELF64_SHDR_STRUCT = struct.Struct("<IIQQQQIIQQ")

EHDR_SHOFF_OFFSET = 40

PHDR_OFFSET_OFFSET = 8
PHDR_FILESZ_OFFSET = 32
PHDR_MEMSZ_OFFSET = 40

SHDR_OFFSET_OFFSET = 24
SHDR_SIZE_OFFSET = 32

ELF_MAGIC = b"\x7fELF"


class ElfFormatError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class SectionHeader:
    index: int
    name: bytes
    sh_type: int
    sh_offset: int
    sh_size: int
    file_offset_of_shdr: int


@dataclasses.dataclass(frozen=True)
class ProgramHeader:
    index: int
    p_type: int
    p_offset: int
    p_filesz: int
    p_memsz: int
    file_offset_of_phdr: int


@dataclasses.dataclass(frozen=True)
class ElfLayout:
    e_phoff: int
    e_shoff: int
    e_phnum: int
    e_phentsize: int
    e_shnum: int
    e_shentsize: int
    e_shstrndx: int
    sections: tuple[SectionHeader, ...]
    segments: tuple[ProgramHeader, ...]

    def section_by_name(self, name: bytes) -> SectionHeader:
        for s in self.sections:
            if s.name == name:
                return s
        raise ElfFormatError(f"section {name!r} not found")


def parse(buf: bytes) -> ElfLayout:
    if buf[:4] != ELF_MAGIC:
        raise ElfFormatError("not an ELF file")
    if buf[4] != 2:
        raise ElfFormatError("only ELF64 supported")
    if buf[5] != 1:
        raise ElfFormatError("only little-endian supported")

    (
        _ident, _type, _machine, _ver, _entry,
        e_phoff, e_shoff, _flags, _ehsize,
        e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
    ) = ELF64_EHDR_STRUCT.unpack_from(buf, 0)

    shstr_shdr = ELF64_SHDR_STRUCT.unpack_from(
        buf, e_shoff + e_shstrndx * e_shentsize,
    )
    shstr_offset = shstr_shdr[4]

    sections = []
    for i in range(e_shnum):
        shdr_off = e_shoff + i * e_shentsize
        fields = ELF64_SHDR_STRUCT.unpack_from(buf, shdr_off)
        sh_name_off = fields[0]
        name_end = buf.index(b"\0", shstr_offset + sh_name_off)
        name = bytes(buf[shstr_offset + sh_name_off:name_end])
        sections.append(SectionHeader(
            index=i, name=name,
            sh_type=fields[1],
            sh_offset=fields[4], sh_size=fields[5],
            file_offset_of_shdr=shdr_off,
        ))

    segments = []
    for i in range(e_phnum):
        ph_off = e_phoff + i * e_phentsize
        fields = ELF64_PHDR_STRUCT.unpack_from(buf, ph_off)
        segments.append(ProgramHeader(
            index=i, p_type=fields[0],
            p_offset=fields[2],
            p_filesz=fields[5], p_memsz=fields[6],
            file_offset_of_phdr=ph_off,
        ))

    return ElfLayout(
        e_phoff=e_phoff, e_shoff=e_shoff,
        e_phnum=e_phnum, e_phentsize=e_phentsize,
        e_shnum=e_shnum, e_shentsize=e_shentsize,
        e_shstrndx=e_shstrndx,
        sections=tuple(sections),
        segments=tuple(segments),
    )
