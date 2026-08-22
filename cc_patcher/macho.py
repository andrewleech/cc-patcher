"""64-bit Mach-O read surface, little-endian only.

Provides immutable `MachOLayout` (parsed header + segment/section
tables + an index of every load-command field that holds a file
offset) and the byte offsets within each header type used by the
applier to rewrite size/offset fields in place.

Unlike ELF, Mach-O declares each segment's file *and* VM extent
independently, and dyld requires both to stay page-aligned and
mutually congruent. Growing the `__BUN` segment therefore means
shifting `fileoff` and `vmaddr` of every later segment by the same
page-rounded amount — see `EditApplier._rewrite_macho_headers`.

The load-command table lives at the very start of the file, well
before the Bun payload, so every `file_offset_of_*` recorded here
stays valid after the payload is spliced.

Layout reference: <mach-o/loader.h>
"""

import dataclasses
import struct

from .binfmt import BunSection

MACH_HEADER_64_STRUCT = struct.Struct("<IiiIIIII")
MACH_HEADER_64_SIZE = MACH_HEADER_64_STRUCT.size
SEGMENT_COMMAND_64_SIZE = 72
SECTION_64_SIZE = 80

SEG_VMADDR_OFFSET = 24
SEG_VMSIZE_OFFSET = 32
SEG_FILEOFF_OFFSET = 40
SEG_FILESIZE_OFFSET = 48
SEG_NSECTS_OFFSET = 64

SECT_ADDR_OFFSET = 32
SECT_SIZE_OFFSET = 40
SECT_OFFSET_OFFSET = 48

CPU_TYPE_ARM64 = 0x0100000C

BUN_SEGNAME = b"__BUN"
BUN_SECTNAME = b"__bun"

LC_REQ_DYLD = 0x80000000

LC_SEGMENT_64 = 0x19

_U32 = 4
_U64 = 8

# cmd -> ((field name, offset within the load command, width), ...) for
# every field holding an absolute file offset. Fields holding a *size*
# are excluded: sizes don't move when the payload grows.
_FILE_OFFSET_FIELDS: dict[int, tuple[tuple[str, int, int], ...]] = {
    0x02: (("symoff", 8, _U32), ("stroff", 16, _U32)),          # LC_SYMTAB
    0x03: (("offset", 8, _U32),),                               # LC_SYMSEG
    0x0B: (                                                     # LC_DYSYMTAB
        ("tocoff", 32, _U32), ("modtaboff", 40, _U32),
        ("extrefsymoff", 48, _U32), ("indirectsymoff", 56, _U32),
        ("extreloff", 64, _U32), ("locreloff", 72, _U32),
    ),
    0x16: (("offset", 8, _U32),),                               # LC_TWOLEVEL_HINTS
    0x1D: (("dataoff", 8, _U32),),                              # LC_CODE_SIGNATURE
    0x1E: (("dataoff", 8, _U32),),                              # LC_SEGMENT_SPLIT_INFO
    0x21: (("cryptoff", 8, _U32),),                             # LC_ENCRYPTION_INFO
    0x22: (                                                     # LC_DYLD_INFO
        ("rebase_off", 8, _U32), ("bind_off", 16, _U32),
        ("weak_bind_off", 24, _U32), ("lazy_bind_off", 32, _U32),
        ("export_off", 40, _U32),
    ),
    0x26: (("dataoff", 8, _U32),),                              # LC_FUNCTION_STARTS
    0x29: (("dataoff", 8, _U32),),                              # LC_DATA_IN_CODE
    0x2B: (("dataoff", 8, _U32),),                              # LC_DYLIB_CODE_SIGN_DRS
    0x2C: (("cryptoff", 8, _U32),),                             # LC_ENCRYPTION_INFO_64
    0x2E: (("dataoff", 8, _U32),),                              # LC_LINKER_OPTIMIZATION_HINT
    0x31: (("offset", 24, _U64),),                              # LC_NOTE
    0x36: (("dataoff", 8, _U32),),                              # LC_ATOM_INFO
    0x22 | LC_REQ_DYLD: (                                       # LC_DYLD_INFO_ONLY
        ("rebase_off", 8, _U32), ("bind_off", 16, _U32),
        ("weak_bind_off", 24, _U32), ("lazy_bind_off", 32, _U32),
        ("export_off", 40, _U32),
    ),
    0x33 | LC_REQ_DYLD: (("dataoff", 8, _U32),),                # LC_DYLD_EXPORTS_TRIE
    0x34 | LC_REQ_DYLD: (("dataoff", 8, _U32),),                # LC_DYLD_CHAINED_FIXUPS
    0x35 | LC_REQ_DYLD: (("fileoff", 8, _U64),),                # LC_FILESET_ENTRY
}

# Load commands carrying no absolute file offset. LC_MAIN is here on
# purpose: its `entryoff` is relative to the __TEXT segment, which
# always precedes __BUN, so it never needs shifting.
_NO_FILE_OFFSET_CMDS = frozenset({
    0x01,                   # LC_SEGMENT (32-bit; rejected earlier anyway)
    0x04, 0x05,             # LC_THREAD, LC_UNIXTHREAD
    0x06, 0x07,             # LC_LOADFVMLIB, LC_IDFVMLIB
    0x08, 0x09, 0x0A,       # LC_IDENT, LC_FVMFILE, LC_PREPAGE
    0x0C, 0x0D,             # LC_LOAD_DYLIB, LC_ID_DYLIB
    0x0E, 0x0F,             # LC_LOAD_DYLINKER, LC_ID_DYLINKER
    0x10,                   # LC_PREBOUND_DYLIB
    0x11, 0x1A,             # LC_ROUTINES, LC_ROUTINES_64
    0x12, 0x13, 0x14, 0x15,  # LC_SUB_{FRAMEWORK,UMBRELLA,CLIENT,LIBRARY}
    0x17,                   # LC_PREBIND_CKSUM
    0x19,                   # LC_SEGMENT_64 (handled structurally)
    0x1B,                   # LC_UUID
    0x20,                   # LC_LAZY_LOAD_DYLIB
    0x24, 0x25, 0x2F, 0x30,  # LC_VERSION_MIN_*
    0x27,                   # LC_DYLD_ENVIRONMENT
    0x2A,                   # LC_SOURCE_VERSION
    0x2D,                   # LC_LINKER_OPTION
    0x32,                   # LC_BUILD_VERSION
    0x18 | LC_REQ_DYLD,     # LC_LOAD_WEAK_DYLIB
    0x1C | LC_REQ_DYLD,     # LC_RPATH
    0x1F | LC_REQ_DYLD,     # LC_REEXPORT_DYLIB
    0x23 | LC_REQ_DYLD,     # LC_LOAD_UPWARD_DYLIB
    0x28 | LC_REQ_DYLD,     # LC_MAIN
})


class MachOFormatError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class Section:
    index: int
    segname: bytes
    sectname: bytes
    addr: int
    size: int
    offset: int
    file_offset_of_sect: int


@dataclasses.dataclass(frozen=True)
class Segment:
    index: int
    segname: bytes
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    file_offset_of_lc: int
    sections: tuple[Section, ...]

    @property
    def file_end(self) -> int:
        return self.fileoff + self.filesize


@dataclasses.dataclass(frozen=True)
class FileOffsetField:
    """A load-command field holding an absolute file offset, located so
    the applier can shift it without re-parsing."""

    cmd: int
    name: str
    file_offset: int
    width: int
    value: int


@dataclasses.dataclass(frozen=True)
class MachOLayout:
    cputype: int
    page_size: int
    segments: tuple[Segment, ...]
    file_offset_fields: tuple[FileOffsetField, ...]

    def segment_by_name(self, name: bytes) -> Segment:
        for seg in self.segments:
            if seg.segname == name:
                return seg
        raise MachOFormatError(f"segment {name!r} not found")

    def _bun_sect(self) -> Section:
        for sect in self.segment_by_name(BUN_SEGNAME).sections:
            if sect.sectname == BUN_SECTNAME:
                return sect
        raise MachOFormatError(
            f"section {BUN_SEGNAME.decode()},{BUN_SECTNAME.decode()} not found"
        )

    def bun_section(self) -> BunSection:
        sect = self._bun_sect()
        return BunSection(
            index=sect.index, offset=sect.offset, size=sect.size,
        )

    def bun_section_header_offset(self) -> int:
        """File offset of the `section_64` struct describing `__bun`."""
        return self._bun_sect().file_offset_of_sect


def parse(buf: bytes) -> MachOLayout:
    magic, cputype, _subtype, filetype, ncmds, sizeofcmds, _flags, _rsv = (
        MACH_HEADER_64_STRUCT.unpack_from(buf, 0)
    )
    if magic != 0xFEEDFACF:
        raise MachOFormatError(
            f"not a 64-bit little-endian Mach-O (magic 0x{magic:08x})"
        )
    if filetype != 2:  # MH_EXECUTE
        raise MachOFormatError(f"not an executable (filetype {filetype})")

    page_size = 16384 if cputype == CPU_TYPE_ARM64 else 4096

    segments: list[Segment] = []
    offset_fields: list[FileOffsetField] = []
    sect_index = 0
    off = MACH_HEADER_64_SIZE
    end_of_cmds = MACH_HEADER_64_SIZE + sizeofcmds

    for i in range(ncmds):
        if off + 8 > end_of_cmds:
            raise MachOFormatError("load command table overruns sizeofcmds")
        cmd, cmdsize = struct.unpack_from("<II", buf, off)
        if cmdsize < 8 or off + cmdsize > end_of_cmds:
            raise MachOFormatError(
                f"load command {i} (cmd 0x{cmd:x}) has bad cmdsize {cmdsize}"
            )

        if cmd == LC_SEGMENT_64:
            if cmdsize < SEGMENT_COMMAND_64_SIZE:
                raise MachOFormatError(
                    f"LC_SEGMENT_64 {i} cmdsize {cmdsize} too small"
                )
            segname = bytes(buf[off + 8:off + 24]).rstrip(b"\0")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                "<QQQQ", buf, off + SEG_VMADDR_OFFSET,
            )
            nsects = struct.unpack_from(
                "<I", buf, off + SEG_NSECTS_OFFSET,
            )[0]
            if SEGMENT_COMMAND_64_SIZE + nsects * SECTION_64_SIZE > cmdsize:
                raise MachOFormatError(
                    f"segment {segname!r} declares {nsects} sections but "
                    f"cmdsize is only {cmdsize}"
                )
            sections = []
            for s in range(nsects):
                so = off + SEGMENT_COMMAND_64_SIZE + s * SECTION_64_SIZE
                sect_addr, sect_size = struct.unpack_from(
                    "<QQ", buf, so + SECT_ADDR_OFFSET,
                )
                sect_off = struct.unpack_from(
                    "<I", buf, so + SECT_OFFSET_OFFSET,
                )[0]
                sections.append(Section(
                    index=sect_index,
                    segname=bytes(buf[so + 16:so + 32]).rstrip(b"\0"),
                    sectname=bytes(buf[so:so + 16]).rstrip(b"\0"),
                    addr=sect_addr, size=sect_size, offset=sect_off,
                    file_offset_of_sect=so,
                ))
                sect_index += 1
            segments.append(Segment(
                index=len(segments), segname=segname,
                vmaddr=vmaddr, vmsize=vmsize,
                fileoff=fileoff, filesize=filesize,
                file_offset_of_lc=off, sections=tuple(sections),
            ))
        elif cmd in _FILE_OFFSET_FIELDS:
            for name, rel, width in _FILE_OFFSET_FIELDS[cmd]:
                if rel + width > cmdsize:
                    raise MachOFormatError(
                        f"load command 0x{cmd:x} too short for field {name}"
                    )
                fmt = "<I" if width == _U32 else "<Q"
                offset_fields.append(FileOffsetField(
                    cmd=cmd, name=name, file_offset=off + rel, width=width,
                    value=struct.unpack_from(fmt, buf, off + rel)[0],
                ))
        elif cmd not in _NO_FILE_OFFSET_CMDS:
            # Refuse rather than risk leaving an unknown file-offset
            # field stale: a stale offset silently corrupts the binary,
            # whereas failing here just falls back to the unpatched one.
            raise MachOFormatError(
                f"unrecognised load command 0x{cmd:x} at file offset {off}; "
                "cc-patcher cannot prove it holds no file offsets"
            )

        off += cmdsize

    if not segments:
        raise MachOFormatError("no LC_SEGMENT_64 load commands found")

    return MachOLayout(
        cputype=cputype, page_size=page_size,
        segments=tuple(segments),
        file_offset_fields=tuple(offset_fields),
    )
