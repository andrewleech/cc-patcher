"""DiscoveryContext + EditApplier.

`DiscoveryContext` is the view of the input binary passed to every
patch. It exposes search helpers, the StringPointer index, and a JS
brace walker.

`EditApplier` owns the same `bytearray` the context views. Given an
EditPlan it:
  1. Applies same-length edits in any order (offsets don't shift).
  2. Applies growable edits in descending file-offset order so
     earlier offsets stay valid throughout.
  3. Rewrites all affected StringPointer offsets/lengths against the
     pre-splice snapshot held in `ctx.bun`, so multiple inserts into
     the same region don't double-count.
  4. Rewrites the Offsets struct, the payload_len prefix, and the
     container headers describing the payload section — see
     `_rewrite_elf_headers` / `_rewrite_macho_headers`.

The whole 244 MB buffer is held exactly once. Patches read from it
via `find_*` helpers during discover; the applier writes to it during
apply. Patches don't access `ctx.buf` during apply.
"""

import dataclasses
import re
import struct

from . import binfmt as _binfmt
from . import bun as _bun
from . import elf as _elf
from . import macho as _macho
from .edits import Edit, EditPlan, StringPointerRef

ContainerLayout = _elf.ElfLayout | _macho.MachOLayout


@dataclasses.dataclass(frozen=True)
class DiscoveryContext:
    buf: bytearray
    layout: ContainerLayout
    bun: _bun.BunFraming
    version: str
    _sp_index: dict[StringPointerRef, _bun.StringPtr]

    def find_in_payload(self, pat: bytes) -> list[int]:
        results: list[int] = []
        start, end = self.bun.payload_start, self.bun.offsets_struct_offset
        i = self.buf.find(pat, start, end)
        while i != -1:
            results.append(i)
            i = self.buf.find(pat, i + 1, end)
        return results

    def find_regex_in_payload(self, rx: bytes) -> list[re.Match[bytes]]:
        regex = re.compile(rx)
        start, end = self.bun.payload_start, self.bun.offsets_struct_offset
        return list(regex.finditer(self.buf, start, end))

    def containing_string_pointer(
        self, abs_offset: int,
    ) -> StringPointerRef | None:
        rel = abs_offset - self.bun.payload_start
        for ref, sp in self._sp_index.items():
            if ref.kind != "module":
                continue
            if sp.length > 0 and sp.offset <= rel < sp.offset + sp.length:
                return ref
        argv_ref = StringPointerRef("offsets", 0, "compile_exec_argv")
        argv = self._sp_index.get(argv_ref)
        if argv and argv.length > 0 and argv.offset <= rel < argv.offset + argv.length:
            return argv_ref
        return None

    def edit_within_region(self, edit: Edit) -> bool:
        ref = edit.grows_region
        if ref is None:
            return False
        sp = self._sp_index.get(ref)
        if sp is None or sp.length == 0:
            return False
        rel_start = edit.offset - self.bun.payload_start
        rel_end = rel_start + len(edit.old)
        return sp.offset <= rel_start and rel_end <= sp.offset + sp.length

    def is_latin1_region(self, ref: StringPointerRef) -> bool:
        if ref.kind != "module" or ref.index >= len(self.bun.modules):
            return False
        return self.bun.modules[ref.index].encoding == _bun.ENCODING_LATIN1

    def is_framing_offset(self, abs_offset: int) -> bool:
        """True if `abs_offset` lands inside the modules table, Offsets
        struct, or trailer — regions no patch should edit."""
        return abs_offset >= self.bun.payload_start + self.bun.modules_ptr.offset

    def find_balanced_close(self, start: int, limit: int) -> int | None:
        """Walk from `start` (immediately after an opening `{`) and return
        the position of the matching `}`, or None if unbalanced within
        `limit`. Handles quoted strings (`"`, `'`, `` ` ``) and backslash
        escapes; does NOT handle `${...}` interpolations inside template
        literals — callers must verify their target has no backticks."""
        depth = 1
        i = start
        in_str: int | None = None
        escape = False
        while i < limit:
            c = self.buf[i]
            if escape:
                escape = False
                i += 1
                continue
            if in_str is not None:
                if c == 0x5C:
                    escape = True
                elif c == in_str:
                    in_str = None
                i += 1
                continue
            if c == 0x22 or c == 0x27 or c == 0x60:
                in_str = c
            elif c == 0x7B:
                depth += 1
            elif c == 0x7D:
                depth -= 1
                if depth == 0:
                    return i
            i += 1
        return None


def _build_sp_index(
    bun: _bun.BunFraming,
) -> dict[StringPointerRef, _bun.StringPtr]:
    idx: dict[StringPointerRef, _bun.StringPtr] = {}
    for mod in bun.modules:
        for fname, sp in mod.fields():
            idx[StringPointerRef("module", mod.index, fname)] = sp
    idx[StringPointerRef("offsets", 0, "modules")] = bun.modules_ptr
    idx[StringPointerRef("offsets", 0, "compile_exec_argv")] = (
        bun.compile_exec_argv_ptr
    )
    return idx


def parse(buf: bytearray, version: str = "unknown") -> DiscoveryContext:
    fmt = _binfmt.sniff(buf)
    layout: ContainerLayout = (
        _elf.parse(buf) if fmt == _binfmt.FORMAT_ELF else _macho.parse(buf)
    )
    bun_framing = _bun.locate(buf, layout)
    return DiscoveryContext(
        buf=buf,
        layout=layout,
        bun=bun_framing,
        version=version,
        _sp_index=_build_sp_index(bun_framing),
    )


class EditApplier:
    def __init__(self, ctx: DiscoveryContext):
        self.ctx = ctx
        self.buf = ctx.buf

    def apply(self, plan: EditPlan) -> bytearray:
        plan.validate(self.ctx)

        for e in plan.same_length():
            self._verify_and_splice(e.offset, e.old, e.new)

        growable = sorted(plan.growable(), key=lambda e: -e.offset)
        if not growable:
            return self.buf

        for e in growable:
            self._verify_and_splice(e.offset, e.old, e.new)

        total_delta = sum(e.delta for e in growable)
        self._rewrite_string_pointers(growable)
        self._rewrite_bun_framing(growable, total_delta)
        if isinstance(self.ctx.layout, _macho.MachOLayout):
            self._rewrite_macho_headers(total_delta)
        else:
            self._rewrite_elf_headers(total_delta)
        return self.buf

    def _verify_and_splice(self, offset: int, old: bytes, new: bytes) -> None:
        actual = bytes(self.buf[offset:offset + len(old)])
        if actual != old:
            raise RuntimeError(
                f"splice at 0x{offset:x}: expected {old!r}, found {actual!r}"
            )
        self.buf[offset:offset + len(old)] = new

    def _shift_past(self, original_offset: int, growable: list[Edit]) -> int:
        """Sum of deltas for growable edits whose entire `old` byte range
        sits strictly before `original_offset`. Works for both file and
        payload-relative offsets since growable edits live entirely
        within the JS portion of the payload (callers convert payload-
        relative offsets to file offsets before passing in)."""
        shift = 0
        for e in growable:
            if e.offset + len(e.old) <= original_offset:
                shift += e.delta
        return shift

    def _rewrite_string_pointers(self, growable: list[Edit]) -> None:
        payload_start = self.ctx.bun.payload_start
        for mod in self.ctx.bun.modules:
            new_base = mod.base + self._shift_past(mod.base, growable)
            for f_idx, (fname, original) in enumerate(mod.fields()):
                ref = StringPointerRef("module", mod.index, fname)
                if original.length == 0:
                    new_off, new_len = original.offset, original.length
                else:
                    new_off = original.offset + self._shift_past(
                        original.offset + payload_start, growable,
                    )
                    new_len = original.length
                for e in growable:
                    if e.grows_region == ref:
                        new_len += e.delta
                _bun.STRING_POINTER_STRUCT.pack_into(
                    self.buf, new_base + f_idx * 8, new_off, new_len,
                )

    def _rewrite_bun_framing(
        self, growable: list[Edit], total_delta: int,
    ) -> None:
        bun = self.ctx.bun
        payload_start = bun.payload_start

        struct.pack_into(
            "<Q", self.buf, bun.bun_offset, bun.payload_len + total_delta,
        )

        new_offsets_pos = (
            bun.offsets_struct_offset
            + self._shift_past(bun.offsets_struct_offset, growable)
        )

        new_mods_off = bun.modules_ptr.offset + self._shift_past(
            bun.modules_ptr.offset + payload_start, growable,
        )
        new_argv_off = bun.compile_exec_argv_ptr.offset
        if bun.compile_exec_argv_ptr.length > 0:
            new_argv_off += self._shift_past(
                bun.compile_exec_argv_ptr.offset + payload_start, growable,
            )

        _bun.OFFSETS_STRUCT.pack_into(
            self.buf, new_offsets_pos,
            bun.byte_count + total_delta,
            new_mods_off, bun.modules_ptr.length,
            bun.entry_point_id,
            new_argv_off, bun.compile_exec_argv_ptr.length,
            bun.flags,
        )

    def _rewrite_elf_headers(self, total_delta: int) -> None:
        elf = self.ctx.layout
        bun_sh_offset = self.ctx.bun.bun_offset
        bun_sh_size = self.ctx.bun.bun_size

        shdr_table_shift = total_delta if elf.e_shoff > bun_sh_offset else 0

        bun_shdr_file_off = (
            elf.e_shoff
            + self.ctx.bun.bun_section_idx * elf.e_shentsize
            + shdr_table_shift
        )
        struct.pack_into(
            "<Q", self.buf, bun_shdr_file_off + _elf.SHDR_SIZE_OFFSET,
            bun_sh_size + total_delta,
        )

        for sec in elf.sections:
            if sec.sh_offset > bun_sh_offset:
                shdr_post = sec.file_offset_of_shdr + shdr_table_shift
                struct.pack_into(
                    "<Q", self.buf, shdr_post + _elf.SHDR_OFFSET_OFFSET,
                    sec.sh_offset + total_delta,
                )

        for seg in elf.segments:
            ph_base = seg.file_offset_of_phdr
            if seg.p_offset <= bun_sh_offset < seg.p_offset + seg.p_filesz:
                struct.pack_into(
                    "<Q", self.buf, ph_base + _elf.PHDR_FILESZ_OFFSET,
                    seg.p_filesz + total_delta,
                )
                struct.pack_into(
                    "<Q", self.buf, ph_base + _elf.PHDR_MEMSZ_OFFSET,
                    seg.p_memsz + total_delta,
                )
            elif seg.p_offset > bun_sh_offset:
                struct.pack_into(
                    "<Q", self.buf, ph_base + _elf.PHDR_OFFSET_OFFSET,
                    seg.p_offset + total_delta,
                )

        if elf.e_shoff > bun_sh_offset:
            struct.pack_into(
                "<Q", self.buf, _elf.EHDR_SHOFF_OFFSET,
                elf.e_shoff + total_delta,
            )

    def _rewrite_macho_headers(self, total_delta: int) -> None:
        """Absorb the inserted bytes into the zero padding that aligns
        `__LINKEDIT`, growing `__BUN` by whole pages only if the padding
        is too small.

        dyld requires every segment's `fileoff` and `vmaddr` to be
        page-aligned and to keep a constant difference, so `__LINKEDIT`
        can only move by a multiple of the page size. Consuming the
        padding instead keeps it still: for the edit sizes the current
        patches emit (tens of bytes against ~2 KB of padding on
        average) nothing after `__BUN` moves at all.
        """
        mo = self.ctx.layout
        bun = self.ctx.bun
        seg = mo.segment_by_name(_macho.BUN_SEGNAME)

        payload_region_end = bun.bun_offset + bun.bun_size
        pad = seg.file_end - payload_region_end
        if pad < 0:
            raise RuntimeError(
                f"__bun section (ends at {payload_region_end}) overruns the "
                f"__BUN segment (ends at {seg.file_end})"
            )

        grow = (
            0 if total_delta <= pad
            else _round_up(total_delta - pad, mo.page_size)
        )
        new_pad = pad + grow - total_delta

        pad_start = payload_region_end + total_delta
        existing = self.buf[pad_start:pad_start + pad]
        if len(existing) != pad:
            raise RuntimeError(
                f"__BUN segment claims to end at {seg.file_end} but the file "
                f"is only {len(self.buf) - total_delta} bytes"
            )
        if any(existing):
            raise RuntimeError(
                f"expected {pad} zero padding bytes after the Bun payload at "
                f"0x{pad_start:x}, found non-zero data"
            )
        self.buf[pad_start:pad_start + pad] = b"\0" * new_pad

        struct.pack_into(
            "<Q", self.buf,
            mo.bun_section_header_offset() + _macho.SECT_SIZE_OFFSET,
            bun.bun_size + total_delta,
        )

        if grow == 0:
            return

        lc = seg.file_offset_of_lc
        struct.pack_into(
            "<Q", self.buf, lc + _macho.SEG_FILESIZE_OFFSET,
            seg.filesize + grow,
        )
        struct.pack_into(
            "<Q", self.buf, lc + _macho.SEG_VMSIZE_OFFSET,
            seg.vmsize + grow,
        )

        for other in mo.segments:
            if other.index == seg.index or other.fileoff < seg.file_end:
                continue
            other_lc = other.file_offset_of_lc
            struct.pack_into(
                "<Q", self.buf, other_lc + _macho.SEG_FILEOFF_OFFSET,
                other.fileoff + grow,
            )
            struct.pack_into(
                "<Q", self.buf, other_lc + _macho.SEG_VMADDR_OFFSET,
                other.vmaddr + grow,
            )
            for sect in other.sections:
                struct.pack_into(
                    "<Q", self.buf,
                    sect.file_offset_of_sect + _macho.SECT_ADDR_OFFSET,
                    sect.addr + grow,
                )
                if sect.offset:
                    struct.pack_into(
                        "<I", self.buf,
                        sect.file_offset_of_sect + _macho.SECT_OFFSET_OFFSET,
                        sect.offset + grow,
                    )

        for field in mo.file_offset_fields:
            if field.value == 0 or field.value < seg.file_end:
                continue
            struct.pack_into(
                "<I" if field.width == 4 else "<Q", self.buf,
                field.file_offset, field.value + grow,
            )


def _round_up(value: int, multiple: int) -> int:
    return -(-value // multiple) * multiple
