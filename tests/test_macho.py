"""Mach-O container reader + applier tests against a synthetic binary.

The real macOS Claude Code binary only ever exercises the padding-
consume path (its `__LINKEDIT` alignment padding is far larger than
anything the patches insert), so the segment-growth path is covered
here with a fixture whose padding is deliberately too small.
"""

import struct
import unittest

from cc_patcher import binfmt, bun as _bun, context, macho
from cc_patcher.edits import Edit, EditPlan

PAGE = 4096
TEXT_VMADDR = 0x100000000

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
LC_CODE_SIGNATURE = 0x1D

# Load-command table offsets in the fixture, in emission order.
LC_TEXT_OFF = 32
LC_BUN_OFF = LC_TEXT_OFF + 72
LC_BUN_SECT_OFF = LC_BUN_OFF + 72
LC_LINKEDIT_OFF = LC_BUN_OFF + 152
LC_SYMTAB_OFF = LC_LINKEDIT_OFF + 72
LC_CODESIG_OFF = LC_SYMTAB_OFF + 24
SIZEOFCMDS = LC_CODESIG_OFF + 16 - 32

LINKEDIT_SIZE = PAGE


def _segment_64(segname, vmaddr, vmsize, fileoff, filesize, nsects):
    return struct.pack(
        "<II16sQQQQiiII",
        LC_SEGMENT_64, 72 + nsects * 80, segname,
        vmaddr, vmsize, fileoff, filesize,
        7, 5, nsects, 0,
    )


def _section_64(sectname, segname, addr, size, offset):
    return struct.pack(
        "<16s16sQQIIIIIIII",
        sectname, segname, addr, size, offset, 14,
        0, 0, 0x10000000, 0, 0, 0,
    )


def build_fixture(
    js_body: bytes, target_pad: int, bytecode: tuple[int, int] = (0, 0),
) -> tuple[bytearray, dict]:
    """A minimal but internally consistent Mach-O + Bun payload.

    `target_pad` is the number of zero alignment bytes left between the
    end of the Bun payload and the start of `__LINKEDIT`; the JS body is
    space-padded to whatever length makes that come out exact.

    `bytecode` seeds module 0's bytecode StringPointer -- non-zero
    simulates a `bun build --bytecode` JSC cache, so tests can assert
    the applier invalidates it when the module's JS text is patched.
    """
    # payload = js | modules table (52) | Offsets (32) | trailer (16)
    overhead = _bun.MODULE_RECORD_SIZE + _bun.OFFSETS_STRUCT.size + len(_bun.TRAILER)
    filler = (-(8 + len(js_body) + overhead + target_pad)) % PAGE
    js = js_body + b" " * filler

    mods_off = len(js)
    offsets_rel = mods_off + _bun.MODULE_RECORD_SIZE
    payload_len = offsets_rel + _bun.OFFSETS_STRUCT.size + len(_bun.TRAILER)

    module = b"".join([
        _bun.STRING_POINTER_STRUCT.pack(0, 0),          # name
        _bun.STRING_POINTER_STRUCT.pack(0, len(js)),    # contents
        _bun.STRING_POINTER_STRUCT.pack(0, 0),          # sourcemap
        _bun.STRING_POINTER_STRUCT.pack(*bytecode),     # bytecode
        _bun.STRING_POINTER_STRUCT.pack(0, 0),          # module_info
        _bun.STRING_POINTER_STRUCT.pack(0, 0),          # bytecode_origin_path
        bytes([_bun.ENCODING_LATIN1, 0, 0, 0]),
    ])
    offsets = _bun.OFFSETS_STRUCT.pack(
        offsets_rel,        # byte_count
        mods_off, _bun.MODULE_RECORD_SIZE,
        0,                  # entry_point_id
        0, 0,               # compile_exec_argv
        0,                  # flags
    )
    payload = js + module + offsets + _bun.TRAILER
    assert len(payload) == payload_len

    bun_fileoff = PAGE
    bun_sect_size = 8 + payload_len
    bun_filesize = bun_sect_size + target_pad
    assert (bun_fileoff + bun_filesize) % PAGE == 0, "fixture is misaligned"
    bun_vmaddr = TEXT_VMADDR + PAGE
    linkedit_off = bun_fileoff + bun_filesize
    linkedit_vmaddr = bun_vmaddr + bun_filesize

    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF, 0x01000007, 3, 2, 5, SIZEOFCMDS, 0x00200085, 0,
    )
    cmds = b"".join([
        _segment_64(b"__TEXT", TEXT_VMADDR, PAGE, 0, PAGE, 0),
        _segment_64(b"__BUN", bun_vmaddr, bun_filesize,
                    bun_fileoff, bun_filesize, 1),
        _section_64(b"__bun", b"__BUN", bun_vmaddr, bun_sect_size, bun_fileoff),
        _segment_64(b"__LINKEDIT", linkedit_vmaddr, LINKEDIT_SIZE,
                    linkedit_off, LINKEDIT_SIZE, 0),
        struct.pack("<IIIIII", LC_SYMTAB, 24,
                    linkedit_off, 4, linkedit_off + 1024, 512),
        struct.pack("<IIII", LC_CODE_SIGNATURE, 16,
                    linkedit_off + 2048, 1024),
    ])
    assert len(cmds) == SIZEOFCMDS, (len(cmds), SIZEOFCMDS)

    buf = bytearray(linkedit_off + LINKEDIT_SIZE)
    buf[0:32] = header
    buf[32:32 + len(cmds)] = cmds
    struct.pack_into("<Q", buf, bun_fileoff, payload_len)
    buf[bun_fileoff + 8:bun_fileoff + 8 + payload_len] = payload

    meta = {
        "js_offset": bun_fileoff + 8,
        "js_len": len(js),
        "bun_fileoff": bun_fileoff,
        "bun_sect_size": bun_sect_size,
        "bun_filesize": bun_filesize,
        "bun_vmaddr": bun_vmaddr,
        "linkedit_off": linkedit_off,
        "linkedit_vmaddr": linkedit_vmaddr,
        "pad": target_pad,
        "total_size": len(buf),
    }
    return buf, meta


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


JS = b'switch(m){case"opus":return A;default:return null}'


class SniffTests(unittest.TestCase):
    def test_macho_magic_recognised(self):
        buf, _ = build_fixture(JS, target_pad=512)
        self.assertEqual(binfmt.sniff(buf), binfmt.FORMAT_MACHO)

    def test_fat_binary_rejected_with_lipo_hint(self):
        with self.assertRaises(binfmt.UnsupportedContainerError) as cm:
            binfmt.sniff(binfmt.FAT_MAGIC + b"\0" * 60)
        self.assertIn("lipo", str(cm.exception))

    def test_unknown_magic_rejected(self):
        with self.assertRaises(binfmt.UnsupportedContainerError):
            binfmt.sniff(b"#!/b" + b"\0" * 60)


class MachOParseTests(unittest.TestCase):
    def setUp(self):
        self.buf, self.meta = build_fixture(JS, target_pad=512)
        self.layout = macho.parse(self.buf)

    def test_segments_parsed_in_order(self):
        self.assertEqual(
            [s.segname for s in self.layout.segments],
            [b"__TEXT", b"__BUN", b"__LINKEDIT"],
        )

    def test_bun_section_located(self):
        sect = self.layout.bun_section()
        self.assertEqual(sect.offset, self.meta["bun_fileoff"])
        self.assertEqual(sect.size, self.meta["bun_sect_size"])

    def test_file_offset_fields_indexed_with_values(self):
        found = {(f.cmd, f.name): f.value for f in self.layout.file_offset_fields}
        le = self.meta["linkedit_off"]
        self.assertEqual(found[(LC_SYMTAB, "symoff")], le)
        self.assertEqual(found[(LC_SYMTAB, "stroff")], le + 1024)
        self.assertEqual(found[(LC_CODE_SIGNATURE, "dataoff")], le + 2048)

    def test_page_size_follows_cpu_type(self):
        self.assertEqual(self.layout.page_size, PAGE)
        arm = bytearray(self.buf)
        struct.pack_into("<i", arm, 4, macho.CPU_TYPE_ARM64)
        self.assertEqual(macho.parse(arm).page_size, 16384)

    def test_unrecognised_load_command_is_refused(self):
        buf = bytearray(self.buf)
        struct.pack_into("<I", buf, LC_SYMTAB_OFF, 0x7FFF)
        with self.assertRaises(macho.MachOFormatError) as cm:
            macho.parse(buf)
        self.assertIn("0x7fff", str(cm.exception))

    def test_non_executable_filetype_refused(self):
        buf = bytearray(self.buf)
        struct.pack_into("<I", buf, 12, 6)  # MH_DYLIB
        with self.assertRaises(macho.MachOFormatError):
            macho.parse(buf)

    def test_bun_framing_parses_through_the_container(self):
        ctx = context.parse(self.buf)
        self.assertEqual(ctx.bun.payload_start, self.meta["js_offset"])
        self.assertEqual(len(ctx.bun.modules), 1)
        self.assertEqual(
            ctx.bun.modules[0].contents.length, self.meta["js_len"],
        )


class MachOGrowableApplyTests(unittest.TestCase):
    """A growable edit must leave a loadable binary: every segment
    page-aligned, `vmaddr - fileoff` unchanged per segment, and every
    __LINKEDIT-referencing load command still pointing at its data."""

    INSERT = b'case"local":return A;'

    def _apply_insert(self, target_pad):
        buf, meta = build_fixture(JS, target_pad=target_pad)
        ctx = context.parse(buf)
        meta["payload_len"] = ctx.bun.payload_len
        at = buf.index(b"default:", meta["js_offset"])
        plan = EditPlan(edits=[Edit(
            offset=at, old=b"default:", new=self.INSERT + b"default:",
            patch_name="test", grows_region=ctx.containing_string_pointer(at),
        )])
        context.EditApplier(ctx).apply(plan)
        return buf, meta, len(self.INSERT)

    def _assert_reparses(self, buf, meta, delta):
        layout = macho.parse(buf)
        for seg in layout.segments:
            self.assertEqual(seg.fileoff % PAGE, 0, f"{seg.segname} fileoff")
            self.assertEqual(seg.vmaddr % PAGE, 0, f"{seg.segname} vmaddr")
        bun = layout.segment_by_name(macho.BUN_SEGNAME)
        linkedit = layout.segment_by_name(b"__LINKEDIT")
        self.assertEqual(bun.file_end, linkedit.fileoff)
        self.assertEqual(bun.vmaddr + bun.vmsize, linkedit.vmaddr)
        self.assertEqual(bun.vmaddr - bun.fileoff, linkedit.vmaddr - linkedit.fileoff)
        self.assertEqual(linkedit.file_end, len(buf))
        self.assertEqual(
            _bun.locate(buf, layout).payload_len, meta["payload_len"] + delta,
        )
        return layout

    def test_insert_fitting_in_padding_moves_nothing(self):
        buf, meta, delta = self._apply_insert(target_pad=512)
        self.assertEqual(len(buf), meta["total_size"], "file size must not change")
        layout = self._assert_reparses(buf, meta, delta)

        bun = layout.segment_by_name(macho.BUN_SEGNAME)
        self.assertEqual(bun.filesize, meta["bun_filesize"])
        self.assertEqual(bun.vmsize, meta["bun_filesize"])
        self.assertEqual(
            layout.bun_section().size, meta["bun_sect_size"] + delta,
        )
        self.assertEqual(
            layout.segment_by_name(b"__LINKEDIT").fileoff, meta["linkedit_off"],
        )
        self.assertEqual(_u32(buf, LC_SYMTAB_OFF + 8), meta["linkedit_off"])
        self.assertEqual(
            _u32(buf, LC_CODESIG_OFF + 8), meta["linkedit_off"] + 2048,
        )

    def test_insert_exceeding_padding_grows_bun_by_one_page(self):
        buf, meta, delta = self._apply_insert(target_pad=0)
        self.assertEqual(len(buf), meta["total_size"] + PAGE)
        layout = self._assert_reparses(buf, meta, delta)

        bun = layout.segment_by_name(macho.BUN_SEGNAME)
        self.assertEqual(bun.filesize, meta["bun_filesize"] + PAGE)
        self.assertEqual(bun.vmsize, meta["bun_filesize"] + PAGE)
        self.assertEqual(
            layout.bun_section().size, meta["bun_sect_size"] + delta,
        )

        linkedit = layout.segment_by_name(b"__LINKEDIT")
        self.assertEqual(linkedit.fileoff, meta["linkedit_off"] + PAGE)
        self.assertEqual(linkedit.vmaddr, meta["linkedit_vmaddr"] + PAGE)
        self.assertEqual(_u32(buf, LC_SYMTAB_OFF + 8), meta["linkedit_off"] + PAGE)
        self.assertEqual(
            _u32(buf, LC_SYMTAB_OFF + 16), meta["linkedit_off"] + 1024 + PAGE,
        )
        self.assertEqual(
            _u32(buf, LC_CODESIG_OFF + 8), meta["linkedit_off"] + 2048 + PAGE,
        )

    def test_inserted_text_lands_before_the_default_arm(self):
        buf, meta, _ = self._apply_insert(target_pad=512)
        js = bytes(buf[meta["js_offset"]:meta["js_offset"] + meta["js_len"] + 64])
        self.assertIn(self.INSERT + b"default:return null", js)

    def test_padding_gap_is_still_zero_filled(self):
        buf, meta, delta = self._apply_insert(target_pad=512)
        layout = macho.parse(buf)
        sect = layout.bun_section()
        gap_start = sect.offset + sect.size
        gap_end = layout.segment_by_name(macho.BUN_SEGNAME).file_end
        self.assertEqual(gap_end - gap_start, meta["pad"] - delta)
        self.assertEqual(bytes(buf[gap_start:gap_end]), b"\0" * (gap_end - gap_start))

    def test_non_zero_padding_is_refused(self):
        buf, meta = build_fixture(JS, target_pad=512)
        buf[meta["bun_fileoff"] + meta["bun_sect_size"] + 8] = 0x41
        ctx = context.parse(buf)
        at = buf.index(b"default:", meta["js_offset"])
        plan = EditPlan(edits=[Edit(
            offset=at, old=b"default:", new=self.INSERT + b"default:",
            patch_name="test", grows_region=ctx.containing_string_pointer(at),
        )])
        with self.assertRaises(RuntimeError) as cm:
            context.EditApplier(ctx).apply(plan)
        self.assertIn("padding", str(cm.exception))


class MachOSameLengthApplyTests(unittest.TestCase):
    def test_same_length_edit_touches_no_headers(self):
        buf, meta = build_fixture(JS, target_pad=512)
        before = bytes(buf[:32 + SIZEOFCMDS])
        ctx = context.parse(buf)
        at = buf.index(b"case", meta["js_offset"])
        plan = EditPlan(edits=[Edit(
            offset=at, old=b"case", new=b"CASE", patch_name="test",
        )])
        context.EditApplier(ctx).apply(plan)
        self.assertEqual(len(buf), meta["total_size"])
        self.assertEqual(bytes(buf[:32 + SIZEOFCMDS]), before)
        self.assertEqual(bytes(buf[at:at + 4]), b"CASE")


class BytecodeInvalidationTests(unittest.TestCase):
    """A patched module's JSC bytecode cache must be zeroed, or Bun's
    standalone runtime keeps executing the pre-patch cached bytecode
    and ignores the edited `contents` text entirely."""

    def test_same_length_edit_zeroes_the_module_bytecode_pointer(self):
        buf, meta = build_fixture(JS, target_pad=512, bytecode=(0, 999))
        ctx = context.parse(buf)
        self.assertEqual(ctx.bun.modules[0].bytecode, _bun.StringPtr(0, 999))
        at = buf.index(b"case", meta["js_offset"])
        plan = EditPlan(edits=[Edit(
            offset=at, old=b"case", new=b"CASE", patch_name="test",
        )])
        context.EditApplier(ctx).apply(plan)
        reparsed = context.parse(buf)
        self.assertEqual(reparsed.bun.modules[0].bytecode, _bun.StringPtr(0, 0))

    def test_growable_edit_zeroes_the_module_bytecode_pointer(self):
        buf, meta = build_fixture(JS, target_pad=512, bytecode=(0, 999))
        ctx = context.parse(buf)
        at = buf.index(b"default:", meta["js_offset"])
        plan = EditPlan(edits=[Edit(
            offset=at, old=b"default:", new=b'case"local":return A;default:',
            patch_name="test", grows_region=ctx.containing_string_pointer(at),
        )])
        context.EditApplier(ctx).apply(plan)
        reparsed = context.parse(buf)
        self.assertEqual(reparsed.bun.modules[0].bytecode, _bun.StringPtr(0, 0))

    def test_untouched_modules_keep_their_bytecode_pointer(self):
        buf, meta = build_fixture(JS, target_pad=512, bytecode=(0, 999))
        ctx = context.parse(buf)
        plan = EditPlan(edits=[])
        context.EditApplier(ctx).apply(plan)
        reparsed = context.parse(buf)
        self.assertEqual(reparsed.bun.modules[0].bytecode, _bun.StringPtr(0, 999))


if __name__ == "__main__":
    unittest.main()
