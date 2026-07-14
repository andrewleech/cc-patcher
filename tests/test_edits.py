"""Unit tests for EditPlan validation (edits.py).

Exercises the plan-level invariants -- coincident/overlapping edits,
framing protection, region containment, Latin1 byte safety -- against a
minimal fake DiscoveryContext, so these rules are covered without
needing a real ELF/Bun binary fixture.
"""

import unittest

from cc_patcher.edits import (
    Edit,
    EditPlan,
    PatchConflictError,
    RegionError,
    StringPointerRef,
)


class FakeStringPointer:
    def __init__(self, offset: int, length: int):
        self.offset = offset
        self.length = length


class FakeContext:
    """Stand-in for DiscoveryContext: enough surface for EditPlan.validate."""

    def __init__(self, regions=None, framing_start=None, latin1_regions=()):
        self.regions = regions or {}
        self.framing_start = framing_start
        self.latin1_regions = set(latin1_regions)

    def is_framing_offset(self, abs_offset: int) -> bool:
        return self.framing_start is not None and abs_offset >= self.framing_start

    def edit_within_region(self, edit: Edit) -> bool:
        ref = edit.grows_region
        sp = self.regions.get(ref)
        if sp is None:
            return False
        return sp.offset <= edit.offset and (
            edit.offset + len(edit.old) <= sp.offset + sp.length
        )

    def is_latin1_region(self, ref: StringPointerRef) -> bool:
        return ref in self.latin1_regions


REGION = StringPointerRef("module", 0, "contents")


class EditPlanValidateTests(unittest.TestCase):
    def test_disjoint_same_length_edits_pass(self):
        ctx = FakeContext()
        plan = EditPlan(edits=[
            Edit(offset=10, old=b"ab", new=b"cd", patch_name="p1"),
            Edit(offset=20, old=b"ef", new=b"gh", patch_name="p2"),
        ])
        plan.validate(ctx)  # no raise

    def test_coincident_offsets_conflict(self):
        ctx = FakeContext()
        plan = EditPlan(edits=[
            Edit(offset=10, old=b"a", new=b"b", patch_name="p1"),
            Edit(offset=10, old=b"c", new=b"d", patch_name="p2"),
        ])
        with self.assertRaises(PatchConflictError):
            plan.validate(ctx)

    def test_overlapping_ranges_conflict(self):
        ctx = FakeContext()
        plan = EditPlan(edits=[
            Edit(offset=10, old=b"abcd", new=b"abcd", patch_name="p1"),
            Edit(offset=12, old=b"cd", new=b"cd", patch_name="p2"),
        ])
        with self.assertRaises(PatchConflictError):
            plan.validate(ctx)

    def test_adjacent_non_overlapping_ranges_pass(self):
        ctx = FakeContext()
        plan = EditPlan(edits=[
            Edit(offset=10, old=b"ab", new=b"ab", patch_name="p1"),
            Edit(offset=12, old=b"cd", new=b"cd", patch_name="p2"),
        ])
        plan.validate(ctx)  # no raise

    def test_framing_offset_rejected(self):
        ctx = FakeContext(framing_start=100)
        plan = EditPlan(edits=[
            Edit(offset=150, old=b"a", new=b"b", patch_name="p1"),
        ])
        with self.assertRaises(RegionError):
            plan.validate(ctx)

    def test_growable_edit_without_region_rejected(self):
        ctx = FakeContext()
        plan = EditPlan(edits=[
            Edit(offset=10, old=b"a", new=b"bb", patch_name="p1"),
        ])
        with self.assertRaises(RegionError):
            plan.validate(ctx)

    def test_growable_edit_escaping_region_rejected(self):
        ctx = FakeContext(regions={REGION: FakeStringPointer(offset=0, length=5)})
        plan = EditPlan(edits=[
            Edit(
                offset=4, old=b"ab", new=b"bbb",
                patch_name="p1", grows_region=REGION,
            ),
        ])
        with self.assertRaises(RegionError):
            plan.validate(ctx)

    def test_growable_edit_within_region_passes(self):
        ctx = FakeContext(regions={REGION: FakeStringPointer(offset=0, length=5)})
        plan = EditPlan(edits=[
            Edit(
                offset=2, old=b"a", new=b"bb",
                patch_name="p1", grows_region=REGION,
            ),
        ])
        plan.validate(ctx)  # no raise

    def test_non_ascii_insert_into_latin1_region_rejected(self):
        ctx = FakeContext(
            regions={REGION: FakeStringPointer(offset=0, length=10)},
            latin1_regions=(REGION,),
        )
        plan = EditPlan(edits=[
            Edit(
                offset=2, old=b"]", new=b',"\xc3\xa9"]',
                patch_name="p1", grows_region=REGION,
            ),
        ])
        with self.assertRaises(RegionError):
            plan.validate(ctx)

    def test_ascii_insert_into_latin1_region_passes(self):
        ctx = FakeContext(
            regions={REGION: FakeStringPointer(offset=0, length=10)},
            latin1_regions=(REGION,),
        )
        plan = EditPlan(edits=[
            Edit(
                offset=2, old=b"]", new=b',"local"]',
                patch_name="p1", grows_region=REGION,
            ),
        ])
        plan.validate(ctx)  # no raise


class EditPlanDeltaTests(unittest.TestCase):
    def test_total_delta_sums_growable_and_same_length(self):
        plan = EditPlan(edits=[
            Edit(offset=1, old=b"a", new=b"a", patch_name="same"),
            Edit(offset=2, old=b"a", new=b"aaa", patch_name="grow"),
        ])
        self.assertEqual(plan.total_delta(), 2)
        self.assertEqual(len(plan.same_length()), 1)
        self.assertEqual(len(plan.growable()), 1)


if __name__ == "__main__":
    unittest.main()
