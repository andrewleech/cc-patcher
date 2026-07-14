"""Edit primitives and EditPlan validation.

An Edit is a single byte-level change: replace `old` with `new` at
`offset`. `len(new) - len(old)` is the delta — zero means same-length,
non-zero means it grows or shrinks the containing region. Growable
edits must lie wholly inside one StringPointer region and declare it
via `grows_region`; that region's length is bumped by `delta` during
header rewrite.

Patches emit Edits in terms of original (pre-splice) file offsets.
The applier handles splice ordering and offset bookkeeping; patches
never compute shifted offsets themselves.
"""

import dataclasses
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .context import DiscoveryContext


@dataclasses.dataclass(frozen=True)
class StringPointerRef:
    """Identifier for a StringPointer field. `kind` is "module" or
    "offsets". For module fields, `index` is the module index; for
    offsets fields, `index` is 0 and `field` selects between the two
    StringPointer slots in the Offsets struct."""

    kind: str
    index: int
    field: str


@dataclasses.dataclass(frozen=True)
class Edit:
    offset: int
    old: bytes
    new: bytes
    patch_name: str
    grows_region: Optional[StringPointerRef] = None

    @property
    def delta(self) -> int:
        return len(self.new) - len(self.old)


class PatchConflictError(Exception):
    pass


class RegionError(Exception):
    pass


@dataclasses.dataclass
class EditPlan:
    edits: list[Edit] = dataclasses.field(default_factory=list)

    def total_delta(self) -> int:
        return sum(e.delta for e in self.edits)

    def same_length(self) -> list[Edit]:
        return [e for e in self.edits if e.delta == 0]

    def growable(self) -> list[Edit]:
        return [e for e in self.edits if e.delta != 0]

    def validate(self, ctx: "DiscoveryContext") -> None:
        sorted_edits = sorted(self.edits, key=lambda e: e.offset)
        for prev, curr in zip(sorted_edits, sorted_edits[1:]):
            if prev.offset == curr.offset:
                raise PatchConflictError(
                    f"coincident edits at offset 0x{prev.offset:x} "
                    f"from {prev.patch_name!r} and {curr.patch_name!r}"
                )
            if prev.offset + len(prev.old) > curr.offset:
                raise PatchConflictError(
                    f"overlapping edits: {prev.patch_name!r} at "
                    f"[0x{prev.offset:x}, 0x{prev.offset + len(prev.old):x}) "
                    f"vs {curr.patch_name!r} at "
                    f"[0x{curr.offset:x}, 0x{curr.offset + len(curr.old):x})"
                )

        for e in self.edits:
            if ctx.is_framing_offset(e.offset):
                raise RegionError(
                    f"{e.patch_name!r} writes to payload framing at "
                    f"0x{e.offset:x}; framing edits are not permitted"
                )

        for e in self.edits:
            if e.delta == 0:
                continue
            if e.grows_region is None:
                raise RegionError(
                    f"{e.patch_name!r}: growable edit at 0x{e.offset:x} "
                    f"declares no grows_region"
                )
            if not ctx.edit_within_region(e):
                raise RegionError(
                    f"{e.patch_name!r}: edit at 0x{e.offset:x} straddles "
                    f"or escapes its declared region {e.grows_region}"
                )
            if ctx.is_latin1_region(e.grows_region):
                inserted = e.new[len(e.old):] if len(e.new) > len(e.old) else b""
                if any(b >= 128 for b in inserted):
                    raise RegionError(
                        f"{e.patch_name!r}: non-ASCII bytes inserted "
                        f"into Latin1 region {e.grows_region}"
                    )
