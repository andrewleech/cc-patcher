"""Patch protocol and registry.

A Patch inspects the DiscoveryContext, finds its anchor pattern, and
returns a list of Edits. Patches never compute shifted offsets or
mutate the buffer -- the orchestrator collects edits across all
patches, validates the plan, and applies it in one pass.

`PATCHES` is assembled from every installed provider package: each
provider registers one entry point in the `cc_patcher.patches` group,
resolving to a list of `Patch` instances. Entry points are loaded in
ascending name order and their lists concatenated, so the overall
order is deterministic and stable across runs on the same environment;
a provider's internal ordering (within its own list) is preserved.
The engine ships no patches of its own -- with no providers installed,
`PATCHES` is empty and a patch run is a clean no-op (exit code 0).
"""

import importlib.metadata
from typing import Protocol, Union

from .context import DiscoveryContext
from .edits import Edit

ExpectCount = Union[int, tuple[int, int | None], None]
"""A patch's expected discover() match count, checked by the CLI before
applying edits (see cli.py). `int` means exactly that many; `(lo, hi)`
means between `lo` and `hi` inclusive; `(lo, None)` means at least `lo`
with no upper bound."""

ENTRY_POINT_GROUP = "cc_patcher.patches"


class Patch(Protocol):
    name: str
    description: str
    may_grow: bool
    expect_count: ExpectCount
    diag_anchor: bytes | None

    def discover(self, ctx: DiscoveryContext) -> list[Edit]: ...

    def cache_key(self) -> str: ...


def discover_entry_points() -> list[importlib.metadata.EntryPoint]:
    """Installed entry points in the `cc_patcher.patches` group, sorted
    by entry-point name for deterministic discovery order."""
    eps = importlib.metadata.entry_points(group=ENTRY_POINT_GROUP)
    return sorted(eps, key=lambda ep: ep.name)


def discover_patches() -> list[Patch]:
    """Load every installed provider's patch list and concatenate them
    in entry-point-name order."""
    patches: list[Patch] = []
    for ep in discover_entry_points():
        provided = ep.load()
        patches.extend(provided)
    return patches


PATCHES: list[Patch] = discover_patches()
