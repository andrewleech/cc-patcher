"""CLI orchestrator for the Claude Code binary patcher.

Loads the input binary, builds a DiscoveryContext, runs every patch's
`discover()`, validates the assembled EditPlan, applies it via
EditApplier, writes the output, and prints a summary.

Exit codes:
  0 = all patches matched and applied
  1 = fatal error (validation conflict, parse failure, I/O failure)
  2 = some patches did not match (partial success -- diagnostics printed)
"""

import argparse
import dataclasses
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

from . import context as _context
from . import diagnostics as _diagnostics
from .edits import EditPlan, PatchConflictError, RegionError
from .patches import PATCHES, discover_entry_points


@dataclasses.dataclass
class PatchResult:
    name: str
    edits_emitted: int
    edits_applied: int
    growable: bool
    diagnostic_lines: list[str]

    @property
    def matched(self) -> bool:
        return self.edits_applied > 0


@dataclasses.dataclass
class PatchRunSummary:
    version: str
    input_size: int
    output_size: int
    results: list[PatchResult]

    @property
    def applied(self) -> list[PatchResult]:
        return [r for r in self.results if r.matched]

    @property
    def missed(self) -> list[PatchResult]:
        return [r for r in self.results if not r.matched]

    def exit_code(self) -> int:
        return 2 if self.missed else 0


def _capture_version(path: Path) -> str:
    try:
        out = subprocess.run(
            [str(path), "--version"], capture_output=True,
            text=True, timeout=10,
        ).stdout.strip()
        return out.split("\n", 1)[0] if out else "unknown"
    except Exception:
        return "unknown"


def run_patcher(src: Path, dst: Path) -> PatchRunSummary:
    buf = bytearray(src.read_bytes())
    input_size = len(buf)
    version = _capture_version(src)
    ctx = _context.parse(buf, version=version)

    plan = EditPlan()
    results: list[PatchResult] = []

    for patch in PATCHES:
        edits = patch.discover(ctx)
        if not edits:
            anchor = getattr(patch, "diag_anchor", None)
            diag = (
                _diagnostics.anchor_search(ctx, anchor)
                if anchor else []
            )
            results.append(PatchResult(
                name=patch.name, edits_emitted=0, edits_applied=0,
                growable=patch.may_grow, diagnostic_lines=diag,
            ))
            continue

        ec = patch.expect_count
        if ec is not None:
            lo, hi = (ec, ec) if isinstance(ec, int) else ec
            if len(edits) < lo or (hi is not None and len(edits) > hi):
                results.append(PatchResult(
                    name=patch.name,
                    edits_emitted=len(edits), edits_applied=0,
                    growable=patch.may_grow,
                    diagnostic_lines=[
                        f"expected {lo}-{hi if hi is not None else 'unbounded'} "
                        f"matches, got {len(edits)}"
                    ],
                ))
                continue

        plan.edits.extend(edits)
        results.append(PatchResult(
            name=patch.name,
            edits_emitted=len(edits), edits_applied=len(edits),
            growable=patch.may_grow, diagnostic_lines=[],
        ))

    try:
        plan.validate(ctx)
    except (PatchConflictError, RegionError) as exc:
        raise SystemExit(f"FATAL: plan validation failed: {exc}")

    applier = _context.EditApplier(ctx)
    new_buf = applier.apply(plan)

    dst.write_bytes(new_buf)
    shutil.copymode(src, dst)

    return PatchRunSummary(
        version=version,
        input_size=input_size,
        output_size=len(new_buf),
        results=results,
    )


def _print_summary(s: PatchRunSummary) -> None:
    print(
        f"Patching binary ({s.version}, {s.input_size:,} bytes)...",
        file=sys.stderr,
    )
    for i, r in enumerate(s.results, 1):
        flag = "applied" if r.matched else "MISSED"
        kind = "growable" if r.growable else "same-length"
        print(
            f"  Patch {i}: {r.name} -- {flag} "
            f"({r.edits_emitted} edit(s), {kind})",
            file=sys.stderr,
        )
        for d in r.diagnostic_lines:
            print(d, file=sys.stderr)

    delta = s.output_size - s.input_size
    if delta:
        print(
            f"  Size changed by {delta:+,} bytes "
            f"({s.input_size:,} -> {s.output_size:,})",
            file=sys.stderr,
        )
    else:
        print(f"  Size unchanged ({s.input_size:,} bytes)", file=sys.stderr)

    if s.missed:
        print(
            f"\n  {len(s.applied)} patch(es) applied, "
            f"{len(s.missed)} FAILED",
            file=sys.stderr,
        )


def cmd_emit_cache_key() -> int:
    h = hashlib.sha256()
    for patch in PATCHES:
        h.update(patch.cache_key().encode())
        h.update(b"\n")
    print(h.hexdigest())
    return 0


def cmd_list_patches() -> int:
    for i, patch in enumerate(PATCHES, 1):
        ec = patch.expect_count
        ec_str = (
            f"{ec[0]}-{ec[1] if ec[1] is not None else '∞'}"
            if isinstance(ec, tuple)
            else str(ec) if ec is not None else "any"
        )
        kind = "growable" if patch.may_grow else "same-length"
        print(f"{i}. {patch.name}")
        print(f"   kind={kind}  expect_count={ec_str}")
        print(f"   {patch.description}")
    return 0


def cmd_list_providers() -> int:
    eps = discover_entry_points()
    if not eps:
        print("No providers installed (cc_patcher.patches entry-point group is empty).")
        return 0
    for ep in eps:
        dist = ep.dist
        dist_str = f"{dist.name} {dist.version}" if dist else "unknown distribution"
        try:
            count = len(ep.load())
            count_str = f"{count} patch(es)"
        except Exception as exc:
            count_str = f"FAILED TO LOAD: {exc}"
        print(f"{ep.name}  ({dist_str})  {ep.value}  -- {count_str}")
    return 0


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "launch":
        from . import launch as _launch
        return _launch.cmd_launch(argv[1:])
    if argv and argv[0] == "resolve":
        from . import launch as _launch
        return _launch.cmd_resolve(argv[1:])

    parser = argparse.ArgumentParser(
        prog="cc-patcher",
        description="Claude Code binary patcher.",
    )
    parser.add_argument("source", nargs="?", type=Path,
                        help="path to the source Claude Code binary")
    parser.add_argument("output", nargs="?", type=Path,
                        help="path to write the patched binary")
    parser.add_argument("--emit-cache-key", action="store_true",
                        help="print a hash of the discovered patch registry and exit")
    parser.add_argument("--list-patches", action="store_true",
                        help="list discovered patches in registry order and exit")
    parser.add_argument("--list-providers", action="store_true",
                        help="list installed provider packages and their entry points, and exit")
    args = parser.parse_args(argv)

    if args.emit_cache_key:
        return cmd_emit_cache_key()
    if args.list_patches:
        return cmd_list_patches()
    if args.list_providers:
        return cmd_list_providers()

    if args.source is None or args.output is None:
        parser.error("source and output paths are required")
    if not args.source.is_file():
        parser.error(f"source not found: {args.source}")

    summary = run_patcher(args.source, args.output)
    _print_summary(summary)
    return summary.exit_code()


if __name__ == "__main__":
    sys.exit(main())
