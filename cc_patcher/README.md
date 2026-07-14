# cc-patcher

Patches Anthropic's Claude Code binary in place, same file size or larger,
without breaking the Bun standalone loader. This package is the reusable
engine only -- it ships no patches of its own. Patch definitions come from
separately-installed provider packages that register entries in the
`cc_patcher.patches` importlib.metadata entry-point group.

Does ELF/Bun header surgery so growable edits work -- needed for injecting
new entries into arrays and new arms into switch statements, not just
byte-swap-in-place replacements.

## Prereqs

- Python 3.11+, stdlib only
- Linux x86-64, ELF64 little-endian only for now

## Quick start

With no providers installed, the registry is empty and a patch run is a
no-op copy:

```
python -m cc_patcher $(readlink -f $(which claude)) /tmp/claude-patched
/tmp/claude-patched --version
```

Install one or more provider packages that expose `cc_patcher.patches`
entry points and they show up automatically:

```
cc-patcher --list-providers    # installed provider distributions + entry points
cc-patcher --list-patches      # patches in discovery order, across all providers
cc-patcher --emit-cache-key    # sha256 of the discovered registry
```

## Discovery contract

`cc_patcher.patches.PATCHES` is built at import time by enumerating
`importlib.metadata.entry_points(group="cc_patcher.patches")`, loading each
entry point, and concatenating the `Patch` lists it resolves to. Entry
points are visited in ascending name order; each provider's internal list
order is preserved. See `patches.py` for the `Patch` protocol a provider's
instances must satisfy.

## Launch helper

`cc_patcher.launch` resolves the real Claude Code binary, applies the
discovered patches, and caches the result under `~/.local/share/cc-patcher/`
keyed by a hash of the source binary plus the discovered registry:

```
cc-patcher launch -- --model haiku --print 'reply just "OK"'
```

Downstream launchers that need to shape argv/env before exec (extra CLI
flags, wrapper env vars) call `cc_patcher.launch.resolve_patched_binary()`
directly and exec the returned path themselves instead of using the `launch`
subcommand.

Exit codes from a patch run (`cc-patcher <src> <dst>`, and internally from
`resolve_patched_binary()`):

- `0` -- all discovered patches matched and applied
- `1` -- fatal error (validation conflict, ELF/Bun parse failure, I/O
  failure); `resolve_patched_binary()` falls back to the unpatched binary
- `2` -- partial success, some patches missed (diagnostics printed);
  `resolve_patched_binary()` falls back to the previous cached patched
  binary if one exists, otherwise proceeds with the partial result

## When a provider's anchor stops matching

Anthropic ships a new Claude Code release and one of a provider's regex
anchors stops matching -- the run reports which patch missed. Patches
declare a `diag_anchor` that gets grepped in the binary and printed with
120 bytes of context, so you can see whether the anchor moved, the
surrounding code changed shape, or the feature was removed. That diagnosis
and fix lives in the provider package, not here.

## File layout

```
cc_patcher/
  __main__.py       entry: `python -m cc_patcher`
  cli.py            orchestrator, argparse, summary printing, cache-key,
                     --list-patches / --list-providers
  launch.py          binary resolution + patch caching + `launch` subcommand
  elf.py            ELF64 read: headers, sections, segments
  bun.py            Bun payload framing: trailer, Offsets struct, modules table
  edits.py          Edit dataclass, EditPlan, validation
  context.py        DiscoveryContext (view for patches) + EditApplier (owns the buffer)
  diagnostics.py    anchor_search for failed-patch diagnostics
  patches.py        Patch protocol + entry-point-driven PATCHES registry
```

## See also

- `docs/PATCHER_V2_ARCHITECTURE.md` in the claude-net repo -- design history
  and decisions behind the ELF/Bun header surgery this engine performs.
