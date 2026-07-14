# cc-patcher

Binary patcher for the Bun-compiled Claude Code executable. Applies
same-length and growable edits to the embedded bundle and fixes up the
ELF / Bun framing so the result still boots.

The engine ships **no patches of its own**. Patch definitions come from
provider packages that register a `cc_patcher.patches` entry point;
cc-patcher discovers them at runtime via `importlib.metadata`.

## Install

cc-patcher is the base tool. Providers are injected into the same
environment with `--with` so their entry points are discoverable in the
one venv:

```bash
# model-splitter patches only
uv tool install git+https://github.com/andrewleech/cc-patcher \
    --with git+https://github.com/andrewleech/cc-local-router

# claude-net channel patches + model-splitter patches together
uv tool install git+https://github.com/andrewleech/cc-patcher \
    --with "git+https://github.com/andrewleech/claude-net#subdirectory=patcher-ext" \
    --with git+https://github.com/andrewleech/cc-local-router
```

Providers must share one environment with the engine. Separate
`uv tool install` invocations create isolated venvs that cannot see each
other's entry points, so `--with` (not a second install) is how you add
providers.

## Use

```bash
cc-patcher <src> <dst>        # patch a binary with every discovered patch
cc-patcher launch -- <argv>   # resolve + patch + cache the real binary, exec it
cc-patcher resolve            # same, but print the patched path instead of exec
cc-patcher --list-providers   # installed providers and their entry points
cc-patcher --list-patches     # discovered patches, in registry order
cc-patcher --emit-cache-key   # hash of the discovered registry
```

Patched binaries are cached under `~/.local/share/cc-patcher/`, keyed on
the source bytes plus the discovered patch registry — installing or
removing a provider invalidates the cache.

Exit codes: `0` all patches applied, `2` some patches missed (partial),
`1` fatal (validation conflict, parse failure, I/O error).

## Writing a provider

A provider exports a module-level list of `Patch`-shaped objects and
declares an entry point:

```toml
[project]
dependencies = ["cc-patcher"]

[project.entry-points."cc_patcher.patches"]
my-patches = "my_package:PATCHES"
```

The `Patch` protocol (`name`, `description`, `may_grow`, `expect_count`,
`diag_anchor`, `discover(ctx)`, `cache_key()`) is defined in
`cc_patcher.patches`. Discovery loads each entry point, sorts by entry-
point name, and concatenates the lists into the active registry.
