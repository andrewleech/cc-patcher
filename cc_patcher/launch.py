"""Binary resolution and patch caching for downstream `claude` launchers.

Resolves the real Claude Code binary, applies every patch discovered
in `cc_patcher.patches.PATCHES`, and caches the patched result under
`~/.local/share/cc-patcher/`, keyed by a hash of the source binary
bytes plus the discovered patch registry (so a change to the source
binary or to the installed provider set invalidates the cache, but
re-running against an unchanged binary and provider set is a no-op).

Downstream launchers call `resolve_patched_binary()` to get a path to
exec with their own argv/env shaping, or invoke `cc-patcher launch --
<argv...>` directly when no extra shaping is needed.

Exit-code semantics of the underlying patch run are unchanged from
`cc-patcher <src> <dst>`: a fatal error (exit 1) falls back to the
unpatched binary; a partial match (exit 2) falls back to the previous
cached patched binary when one exists, otherwise proceeds with the
partially-patched result.
"""

import os
import shutil
import sys
from hashlib import sha256
from pathlib import Path

from . import binfmt as _binfmt
from .cli import _print_summary, run_patcher
from .patches import PATCHES

CACHE_DIRNAME = "cc-patcher"
PATCHED_LINK_NAME = "claude-patched"


class BinaryNotFoundError(Exception):
    pass


def _resolve_existing(path: Path) -> Path | None:
    """Resolve `path` (following symlinks) if it exists, else None."""
    try:
        if path.exists():
            return path.resolve()
    except OSError:
        pass
    return None


def _looks_like_native_binary(path: Path) -> bool:
    """True if `path` is an ELF or 64-bit Mach-O executable — i.e. a
    Bun-compiled binary the patcher can read, not a shell/JS wrapper."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return False
    return magic in (_binfmt.ELF_MAGIC, _binfmt.MACHO_MAGIC_64)


def find_claude_binary(cli_path_env: str | None = None) -> Path:
    """Locate the real Claude Code native binary.

    Checks `CLAUDE_CLI_PATH` first, then well-known native-install
    locations, then PATH resolution. PATH resolution rejects
    non-native matches (e.g. the npm launcher's `cli.js` wrapper
    script) with a clear error instead of letting the patcher fail on
    "no anchor strings found".
    """
    env_value = (
        cli_path_env if cli_path_env is not None
        else os.environ.get("CLAUDE_CLI_PATH")
    )
    if env_value and Path(env_value).is_file():
        return Path(env_value)

    home = Path.home()
    candidates = [
        home / ".local" / "bin" / "claude",
        home / ".claude" / "local" / "claude",
    ]
    versions_dir = home / ".local" / "share" / "claude" / "versions"
    if versions_dir.is_dir():
        candidates.extend(sorted(versions_dir.iterdir()))

    for candidate in candidates:
        resolved = _resolve_existing(candidate)
        if resolved and resolved.is_file() and _looks_like_native_binary(resolved):
            return resolved

    which = shutil.which("claude")
    if which:
        resolved = _resolve_existing(Path(which))
        if resolved and resolved.is_file():
            if _looks_like_native_binary(resolved):
                return resolved
            raise BinaryNotFoundError(
                f"$PATH 'claude' resolves to {resolved}, which is not the "
                "Bun-compiled native binary the patcher needs (likely the "
                "npm-install launcher's cli.js wrapper). Install the native "
                "binary alongside it: curl -fsSL https://claude.ai/install.sh "
                "| bash"
            )

    raise BinaryNotFoundError("Could not find Claude Code binary.")


def cache_dir() -> Path:
    d = Path.home() / ".local" / "share" / CACHE_DIRNAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def engine_cache_key() -> str:
    """Hash of this installed `cc_patcher` package's own `.py` source.

    Folded into `registry_cache_key()` so an engine upgrade (e.g. a fix
    to `EditApplier`'s edit-application semantics) invalidates cached
    patched binaries even when the discovered patch registry -- whose
    `cache_key()`s only cover each patch's own anchor/replacement --
    is unchanged."""
    pkg_dir = Path(__file__).resolve().parent
    h = sha256()
    for path in sorted(pkg_dir.rglob("*.py")):
        h.update(str(path.relative_to(pkg_dir)).encode())
        h.update(b"\0")
        h.update(path.read_bytes())
    return h.hexdigest()


def registry_cache_key() -> str:
    h = sha256()
    h.update(engine_cache_key().encode())
    for patch in PATCHES:
        h.update(patch.cache_key().encode())
        h.update(b"\n")
    return h.hexdigest()


def binary_cache_key(binary: Path) -> str:
    """sha256(binary bytes) folded with the discovered-registry cache
    key, truncated to a short, still-collision-safe cache filename
    suffix. Changes whenever the source binary or the installed
    provider set changes."""
    h = sha256()
    h.update(binary.read_bytes())
    h.update(registry_cache_key().encode())
    return h.hexdigest()[:16]


def resolve_patched_binary(cli_path_env: str | None = None) -> Path:
    """Return the path to a cached, patched Claude Code binary,
    patching and caching it first if this binary+registry combination
    hasn't been seen before."""
    if not PATCHES:
        print(
            "[cc-patcher] WARNING: no cc_patcher.patches providers are "
            "installed in this Python environment -- launching an "
            "UNPATCHED Claude Code binary. Install a provider package "
            "(e.g. claude-net-patcher, cc-local-router) alongside "
            "cc-patcher.",
            file=sys.stderr,
        )

    src = find_claude_binary(cli_path_env)
    cdir = cache_dir()
    link = cdir / PATCHED_LINK_NAME

    key = binary_cache_key(src)
    versioned = cdir / f"claude-patched-{key}"

    if not versioned.is_file():
        try:
            summary = run_patcher(src, versioned)
        except (SystemExit, Exception) as exc:
            # Any failure here (validation conflict, container/Bun
            # parse error, I/O failure) is fatal to this patch attempt --
            # same bucket as exit code 1 from the standalone CLI.
            print(f"[cc-patcher] {exc}", file=sys.stderr)
            versioned.unlink(missing_ok=True)
            print(
                "[cc-patcher] Fatal patching error. Falling back to "
                "unpatched binary.",
                file=sys.stderr,
            )
            versioned = src
        else:
            _print_summary(summary)
            if summary.missed:
                prev = _resolve_existing(link)
                if prev and prev.is_file() and prev != versioned:
                    print(
                        f"[cc-patcher] partial patch on new build; using "
                        f"previous patched binary {prev.name}",
                        file=sys.stderr,
                    )
                    versioned.unlink(missing_ok=True)
                    versioned = prev
                else:
                    print(
                        "[cc-patcher] partial patch; continuing -- some "
                        "restrictions may still apply",
                        file=sys.stderr,
                    )

        if versioned != src:
            for old in cdir.glob("claude-patched-*"):
                if old.name != versioned.name:
                    old.unlink(missing_ok=True)

    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(versioned)

    # Return the stable symlink, not the hash-versioned target: callers
    # exec this path directly, so argv[0] must end in exactly
    # "claude-patched" for downstream argv[0]-anchored regexes (e.g.
    # claude-net's mirror-agent CC_BINARY_PATTERN) to recognize the
    # process as a channels-launched Claude Code.
    return link


def cmd_launch(argv: list[str]) -> int:
    """Implements `cc-patcher launch -- <argv...>`: resolve, patch, and
    cache the real binary, then exec it with `argv` unchanged."""
    if argv and argv[0] == "--":
        argv = argv[1:]
    patched = resolve_patched_binary()
    os.execv(str(patched), [str(patched), *argv])


def cmd_resolve(argv: list[str]) -> int:
    """Implements `cc-patcher resolve`: resolve, patch, and cache the
    real binary, then print its path (no exec). Used by launchers that
    inject their own env/argv before exec'ing the binary themselves.

    Refuses (exit 1) if no `cc_patcher.patches` provider is installed —
    launching against an unpatched binary is never the intent here."""
    import sys

    from .patches import PATCHES

    if not PATCHES:
        print(
            "ERROR: cc-patcher is installed but no cc_patcher.patches "
            "provider is. Install a provider alongside it, e.g.:\n"
            "    uv tool install cc-patcher --with claude-net-patcher",
            file=sys.stderr,
        )
        return 1
    try:
        print(resolve_patched_binary())
    except BinaryNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0
