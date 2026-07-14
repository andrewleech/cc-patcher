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
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

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


def _looks_like_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def find_claude_binary(cli_path_env: str | None = None) -> Path:
    """Locate the real Claude Code ELF binary.

    Checks `CLAUDE_CLI_PATH` first, then well-known native-install
    locations, then PATH resolution. PATH resolution rejects non-ELF
    matches (e.g. the npm launcher's `cli.js` wrapper script) with a
    clear error instead of letting the patcher fail on "no anchor
    strings found".
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
        if resolved and resolved.is_file() and _looks_like_elf(resolved):
            return resolved

    which = shutil.which("claude")
    if which:
        resolved = _resolve_existing(Path(which))
        if resolved and resolved.is_file():
            if _looks_like_elf(resolved):
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


def registry_cache_key() -> str:
    h = sha256()
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


def _codesign(path: Path) -> None:
    """macOS only: in-place byte patches invalidate Apple's code
    signature, and AMFI then silently kills the binary at exec. Ad-hoc
    re-sign with preserved entitlements so Bun's JIT / dylib loading
    still works."""
    if shutil.which("codesign") is None:
        return
    result = subprocess.run(
        [
            "codesign", "--force",
            "--preserve-metadata=entitlements,requirements,flags,runtime",
            "--sign", "-", str(path),
        ],
        capture_output=True,
    )
    if result.returncode == 0:
        return
    # Some binaries lack enough metadata to preserve -- fall back to a
    # bare ad-hoc sign.
    result = subprocess.run(
        ["codesign", "--force", "--sign", "-", str(path)],
        capture_output=True,
    )
    if result.returncode != 0:
        print(
            "WARN: codesign failed -- macOS AMFI may kill the patched "
            "binary at exec.",
            file=sys.stderr,
        )


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
            # Any failure here (validation conflict, ELF/Bun parse
            # error, I/O failure) is fatal to this patch attempt --
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
            if sys.platform == "darwin":
                _codesign(versioned)
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
