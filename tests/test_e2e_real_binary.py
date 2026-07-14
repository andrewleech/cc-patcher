"""End-to-end test against the real, locally installed Claude Code
binary (skipped when one isn't present, e.g. in CI).

Exercises the full discover -> validate -> apply -> re-parse pipeline
against production input, and asserts the two load-bearing contracts
from docs/PATCHER_EXTRACTION_PLAN.md:

  - `--version` still reports the real Claude Code version after
    patching.
  - Idempotence: re-running the patcher against its own output is
    byte-stable (a no-op).
"""

import subprocess
import tempfile
import unittest
from pathlib import Path

from cc_patcher.cli import run_patcher
from cc_patcher.launch import find_claude_binary, BinaryNotFoundError
from cc_patcher.patches import PATCHES


def _real_claude_binary() -> Path | None:
    try:
        return find_claude_binary()
    except BinaryNotFoundError:
        return None


def _version_of(path: Path) -> str:
    out = subprocess.run(
        [str(path), "--version"], capture_output=True, text=True, timeout=10,
    ).stdout.strip()
    return out.split("\n", 1)[0] if out else ""


@unittest.skipUnless(_real_claude_binary(), "no local Claude Code install found")
@unittest.skipUnless(PATCHES, "no cc_patcher.patches providers installed")
class RealBinaryE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = _real_claude_binary()
        cls.tmpdir = tempfile.TemporaryDirectory()
        cls.first_pass = Path(cls.tmpdir.name) / "claude-patched-1"
        cls.second_pass = Path(cls.tmpdir.name) / "claude-patched-2"

    @classmethod
    def tearDownClass(cls):
        cls.tmpdir.cleanup()

    def test_version_preserved_after_patching(self):
        summary = run_patcher(self.src, self.first_pass)
        self.assertEqual(
            [], [r.name for r in summary.missed],
            "every discovered patch must apply against the real binary; "
            "a miss means an anchor has drifted from the current build",
        )
        self.assertEqual(len(summary.applied), len(PATCHES))
        self.assertEqual(_version_of(self.src), _version_of(self.first_pass))

    def test_repatching_own_output_is_byte_stable(self):
        # Depends on test_version_preserved_after_patching having run first
        # to produce first_pass; re-derive it here too so this test is
        # independently runnable.
        run_patcher(self.src, self.first_pass)
        run_patcher(self.first_pass, self.second_pass)
        self.assertEqual(
            self.first_pass.stat().st_size, self.second_pass.stat().st_size,
        )
        self.assertEqual(
            self.first_pass.read_bytes(), self.second_pass.read_bytes(),
            "re-patching an already-patched binary must be a byte-stable no-op",
        )


if __name__ == "__main__":
    unittest.main()
