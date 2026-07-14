"""Integration check: with both `claude-net-patcher` and
`cc-local-router` installed in the same environment, the registry
discovers patches from both (skipped when either isn't installed --
e.g. a single-provider dev environment or CI without the sibling
repos)."""

import importlib.util
import unittest

from cc_patcher.patches import discover_entry_points, discover_patches

_HAS_CHANNELS = importlib.util.find_spec("claude_net_patcher") is not None
_HAS_MODEL_ALIAS = importlib.util.find_spec("cc_local_router") is not None


@unittest.skipUnless(
    _HAS_CHANNELS and _HAS_MODEL_ALIAS,
    "both claude-net-patcher and cc-local-router must be installed",
)
class TwoProviderDiscoveryTests(unittest.TestCase):
    def test_both_providers_are_discovered(self):
        eps = discover_entry_points()
        self.assertIn("channels", [ep.name for ep in eps])
        self.assertIn("model-alias", [ep.name for ep in eps])

    def test_patches_from_both_providers_are_present(self):
        import claude_net_patcher
        import cc_local_router

        patches = discover_patches()
        names = {p.name for p in patches}
        self.assertTrue(
            {p.name for p in claude_net_patcher.PATCHES} <= names,
        )
        self.assertTrue(
            {p.name for p in cc_local_router.PATCHES} <= names,
        )
        self.assertEqual(
            len(patches),
            len(claude_net_patcher.PATCHES) + len(cc_local_router.PATCHES),
        )


if __name__ == "__main__":
    unittest.main()
