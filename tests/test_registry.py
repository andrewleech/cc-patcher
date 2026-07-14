"""Unit tests for entry-point discovery and cache-key derivation.

Uses fake `importlib.metadata.EntryPoint`-shaped objects (monkeypatched
in place of the real `entry_points()` call) so discovery order and the
provider-set-sensitive cache key are covered without needing real
packages installed in the test environment.
"""

import unittest
from unittest import mock

from cc_patcher import launch as launch_mod
from cc_patcher import patches as patches_mod


class FakeEntryPoint:
    def __init__(self, name: str, patch_list: list):
        self.name = name
        self._patch_list = patch_list

    def load(self):
        return self._patch_list


class FakePatch:
    def __init__(self, name: str, key: str):
        self.name = name
        self._key = key

    def cache_key(self) -> str:
        return self._key


class DiscoveryOrderTests(unittest.TestCase):
    def test_entry_points_sorted_by_name(self):
        eps = [
            FakeEntryPoint("channels", [FakePatch("c1", "c1")]),
            FakeEntryPoint("model-alias", [FakePatch("m1", "m1")]),
        ]
        with mock.patch(
            "importlib.metadata.entry_points",
            return_value=list(reversed(eps)),
        ):
            found = patches_mod.discover_entry_points()
        self.assertEqual([ep.name for ep in found], ["channels", "model-alias"])

    def test_discover_patches_concatenates_in_entry_point_order(self):
        eps = [
            FakeEntryPoint("channels", [FakePatch("c1", "k1"), FakePatch("c2", "k2")]),
            FakeEntryPoint("model-alias", [FakePatch("m1", "k3")]),
        ]
        with mock.patch(
            "importlib.metadata.entry_points",
            return_value=list(reversed(eps)),
        ):
            found = patches_mod.discover_patches()
        self.assertEqual([p.name for p in found], ["c1", "c2", "m1"])

    def test_no_providers_yields_empty_registry(self):
        with mock.patch("importlib.metadata.entry_points", return_value=[]):
            found = patches_mod.discover_patches()
        self.assertEqual(found, [])


class CacheKeyTests(unittest.TestCase):
    def _registry_key_for(self, patch_list):
        with mock.patch.object(launch_mod, "PATCHES", patch_list):
            return launch_mod.registry_cache_key()

    def test_cache_key_stable_for_same_registry(self):
        patches = [FakePatch("a", "key-a"), FakePatch("b", "key-b")]
        self.assertEqual(
            self._registry_key_for(patches), self._registry_key_for(patches),
        )

    def test_cache_key_changes_when_provider_set_changes(self):
        one_provider = [FakePatch("a", "key-a")]
        two_providers = [FakePatch("a", "key-a"), FakePatch("b", "key-b")]
        self.assertNotEqual(
            self._registry_key_for(one_provider),
            self._registry_key_for(two_providers),
        )

    def test_cache_key_changes_when_a_provider_is_swapped(self):
        with_channels = [FakePatch("a", "key-a"), FakePatch("channels", "chan-v1")]
        with_different_channels = [
            FakePatch("a", "key-a"), FakePatch("channels", "chan-v2"),
        ]
        self.assertNotEqual(
            self._registry_key_for(with_channels),
            self._registry_key_for(with_different_channels),
        )

    def test_empty_registry_has_a_stable_key(self):
        self.assertEqual(self._registry_key_for([]), self._registry_key_for([]))


if __name__ == "__main__":
    unittest.main()
