"""Tests for fixture repos under fixtures/ (npm lock policy)."""

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_scan_module():
    path = ROOT / "security-scan.py"
    spec = importlib.util.spec_from_file_location("security_scan", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_SCAN = _load_scan_module()


class TestNpmLockFixtures(unittest.TestCase):
    def test_npm_locked_ok_has_no_violations(self):
        d = ROOT / "fixtures" / "npm-locked-ok"
        pkg_v, lock_v = _SCAN.collect_npm_lock_violations(str(d))
        self.assertEqual(pkg_v, [])
        self.assertEqual(lock_v, [])

    def test_npm_ranges_bad_reports_package_json(self):
        d = ROOT / "fixtures" / "npm-ranges-bad"
        pkg_v, lock_v = _SCAN.collect_npm_lock_violations(str(d))
        self.assertGreater(len(pkg_v), 0)
        keys = {p for p, _ in pkg_v}
        self.assertIn("dependencies.caret-dep", keys)
        self.assertIn("devDependencies.tag-dep", keys)
        self.assertIn("overrides.some-pkg..", keys)
        self.assertEqual(lock_v, [])

    def test_npm_lock_bad_version_reports_lock_only(self):
        d = ROOT / "fixtures" / "npm-lock-bad-version"
        pkg_v, lock_v = _SCAN.collect_npm_lock_violations(str(d))
        self.assertEqual(pkg_v, [])
        self.assertEqual(lock_v, [("node_modules/synthetic-bad", "^9.9.9")])

    def test_npm_lock_v1_bad_reports_nested_version(self):
        d = ROOT / "fixtures" / "npm-lock-v1-bad"
        pkg_v, lock_v = _SCAN.collect_npm_lock_violations(str(d))
        self.assertGreaterEqual(len(pkg_v), 0)
        self.assertTrue(any("placeholder" in loc for loc, _ in lock_v))
        self.assertTrue(any(ver.startswith("~") for _, ver in lock_v))


if __name__ == "__main__":
    unittest.main()
