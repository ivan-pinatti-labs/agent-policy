# SPDX-License-Identifier: Apache-2.0
"""Refusals and rare paths of the backup tool, the renderer and harvest."""

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import backup
import harvest
import render


class BackupEdges(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.root = self.tmp / "etc" / "claude-code"
        (self.root / "managed-settings.d").mkdir(parents=True)
        (self.root / "managed-settings.d" / "10-a.json").write_text("{}\n")
        (self.root / "link").symlink_to(self.root / "managed-settings.d" / "10-a.json")
        self.dest = self.tmp / "backups" / "one"
        self.quiet = {"log": lambda *_: None}

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_inside_and_stored_refuse_escapes(self):
        with self.assertRaises(backup.BackupError):
            backup.inside("/elsewhere/x", [Path("/etc")])
        with self.assertRaises(backup.BackupError):
            backup.stored(self.dest, "/a/../../outside")

    def test_a_special_file_cannot_be_backed_up(self):
        os.mkfifo(self.root / "pipe")
        with self.assertRaises(backup.BackupError):
            backup.create(self.dest, [self.root])

    def test_a_copy_that_changes_under_the_backup_is_refused(self):
        with mock.patch.object(backup, "sha256", side_effect=["aaa", "bbb"]):
            with self.assertRaises(backup.BackupError):
                backup.create(self.dest, [self.root / "managed-settings.d" / "10-a.json"])

    def tamper(self, change):
        backup.create(self.dest, [self.root])
        path = self.dest / backup.MANIFEST
        manifest = json.loads(path.read_text())
        change(manifest)
        path.write_text(json.dumps(manifest))

    def test_an_unknown_format_or_entry_type_is_refused(self):
        self.tamper(lambda m: m.update(format=99))
        with self.assertRaises(backup.BackupError):
            backup.restore(self.dest, [self.root], **self.quiet)
        shutil.rmtree(self.dest)
        self.tamper(lambda m: m["entries"][1].update(type="fifo"))
        with self.assertRaises(backup.BackupError):
            backup.restore(self.dest, [self.root], **self.quiet)

    def test_restore_as_root_rebuilds_a_deleted_tree(self):
        # As root, restore sets each owner from the folder it lands in; here
        # that is the current user, which any user may set.
        backup.create(self.dest, [self.root])
        before = sorted(str(p) for p in backup.walk(self.root))
        shutil.rmtree(self.tmp / "etc")
        backup.restore(self.dest, [self.root], as_root=True, **self.quiet)
        self.assertEqual(before, sorted(str(p) for p in backup.walk(self.root)))
        self.assertTrue((self.root / "link").is_symlink())

    def test_restore_replaces_a_folder_with_the_saved_file(self):
        backup.create(self.dest, [self.root])
        target = self.root / "managed-settings.d" / "10-a.json"
        target.unlink()
        target.mkdir()
        backup.restore(self.dest, [self.root], **self.quiet)
        self.assertTrue(target.is_file())

    def test_restore_fixes_the_mode_of_an_existing_folder(self):
        backup.create(self.dest, [self.root])
        os.chmod(self.root / "managed-settings.d", 0o700)
        backup.restore(self.dest, [self.root], **self.quiet)
        self.assertEqual(0o755, os.stat(self.root / "managed-settings.d").st_mode & 0o777)

    def test_open_dir_does_not_create_unless_asked(self):
        with self.assertRaises(FileNotFoundError):
            backup.open_dir(self.tmp / "missing" / "folder")
        os.close(backup.open_dir(self.tmp / "missing" / "folder", create=True))
        self.assertEqual(0o755, os.stat(self.tmp / "missing" / "folder").st_mode & 0o777)

    def test_restore_at_checks_a_link_target_itself(self):
        entry = {"type": "symlink", "target": "/etc/passwd", "mode": 0o777}
        with self.assertRaises(backup.BackupError):
            backup.restore_at(str(self.root / "evil"), entry, None, False, [self.root])
        self.assertFalse(os.path.lexists(self.root / "evil"))

    def test_a_stored_copy_that_is_a_folder_is_refused(self):
        backup.create(self.dest, [self.root])
        copy = backup.stored(self.dest, self.root / "managed-settings.d" / "10-a.json")
        copy.unlink()
        copy.mkdir()
        (self.root / "managed-settings.d" / "10-a.json").write_text("changed\n")
        with self.assertRaises(backup.BackupError):
            backup.restore(self.dest, [self.root], **self.quiet)

    def test_an_extra_path_already_gone_is_skipped(self):
        backup.create(self.dest, [self.root])
        gone = self.root / "already-gone"
        real_walk = backup.walk

        def walk_with_a_ghost(root):
            yield from real_walk(root)
            yield gone

        with mock.patch.object(backup, "walk", walk_with_a_ghost):
            self.assertEqual([], backup.restore(self.dest, [self.root], **self.quiet))

    def test_list_skips_incomplete_backups_and_a_missing_root(self):
        self.assertEqual([], backup.list_backups(self.tmp / "no-such-root"))
        backup.create(self.dest, [self.root])
        (self.dest.parent / "incomplete").mkdir()
        self.assertEqual([self.dest], [p for p, _ in backup.list_backups(self.dest.parent)])


class RenderEdges(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def assert_invalid(self, rule_toml):
        (self.tmp / "x.toml").write_text("[[rule]]\n" + rule_toml)
        with self.assertRaises(render.PolicyError):
            render.load(self.tmp)

    def test_every_validation_error(self):
        base = 'severity = "low"\nreason = "r"\n'
        cases = [
            base + 'prefix = [["ls"]]\nextra = 1\n',
            'severity = "low"\nreason = ""\nprefix = [["ls"]]\n',
            base + 'agents = ["other"]\nprefix = [["ls"]]\n',
            base + 'agents = ["codex"]\nclaude = ["Bash(ls)"]\n',
            base + "prefix = [[]]\n",
            base + 'prefix = [["has space"]]\n',
            base + 'claude = [""]\n',
            base,
        ]
        for case in cases:
            with self.subTest(case=case):
                self.assert_invalid(case)

    def test_codex_only_rules_are_left_out_for_claude(self):
        rule = {"severity": "low", "agents": ["codex"], "prefix": [["ls"]], "claude": []}
        self.assertEqual([], render.claude_rules([rule])["allow"])

    def test_sandbox_file_missing_or_unknown(self):
        self.assertIsNone(render.load_sandbox(self.tmp))
        (self.tmp / "sandbox.toml").write_text("[sandbox]\nsurprise = true\n")
        with self.assertRaises(render.PolicyError):
            render.load_sandbox(self.tmp)

    def run_main(self, sandbox):
        out = self.tmp / "dist"
        with (
            mock.patch.object(render, "load_sandbox", **sandbox),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            status = render.main(["--out", str(out)])
        return status, out

    def test_main_with_a_broken_missing_or_installed_sandbox(self):
        status, _ = self.run_main({"side_effect": render.PolicyError("bad")})
        self.assertEqual(1, status)
        status, out = self.run_main({"return_value": None})
        self.assertEqual(0, status)
        self.assertFalse((out / "claude" / "sandbox-trial.json").exists())
        status, out = self.run_main({"return_value": {"install": True}})
        built = json.loads((out / "claude" / "50-agent-policy.json").read_text())
        self.assertTrue(built["sandbox"]["enabled"])


class HarvestEdges(unittest.TestCase):
    def test_long_redundant_lists_are_shortened(self):
        with tempfile.TemporaryDirectory() as staging:
            rules = [
                f"Bash(git {sub} *)"
                for sub in ("status", "log", "diff", "show", "blame", "describe")
            ]
            Path(staging, "001-settings.json").write_text(
                json.dumps({"permissions": {"allow": rules}})
            )
            Path(staging, "index.tsv").write_text("001-settings.json\t~/p/.claude/settings.json\n")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(0, harvest.main([staging]))
        self.assertIn("... and 1 more", out.getvalue())


if __name__ == "__main__":
    unittest.main()
