# SPDX-License-Identifier: Apache-2.0
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import backup


def snapshot(root):
    """{relative path: (kind, content or target, mode)} for a whole tree."""
    out = {}
    root = Path(root)
    if not os.path.lexists(root):
        return None
    for path in backup.walk(root):
        rel = str(path.relative_to(root))
        info = os.lstat(path)
        if path.is_symlink():
            out[rel] = ("link", os.readlink(path), None)
        elif path.is_dir():
            out[rel] = ("dir", None, info.st_mode & 0o7777)
        else:
            out[rel] = ("file", path.read_bytes(), info.st_mode & 0o7777)
    return out


class Backup(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        # A stand-in for /etc/claude-code, ~/.codex/rules and the scratch link.
        self.policy = self.tmp / "etc" / "claude-code"
        (self.policy / "managed-settings.d").mkdir(parents=True)
        (self.policy / "managed-settings.json").write_text('{"keep": true}\n')
        (self.policy / "managed-settings.d" / "10-other.json").write_text("{}\n")
        os.chmod(self.policy / "managed-settings.json", 0o640)
        self.rules = self.tmp / "home" / ".codex" / "rules"
        self.rules.mkdir(parents=True)
        (self.rules / "default.rules").write_text("prefix_rule(pattern=['ls'])\n")
        self.link = self.tmp / "bin" / "agent-scratch"
        self.link.parent.mkdir()
        self.link.symlink_to("/opt/old/agent-scratch")
        self.absent = self.tmp / "etc" / "codex"
        self.paths = [self.policy, self.rules, self.link, self.absent]
        self.dest = self.tmp / "backups" / "one"

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def state(self):
        return [snapshot(p) for p in self.paths]

    def install_something(self):
        """What an install does: add, overwrite, replace, create."""
        (self.policy / "managed-settings.d" / "50-agent-policy.json").write_text('{"new": 1}\n')
        (self.policy / "managed-settings.json").write_text('{"overwritten": true}\n')
        (self.rules / "agent-policy.rules").write_text("prefix_rule(pattern=['git'])\n")
        (self.rules / "default.rules").unlink()
        self.link.unlink()
        self.link.symlink_to("/usr/local/libexec/agent-policy/agent-scratch")
        self.absent.mkdir(parents=True)
        (self.absent / "requirements.toml").write_text("[features]\nhooks = true\n")

    def test_restore_puts_everything_back(self):
        before = self.state()
        backup.create(self.dest, self.paths)
        self.install_something()
        self.assertNotEqual(before, self.state())
        backup.restore(self.dest, log=lambda *_: None)
        self.assertEqual(before, self.state())

    def test_restore_is_idempotent(self):
        backup.create(self.dest, self.paths)
        self.install_something()
        backup.restore(self.dest, log=lambda *_: None)
        self.assertEqual([], backup.restore(self.dest, log=lambda *_: None))

    def test_dry_run_changes_nothing(self):
        backup.create(self.dest, self.paths)
        self.install_something()
        after_install = self.state()
        actions = backup.restore(self.dest, dry_run=True, log=lambda *_: None)
        self.assertTrue(actions)
        self.assertEqual(after_install, self.state())

    def test_manifest_records_every_entry(self):
        manifest = backup.create(self.dest, self.paths)
        kinds = {Path(e["path"]).name: e["type"] for e in manifest["entries"]}
        self.assertEqual("file", kinds["managed-settings.json"])
        self.assertEqual("symlink", kinds["agent-scratch"])
        self.assertEqual("absent", kinds["codex"])
        self.assertEqual(0o700, os.stat(self.dest).st_mode & 0o777)

    def test_backup_never_writes_to_the_paths_it_saves(self):
        before = self.state()
        backup.create(self.dest, self.paths)
        self.assertEqual(before, self.state())

    def test_an_unreadable_file_fails_without_a_manifest(self):
        if os.geteuid() == 0:
            self.skipTest("root reads everything")
        secret = self.policy / "managed-settings.d" / "20-locked.json"
        secret.write_text("{}\n")
        os.chmod(secret, 0)
        with self.assertRaises(OSError):
            backup.create(self.dest, self.paths)
        self.assertFalse((self.dest / backup.MANIFEST).exists())
        with self.assertRaises(backup.BackupError):
            backup.restore(self.dest, log=lambda *_: None)
        os.chmod(secret, 0o600)

    def test_refuses_a_non_empty_destination(self):
        self.dest.mkdir(parents=True)
        (self.dest / "x").write_text("")
        with self.assertRaises(backup.BackupError):
            backup.create(self.dest, self.paths)

    def test_cli_create_list_restore(self):
        root = self.tmp / "backups"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(0, backup.main(["create", "--root", str(root), *map(str, self.paths)]))
            self.assertEqual(0, backup.main(["list", str(root)]))
        made = [p for p in root.iterdir() if (p / backup.MANIFEST).exists()]
        self.assertEqual(1, len(made))
        self.assertIn(str(made[0]), out.getvalue())
        manifest = json.loads((made[0] / backup.MANIFEST).read_text())
        self.assertEqual([str(p) for p in self.paths], manifest["roots"])
        self.install_something()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, backup.main(["restore", str(made[0])]))
        self.assertIsNone(snapshot(self.absent))

    def test_cli_reports_failure(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(1, backup.main(["restore", str(self.tmp / "nothing")]))


if __name__ == "__main__":
    unittest.main()
