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
        self.link.symlink_to(self.policy / "managed-settings.json")
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
        backup.restore(self.dest, self.paths, log=lambda *_: None)
        self.assertEqual(before, self.state())

    def test_restore_is_idempotent(self):
        backup.create(self.dest, self.paths)
        self.install_something()
        backup.restore(self.dest, self.paths, log=lambda *_: None)
        self.assertEqual([], backup.restore(self.dest, self.paths, log=lambda *_: None))

    def test_dry_run_changes_nothing(self):
        backup.create(self.dest, self.paths)
        self.install_something()
        after_install = self.state()
        actions = backup.restore(self.dest, self.paths, dry_run=True, log=lambda *_: None)
        self.assertTrue(actions)
        self.assertEqual(after_install, self.state())

    def test_manifest_records_every_entry(self):
        manifest = backup.create(self.dest, self.paths)
        kinds = {Path(e["path"]).name: e["type"] for e in manifest["entries"]}
        self.assertEqual("file", kinds["managed-settings.json"])
        self.assertEqual("symlink", kinds["agent-scratch"])
        self.assertEqual("absent", kinds["codex"])
        self.assertEqual(0o700, os.stat(self.dest).st_mode & 0o777)

    def test_copies_and_manifest_are_owner_only(self):
        backup.create(self.dest, self.paths)
        self.assertEqual(0o600, os.stat(self.dest / backup.MANIFEST).st_mode & 0o777)
        copy = backup.stored(self.dest, self.policy / "managed-settings.json")
        self.assertEqual(0o600, os.stat(copy).st_mode & 0o777)

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
            backup.restore(self.dest, self.paths, log=lambda *_: None)
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
            allow = [arg for p in self.paths for arg in ("--allow", str(p))]
            self.assertEqual(
                0, backup.main(["restore", "--backup-root", str(root), *allow, str(made[0])])
            )
        self.assertIsNone(snapshot(self.absent))

    def tamper(self, change):
        backup.create(self.dest, self.paths)
        path = self.dest / backup.MANIFEST
        manifest = json.loads(path.read_text())
        change(manifest)
        path.write_text(json.dumps(manifest))

    def assert_refused(self):
        with self.assertRaises(backup.BackupError):
            backup.restore(self.dest, self.paths, log=lambda *_: None)

    def test_refuses_a_root_that_was_not_allowed(self):
        victim = self.tmp / "victim"
        victim.write_text("keep\n")

        def change(m):
            m["roots"].append(str(victim))
            m["entries"].append({"path": str(victim), "type": "absent"})

        self.tamper(change)
        self.assert_refused()
        self.assertEqual("keep\n", victim.read_text())

    def test_refuses_an_entry_outside_its_root(self):
        victim = self.tmp / "victim"
        victim.write_text("keep\n")

        def change(m):
            entry = next(e for e in m["entries"] if e["type"] == "file")
            entry["path"] = str(self.policy / ".." / ".." / "victim")

        self.tamper(change)
        self.assert_refused()
        self.assertEqual("keep\n", victim.read_text())

    def test_refuses_a_path_reached_through_a_symlink(self):
        outside = self.tmp / "outside"
        outside.mkdir()
        backup.create(self.dest, self.paths)
        # After the backup, a folder inside a root becomes a link out of it.
        shutil.rmtree(self.policy / "managed-settings.d")
        (self.policy / "managed-settings.d").symlink_to(outside)
        backup.restore(self.dest, self.paths, log=lambda *_: None)
        self.assertFalse((self.policy / "managed-settings.d").is_symlink())
        self.assertEqual([], list(outside.iterdir()))
        self.assertTrue((self.policy / "managed-settings.d" / "10-other.json").is_file())

    def test_refuses_a_backup_outside_the_backup_root(self):
        backup.create(self.dest, self.paths)
        with self.assertRaises(backup.BackupError):
            backup.restore(
                self.dest, self.paths, log=lambda *_: None, backup_root=self.tmp / "elsewhere"
            )

    def test_cli_refuses_paths_outside_the_fixed_bases(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(1, backup.main(["create", "--dest", "/var/x", str(self.policy)]))
            self.assertEqual(
                1, backup.main(["create", "--root", str(self.tmp / "b"), "/opt/thing"])
            )
            self.assertEqual(1, backup.main(["restore", "--allow", "/opt/thing", str(self.dest)]))

    def test_refuses_a_stored_copy_that_is_a_symlink(self):
        secret = self.tmp / "root-only"
        secret.write_text("secret\n")
        backup.create(self.dest, self.paths)
        copy = backup.stored(self.dest, self.policy / "managed-settings.json")
        copy.unlink()
        copy.symlink_to(secret)
        (self.policy / "managed-settings.json").write_text("changed\n")
        with self.assertRaises((backup.BackupError, OSError)):
            backup.restore(self.dest, self.paths, log=lambda *_: None)
        self.assertEqual("changed\n", (self.policy / "managed-settings.json").read_text())

    def test_refuses_a_stored_copy_that_does_not_match(self):
        backup.create(self.dest, self.paths)
        backup.stored(self.dest, self.policy / "managed-settings.json").write_text("evil\n")
        (self.policy / "managed-settings.json").write_text("changed\n")
        with self.assertRaises(backup.BackupError):
            backup.restore(self.dest, self.paths, log=lambda *_: None)

    def test_special_mode_bits_are_never_restored(self):
        def change(m):
            entry = next(e for e in m["entries"] if e["path"].endswith("managed-settings.json"))
            entry["mode"] = 0o6755

        self.tamper(change)
        (self.policy / "managed-settings.json").write_text("changed\n")
        backup.restore(self.dest, self.paths, log=lambda *_: None)
        mode = os.stat(self.policy / "managed-settings.json").st_mode & 0o7777
        self.assertEqual(0o755, mode)

    def test_restore_is_idempotent_for_special_mode_bits(self):
        special = self.policy / "managed-settings.d" / "30-setgid.json"
        special.write_text("{}\n")
        os.chmod(special, 0o2755)
        backup.create(self.dest, self.paths)
        special.write_text("changed\n")
        backup.restore(self.dest, self.paths, log=lambda *_: None)
        self.assertEqual([], backup.restore(self.dest, self.paths, log=lambda *_: None))

    def test_a_symlink_in_a_parent_folder_stops_the_restore(self):
        backup.create(self.dest, self.paths)
        (self.rules / "default.rules").write_text("changed\n")
        # Swap the folder above a root for a link to somewhere else that has
        # the same layout: a path-based write would follow it.
        outside = self.tmp / "outside"
        (outside / "rules").mkdir(parents=True)
        codex = self.rules.parent
        shutil.move(str(codex), str(self.tmp / "codex-moved"))
        codex.symlink_to(outside)
        with self.assertRaises((backup.BackupError, OSError)):
            backup.restore(self.dest, self.paths, log=lambda *_: None)
        self.assertEqual([], list((outside / "rules").iterdir()))

    def test_a_parent_swapped_after_the_check_is_not_followed(self):
        backup.create(self.dest, self.paths)
        target = self.rules / "default.rules"
        target.write_text("changed\n")
        entry = next(e for e in backup.load(self.dest)["entries"] if e["path"] == str(target))
        data = backup.read_copy(self.dest, str(target), entry)
        # The race: the path passed every check, then a parent becomes a link.
        outside = self.tmp / "outside"
        (outside / "rules").mkdir(parents=True)
        codex = self.rules.parent
        shutil.move(str(codex), str(self.tmp / "codex-moved"))
        codex.symlink_to(outside)
        with self.assertRaises(OSError):
            backup.restore_at(str(target), entry, data, as_root=False)
        self.assertEqual([], list((outside / "rules").iterdir()))

    def test_refuses_a_link_pointing_outside_the_allowed_paths(self):
        mine = self.tmp / "users-own-policy.json"
        mine.write_text('{"permissions": {"allow": ["Bash(*)"]}}\n')

        def change(m):
            m["entries"].append(
                {
                    "path": str(self.policy / "managed-settings.d" / "99-planted.json"),
                    "type": "symlink",
                    "target": str(mine),
                    "mode": 0o777,
                    "uid": 0,
                    "gid": 0,
                }
            )

        self.tamper(change)
        self.assert_refused()
        self.assertFalse(os.path.lexists(self.policy / "managed-settings.d" / "99-planted.json"))

    def test_an_original_link_pointing_outside_is_not_restored(self):
        self.link.unlink()
        self.link.symlink_to("/opt/elsewhere/agent-scratch")
        backup.create(self.dest, self.paths)
        self.link.unlink()
        with self.assertRaisesRegex(backup.BackupError, "points outside"):
            backup.restore(self.dest, self.paths, log=lambda *_: None)

    def test_a_link_inside_the_allowed_paths_is_restored(self):
        before = self.state()
        backup.create(self.dest, self.paths)
        self.link.unlink()
        backup.restore(self.dest, self.paths, log=lambda *_: None)
        self.assertEqual(before, self.state())

    def test_a_link_chain_cannot_escape_through_dot_dot(self):
        def change(m):
            deep = self.policy / "deep"
            m["entries"] += [
                {"path": str(deep), "type": "dir", "mode": 0o755, "uid": 0, "gid": 0},
                {
                    "path": str(deep / "a"),
                    "type": "symlink",
                    "target": "..",
                    "mode": 0o777,
                    "uid": 0,
                    "gid": 0,
                },
                {
                    "path": str(deep / "link"),
                    "type": "symlink",
                    "target": "a/../../" + str(self.tmp.relative_to("/")) + "/payload",
                    "mode": 0o777,
                    "uid": 0,
                    "gid": 0,
                },
            ]

        self.tamper(change)
        try:
            backup.restore(self.dest, self.paths, log=lambda *_: None)
        except backup.BackupError:
            return  # refused outright: fine
        # Restored, then only as the checked absolute path inside the root.
        for name in ("a", "link"):
            target = os.readlink(self.policy / "deep" / name)
            self.assertTrue(os.path.isabs(target), target)
            self.assertTrue(Path(target).is_relative_to(self.policy), target)

    def test_an_unchanged_relative_link_is_left_alone(self):
        self.link.unlink()
        self.link.symlink_to(
            os.path.relpath(self.policy / "managed-settings.json", self.link.parent)
        )
        backup.create(self.dest, self.paths)
        actions = backup.restore(self.dest, self.paths, log=lambda *_: None)
        self.assertNotIn(("restore", str(self.link)), actions)

    def test_cli_reports_failure(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                1, backup.main(["restore", "--allow", str(self.policy), str(self.tmp / "nothing")])
            )


if __name__ == "__main__":
    unittest.main()
