# SPDX-License-Identifier: Apache-2.0
"""tools/install_diff.py, the report behind `make diff`."""

import io
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import install_diff


class InstallDiff(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.src = self.tmp / "src"
        self.inst = self.tmp / "inst"
        for base in (self.src, self.inst):
            (base / "lib" / "__pycache__").mkdir(parents=True)
        (self.src / "a.json").write_text('{"a": 1}\n')
        (self.src / "lib" / "m.py").write_text("x = 1\n")

    def tearDown(self):
        # Undo the chmod 0 some tests apply, so the folder can be removed.
        for path in [self.tmp, *self.tmp.rglob("*")]:
            if path.is_dir():
                path.chmod(0o700)
        shutil.rmtree(self.tmp)

    def run_tool(self, *args):
        out = io.StringIO()
        status = install_diff.main([str(a) for a in args], out=out)
        return status, out.getvalue()

    def pair(self, name):
        return f"{self.inst / name}={self.src / name}"

    def test_new_unchanged_and_changed_files(self):
        (self.inst / "lib" / "m.py").write_text("x = 1\n")
        (self.inst / "lib" / "__pycache__" / "m.pyc").write_bytes(b"ignored")
        status, out = self.run_tool(self.pair("a.json"), self.pair("lib"))
        self.assertEqual(0, status)
        self.assertIn(f"  new        {self.inst / 'a.json'}", out)
        self.assertIn(f"  unchanged  {self.inst / 'lib'}", out)
        self.assertIn("diff: 1 new, 0 changed, 1 unchanged;", out)
        self.assertNotIn("error", out)

        (self.inst / "a.json").write_text('{"a": 0}\n')
        status, out = self.run_tool(self.pair("a.json"))
        self.assertEqual(0, status)
        self.assertIn(f"  changed    {self.inst / 'a.json'}", out)
        self.assertIn('      -{"a": 0}', out)
        self.assertIn('      +{"a": 1}', out)

    def test_folders_report_changed_and_one_sided_files(self):
        (self.inst / "lib" / "m.py").write_text("x = 2\n")
        (self.inst / "lib" / "old.py").write_text("")
        (self.src / "lib" / "new.py").write_text("")
        status, out = self.run_tool(self.pair("lib"))
        self.assertEqual(0, status)
        self.assertIn("changed", out)
        self.assertIn("-x = 2", out)
        self.assertIn(f"only installed: {self.inst / 'lib' / 'old.py'}", out)
        self.assertIn(f"only in the source: {self.src / 'lib' / 'new.py'}", out)

    def test_a_path_that_cannot_be_compared_fails_the_run(self):
        (self.inst / "a.json").mkdir()
        (self.inst / "lib" / "m.py").write_text("x = 1\n")
        (self.inst / "lib" / "m.py").chmod(0)
        status, out = self.run_tool(self.pair("a.json"), self.pair("lib"))
        self.assertEqual(1, status)
        self.assertIn(f"  error      {self.inst / 'a.json'}", out)
        self.assertIn("is a folder, the source is not", out)
        self.assertIn(f"  error      {self.inst / 'lib'}", out)
        self.assertIn("2 error", out)

    def test_an_unreadable_folder_fails_the_run(self):
        (self.inst / "lib").chmod(0)
        status, out = self.run_tool(self.pair("lib"))
        self.assertEqual(1, status)
        self.assertIn("error", out)

    def test_a_path_behind_an_unreadable_folder_is_an_error_not_new(self):
        hidden = self.tmp / "hidden"
        (hidden / "lib").mkdir(parents=True)
        hidden.chmod(0)
        status, out = self.run_tool(
            f"{hidden / 'lib'}={self.src / 'lib'}", f"--link={hidden / 'link'}=x"
        )
        self.assertEqual(1, status)
        self.assertIn(f"  error      {hidden / 'lib'}", out)
        self.assertIn(f"  error      {hidden / 'link'}", out)
        self.assertNotIn("  new ", out)

    def test_the_link_install_creates(self):
        target = self.src / "a.json"
        link = self.inst / "link"
        status, out = self.run_tool(f"--link={link}={target}")
        self.assertIn(f"  new        {link}", out)
        link.symlink_to(target)
        status, out = self.run_tool(f"--link={link}={target}")
        self.assertIn(f"  unchanged  {link}", out)
        status, out = self.run_tool(f"--link={link}={self.src / 'other'}")
        self.assertIn(f"  changed    {link}", out)
        self.assertIn(f"points to {target}, install links {self.src / 'other'}", out)
        plain = self.inst / "plain"
        plain.write_text("")
        status, out = self.run_tool(f"--link={plain}={target}")
        self.assertEqual(1, status)
        self.assertIn("is not a symbolic link", out)

    def test_a_malformed_pair_is_rejected(self):
        with self.assertRaises(SystemExit):
            self.run_tool("no-equals-sign")

    def test_runs_as_a_script(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "install_diff.py"), self.pair("a.json")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, proc.returncode)
        self.assertIn("1 new", proc.stdout)


if __name__ == "__main__":
    unittest.main()
