# SPDX-License-Identifier: Apache-2.0
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRATCH = ROOT / "bin" / "agent-scratch"
LABEL = "io.agent-policy.scratch"


class Scratch(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.home = self.tmp / "home"
        self.project = self.tmp / "project"
        self.state = self.tmp / "state"
        for path in (
            self.home,
            self.project,
            self.state / "list",
            self.state / "container",
            self.state / "network",
            self.state / "volume",
        ):
            path.mkdir(parents=True)
        self.log = self.tmp / "calls.log"
        self.env = dict(
            os.environ,
            HOME=str(self.home),
            STUB_LOG=str(self.log),
            STUB_STATE=str(self.state),
            PATH=f"{ROOT / 'tests' / 'stubs'}{os.pathsep}{os.environ['PATH']}",
        )

    def tearDown(self):
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def scratch(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRATCH), *args],
            cwd=self.project,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def engine_calls(self):
        return [c for c in self.calls() if "inspect" not in c[:2]]

    def own(self, kind, name, slug):
        (self.state / kind / f"{name}.json").write_text(
            json.dumps([{"Config": {"Labels": {LABEL: slug}}, "Labels": {LABEL: slug}}])
        )

    def test_run_names_and_labels(self):
        proc = self.scratch(
            "run",
            "demo",
            "--rm",
            "--name",
            "web",
            "-v",
            "./data:/d:Z",
            "debian:13-slim",
            "true",
        )
        self.assertEqual(0, proc.returncode, proc.stderr)
        call = self.engine_calls()[-1]
        self.assertEqual("run", call[0])
        self.assertIn(f"--label={LABEL}=demo", call)
        self.assertIn("--name=as-demo-web", call)

    def test_run_without_name_gets_one(self):
        self.assertEqual(0, self.scratch("run", "demo", "debian:13-slim").returncode)
        self.assertTrue(any(a.startswith("--name=as-demo-") for a in self.engine_calls()[-1]))

    def test_run_refuses_outside_mounts(self):
        for mount in (
            "~/.ssh:/s",
            "/etc:/e",
            f"{self.tmp}/elsewhere:/x",
            "other-volume:/v",
        ):
            with self.subTest(mount=mount):
                proc = self.scratch("run", "demo", "-v", mount, "debian:13-slim")
                self.assertEqual(2, proc.returncode)
        self.assertEqual([], self.engine_calls())

    def test_run_allows_scratch_dir_and_volume(self):
        scratch_dir = self.home / "scratch" / "as-demo"
        proc = self.scratch(
            "run",
            "demo",
            "-v",
            f"{scratch_dir}:/s",
            "-v",
            "as-demo-cache:/c",
            "debian:13-slim",
        )
        self.assertEqual(0, proc.returncode, proc.stderr)

    def test_run_refuses_wider_access(self):
        for flags in (
            ["--privileged"],
            ["--network", "host"],
            ["--network=other-net"],
            ["--cap-add", "SYS_ADMIN"],
            ["--pod", "p"],
        ):
            with self.subTest(flags=flags):
                self.assertEqual(
                    2, self.scratch("run", "demo", *flags, "debian:13-slim").returncode
                )
        self.assertEqual(
            0,
            self.scratch("run", "demo", "--network", "as-demo-net", "debian:13-slim").returncode,
        )

    def test_network_and_volume(self):
        self.assertEqual(0, self.scratch("network", "demo", "net", "--internal").returncode)
        self.assertEqual(
            ["network", "create", f"--label={LABEL}=demo", "--internal", "as-demo-net"],
            self.engine_calls()[-1],
        )
        self.assertEqual(
            2, self.scratch("network", "demo", "net", "--driver", "macvlan").returncode
        )
        self.assertEqual(0, self.scratch("volume", "demo", "cache").returncode)

    def test_rm_only_what_it_owns(self):
        self.own("container", "as-demo-web", "demo")
        self.own("container", "as-demo-db", "other")
        self.assertEqual(0, self.scratch("rm", "demo", "web").returncode)
        self.assertEqual(["rm", "-f", "as-demo-web"], self.engine_calls()[-1])
        self.assertEqual(2, self.scratch("rm", "demo", "db").returncode)
        self.assertEqual(1, self.scratch("rm", "demo", "missing").returncode)

    def test_exec_only_into_its_own(self):
        self.own("container", "as-demo-web", "demo")
        self.assertEqual(0, self.scratch("exec", "demo", "web", "ls", "/").returncode)
        self.assertEqual(["exec", "as-demo-web", "ls", "/"], self.engine_calls()[-1])
        self.assertEqual(2, self.scratch("exec", "demo", "live", "ls").returncode)

    def test_purge(self):
        (self.state / "list" / "ps").write_text("as-demo-web\n")
        (self.state / "list" / "network").write_text("as-demo-net\n")
        folder = self.home / "scratch" / "as-demo"
        folder.mkdir(parents=True)
        self.assertEqual(0, self.scratch("purge", "demo").returncode)
        calls = self.engine_calls()
        self.assertIn(["rm", "-f", "as-demo-web"], calls)
        self.assertIn(["network", "rm", "as-demo-net"], calls)
        self.assertFalse(folder.exists())

    def test_bad_slug(self):
        for slug in ("Demo", "../x", "", "a" * 41):
            with self.subTest(slug=slug):
                self.assertEqual(2, self.scratch("dir", slug).returncode)


if __name__ == "__main__":
    unittest.main()
