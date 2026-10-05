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

    def test_run_refuses_other_volumes_in_any_spelling(self):
        for args in (
            ["--mount", "type=volume,src=live-db,dst=/d"],
            ["-v=live-db:/d"],
            ["-vlive-db:/d"],
            ["-v=/etc:/e"],
        ):
            with self.subTest(args=args):
                self.assertEqual(2, self.scratch("run", "demo", *args, "debian:13-slim").returncode)
        self.assertEqual([], self.engine_calls())

    def test_run_checks_the_label_of_an_existing_volume(self):
        self.own("volume", "as-demo-data", "other")
        proc = self.scratch("run", "demo", "-v", "as-demo-data:/d", "debian:13-slim")
        self.assertEqual(2, proc.returncode)
        self.assertIn("not labelled", proc.stderr)
        self.assertEqual([], self.engine_calls())

    def test_run_creates_a_missing_volume_with_the_label(self):
        proc = self.scratch("run", "demo", "-v", "as-demo-new:/d", "debian:13-slim")
        self.assertEqual(0, proc.returncode, proc.stderr)
        calls = self.engine_calls()
        self.assertEqual(["volume", "create", f"--label={LABEL}=demo", "as-demo-new"], calls[0])
        self.assertEqual("run", calls[1][0])

    def test_run_checks_the_label_of_a_network(self):
        self.own("network", "as-demo-other", "other")
        for net, why in (("as-demo-other", "not labelled"), ("as-demo-missing", "does not exist")):
            with self.subTest(net=net):
                proc = self.scratch("run", "demo", "--network", net, "debian:13-slim")
                self.assertEqual(2, proc.returncode)
                self.assertIn(why, proc.stderr)
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
        self.own("network", "as-demo-net", "demo")
        self.assertEqual(
            0, self.scratch("run", "demo", "--network", "as-demo-net", "debian:13-slim").returncode
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


class ScratchCommands(Scratch):
    """The verbs and refusals the main tests do not reach."""

    def test_help_and_no_arguments(self):
        self.assertEqual(0, self.scratch("--help").returncode)
        self.assertEqual(2, self.scratch().returncode)

    def test_dir_creates_and_prints_the_folder(self):
        proc = self.scratch("dir", "demo")
        folder = self.home / "scratch" / "as-demo"
        self.assertEqual(0, proc.returncode)
        self.assertEqual(str(folder), proc.stdout.strip())
        self.assertTrue(folder.is_dir())

    def test_ls_with_and_without_a_slug(self):
        (self.state / "list" / "ps").write_text("as-demo-web\n")
        (self.home / "scratch" / "as-demo").mkdir(parents=True)
        (self.home / "scratch" / "unrelated").mkdir()
        everything = self.scratch("ls")
        self.assertEqual(0, everything.returncode)
        self.assertIn("folders: as-demo", everything.stdout)
        self.assertIn("as-demo-web", self.scratch("ls", "demo").stdout)

    def test_ls_without_a_scratch_folder(self):
        proc = self.scratch("ls", "demo")
        self.assertEqual(0, proc.returncode)
        self.assertNotIn("folders:", proc.stdout)

    def test_unknown_or_incomplete_verbs(self):
        for args in (("launch", "demo"), ("exec", "demo", "web"), ("volume", "demo")):
            with self.subTest(args=args):
                self.assertEqual(2, self.scratch(*args).returncode)

    def test_an_invalid_name_is_refused(self):
        self.assertEqual(2, self.scratch("rm", "demo", "bad name").returncode)

    def test_default_networks_need_no_label(self):
        proc = self.scratch("run", "demo", "--network", "none", "debian:13-slim")
        self.assertEqual(0, proc.returncode, proc.stderr)

    def test_rm_a_network_it_owns(self):
        self.own("network", "as-demo-net", "demo")
        self.assertEqual(0, self.scratch("rm", "demo", "net").returncode)
        self.assertEqual(["network", "rm", "as-demo-net"], self.engine_calls()[-1])

    def test_an_existing_volume_with_the_label_is_used_as_is(self):
        self.own("volume", "as-demo-data", "demo")
        proc = self.scratch("run", "demo", "-v", "as-demo-data:/d", "debian:13-slim")
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertNotIn("create", [c[1] for c in self.engine_calls() if len(c) > 1])

    def test_a_volume_that_cannot_be_created(self):
        self.env["STUB_FAIL"] = "volume create"
        proc = self.scratch("run", "demo", "-v", "as-demo-new:/d", "debian:13-slim")
        self.assertEqual(2, proc.returncode)
        self.assertIn("could not create", proc.stderr)

    def test_purge_removes_volumes_and_tolerates_a_missing_folder(self):
        (self.state / "list" / "volume").write_text("as-demo-data\n")
        self.assertEqual(0, self.scratch("purge", "demo").returncode)
        self.assertIn(["volume", "rm", "as-demo-data"], self.engine_calls())

    def test_the_project_is_the_git_top_level(self):
        subprocess.run(["git", "init", "-q", str(self.project)], check=True)
        (self.project / "sub").mkdir()
        proc = subprocess.run(
            [sys.executable, str(SCRATCH), "run", "demo", "-v", f"{self.project}:/p", "img"],
            cwd=self.project / "sub",
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, proc.returncode, proc.stderr)

    def test_without_git_the_project_is_the_working_folder(self):
        self.env["PATH"] = str(ROOT / "tests" / "stubs")
        proc = self.scratch("run", "demo", "-v", f"{self.project}:/p", "img")
        self.assertEqual(0, proc.returncode, proc.stderr)


if __name__ == "__main__":
    unittest.main()
