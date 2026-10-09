# SPDX-License-Identifier: Apache-2.0
"""The guard's edges that a command line alone cannot reach."""

import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from agent_policy import containers
from agent_policy.checks import evaluate
from agent_policy.shell import segments


def no_engine(*_args, **_kwargs):
    return None


class WithoutProtectedPaths(unittest.TestCase):
    """With no protected deployment configured, targeted engine commands and
    --all pass straight through."""

    def decide(self, command):
        env = {"HOME": "/home/user", "XDG_CONFIG_HOME": "/nonexistent"}
        finding = evaluate(command, "/work/project", env=env, inspector=no_engine)
        return finding.decision if finding else "none"

    def test_targeted_and_all(self):
        self.assertEqual("none", self.decide("podman stop --all"))
        self.assertEqual("none", self.decide("podman stop web"))


class ReservedWords(unittest.TestCase):
    """A loop or case header runs nothing, so it yields no command; the
    command after a reserved word is yielded on its own."""

    def commands(self, line):
        return [seg.words for seg in segments(line)]

    def test_headers_yield_no_command(self):
        for line in (
            "for cat in a; do :; done",
            "select cat in a; do :; done",
            "case cat in a) :;; esac",
        ):
            with self.subTest(line=line):
                self.assertFalse(any(w and w[0] == "cat" for w in self.commands(line)))
                self.assertFalse(
                    any(w and w[0] in ("for", "select", "case") for w in self.commands(line))
                )

    def test_the_command_after_a_reserved_word(self):
        self.assertIn(["cat", "x"], self.commands("select v in a; do cat x; done"))
        self.assertIn(["cat", "x"], self.commands("function f { cat x; }"))


class EngineInspect(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def engine(self, output, status=0):
        script = self.tmp / "engine"
        script.write_text(f"#!/bin/sh\nprintf '%s' '{output}'\nexit {status}\n")
        script.chmod(0o755)
        return str(script)

    def test_missing_engine(self):
        self.assertIsNone(containers.inspect(str(self.tmp / "absent"), "container", "x"))

    def test_failing_engine(self):
        self.assertIsNone(containers.inspect(self.engine("", status=125), "container", "x"))

    def test_output_that_is_not_json(self):
        self.assertIsNone(containers.inspect(self.engine("not json"), "container", "x"))

    def test_a_single_object_and_an_empty_list(self):
        self.assertEqual({"Id": "a"}, containers.inspect(self.engine('{"Id": "a"}'), "c", "x"))
        self.assertIsNone(containers.inspect(self.engine("[]"), "container", "x"))

    def test_labels_and_protection_of_nothing(self):
        self.assertEqual({}, containers.labels_of(None))
        self.assertIsNone(containers.container_protected(None, ["/live"]))
        self.assertIsNone(containers.container_protected({"Mounts": []}, []))

    def test_protected_paths_file(self):
        config = self.tmp / "agent-policy"
        config.mkdir()
        (config / "protected-paths").write_text("# a comment\n\n~/live\n/srv/other\n")
        env = {"HOME": "/home/user", "XDG_CONFIG_HOME": str(self.tmp)}
        self.assertEqual(["/home/user/live", "/srv/other"], containers.protected_paths(env))


class HookPayloads(unittest.TestCase):
    def run_hook(self, payload):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "hooks" / "guard"), "--agent", "claude"],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            check=True,
            env=dict(os.environ, HOME="/home/user"),
        )
        return json.loads(proc.stdout)["hookSpecificOutput"] if proc.stdout else None

    def test_a_command_given_as_a_list(self):
        out = self.run_hook({"tool_input": {"command": ["cat", "/home/user/.ssh/id_rsa"]}})
        self.assertEqual("deny", out["permissionDecision"])

    def test_runs_from_the_installed_layout(self):
        # make install puts lib/ next to the guard, not one level up.
        with tempfile.TemporaryDirectory() as prefix:
            shutil.copy(ROOT / "hooks" / "guard", prefix)
            shutil.copytree(ROOT / "lib", Path(prefix) / "lib")
            proc = subprocess.run(
                [sys.executable, str(Path(prefix) / "guard")],
                input=json.dumps({"tool_input": {"command": "cat ~/.ssh/id_rsa"}}),
                capture_output=True,
                text=True,
                check=True,
                env=dict(os.environ, HOME="/home/user"),
            )
        self.assertEqual(
            "deny", json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"]
        )

    def test_agent_scratch_runs_from_the_installed_layout(self):
        # make install puts lib/ next to agent-scratch in libexec, and runs
        # it through a symlink in bin/.
        with tempfile.TemporaryDirectory() as prefix:
            libexec, bin_dir = Path(prefix) / "libexec", Path(prefix) / "bin"
            libexec.mkdir()
            bin_dir.mkdir()
            shutil.copy(ROOT / "bin" / "agent-scratch", libexec)
            shutil.copytree(ROOT / "lib", libexec / "lib")
            (bin_dir / "agent-scratch").symlink_to(libexec / "agent-scratch")
            proc = subprocess.run(
                [sys.executable, str(bin_dir / "agent-scratch"), "--help"],
                capture_output=True,
                text=True,
                check=True,
            )
        self.assertIn("agent-scratch dir", proc.stdout)

    def test_importing_the_scripts_runs_nothing(self):
        for name, path in (
            ("guard", ROOT / "hooks" / "guard"),
            ("scratch", ROOT / "bin" / "agent-scratch"),
        ):
            with self.subTest(script=name):
                loader = importlib.machinery.SourceFileLoader(f"script_{name}", str(path))
                spec = importlib.util.spec_from_file_location(loader.name, path, loader=loader)
                module = importlib.util.module_from_spec(spec)
                loader.exec_module(module)
                self.assertTrue(callable(module.main))

    def test_an_allow_file_it_cannot_use_approves_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            allow = Path(tmp) / "guard-allow.json"
            for name, content in (
                ("missing", None),
                ("not json", "{"),
                ("not an object", "[]"),
                ("no list", '{"prefixes": "git status"}'),
                ("bad entries", '{"prefixes": [[], "git", [1], ["git", 2]]}'),
            ):
                with self.subTest(allow=name):
                    allow.unlink(missing_ok=True)
                    if content is not None:
                        allow.write_text(content)
                    proc = subprocess.run(
                        [sys.executable, str(ROOT / "hooks" / "guard"), "--allow", str(allow)],
                        input=json.dumps({"tool_input": {"command": "git -C /x status"}}),
                        capture_output=True,
                        text=True,
                        check=True,
                        env=dict(os.environ, HOME="/home/user"),
                    )
                    self.assertEqual("", proc.stdout)

    def test_no_command_is_no_opinion(self):
        self.assertIsNone(self.run_hook({"tool_input": {}}))
        self.assertIsNone(self.run_hook({"tool_input": {"command": "   "}}))


if __name__ == "__main__":
    unittest.main()
