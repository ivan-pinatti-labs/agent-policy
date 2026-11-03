# SPDX-License-Identifier: Apache-2.0
"""The guard's edges that a command line alone cannot reach."""

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from agent_policy import containers
from agent_policy.checks import evaluate
from agent_policy.shell import ParseError, segments


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

    def test_a_bare_function_is_kept_as_a_command(self):
        self.assertEqual([["function"]], self.commands("function"))


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


def load_guard(name):
    path = ROOT / "hooks" / "guard"
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_file_location(loader.name, path, loader=loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class PermissiveNeedsItsEnvironment(unittest.TestCase):
    """docs/POLICY.md, "Modes": the guard takes permissive only where the
    environment declares it, and otherwise runs hardened and says so."""

    def setUp(self):
        self.guard = load_guard("guard_for_permissive")
        self.tmp = Path(tempfile.mkdtemp())
        self.marker = self.tmp / ".containerenv"
        self.marker.write_text("")
        self.guard.CONTAINER_MARKER = str(self.marker)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def hook(self, command, level="permissive", agent="claude", mode="permissive"):
        env = {"HOME": "/home/user", "XDG_CONFIG_HOME": "/nonexistent"}
        if level is not None:
            env[self.guard.BOUNDARY_LEVEL] = level
        payload = json.dumps({"tool_input": {"command": command}, "cwd": "/work/project"})
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch.object(sys, "stdin", io.StringIO(payload)),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            self.assertEqual(0, self.guard.main(["--agent", agent, "--mode", mode]))
        return (json.loads(out.getvalue()) if out.getvalue() else {}), err.getvalue()

    def decision(self, answer):
        return answer.get("hookSpecificOutput", {}).get("permissionDecision")

    def test_held_where_the_environment_declares_it(self):
        self.assertEqual(
            ("permissive", ""),
            self.guard.held_mode("permissive", "claude", {"AIRLOCK_LEVEL": "permissive"}),
        )
        answer, err = self.hook("cat $f")
        self.assertEqual({}, answer)
        self.assertEqual("", err)

    def test_high_still_asks_and_deny_still_denies(self):
        answer, _ = self.hook("git reset --hard")
        self.assertEqual("ask", self.decision(answer))
        self.assertNotIn("systemMessage", answer)
        answer, _ = self.hook("gh api -X DELETE repos/o/r")
        self.assertEqual("ask", self.decision(answer))
        for command in ("git push --force origin x", "cat ~/.ssh/id_ed25519"):
            with self.subTest(command=command):
                self.assertEqual("deny", self.decision(self.hook(command)[0]))

    def test_refused_without_the_level(self):
        for level in (None, "assisted", "hardened", ""):
            with self.subTest(level=level):
                # A line the guard has no opinion on still carries the notice.
                answer, _ = self.hook("ls", level=level)
                self.assertNotIn("hookSpecificOutput", answer)
                self.assertIn("permissive mode was refused", answer["systemMessage"])
                self.assertIn("AIRLOCK_LEVEL is not permissive", answer["systemMessage"])
                # Hardened: what permissive leaves to the classifier asks.
                for command in ("cat $f", "echo 'unterminated"):
                    answer, _ = self.hook(command, level=level)
                    self.assertEqual("ask", self.decision(answer))
                    self.assertIn("refused", answer["systemMessage"])

    def test_refused_outside_a_container(self):
        # A host has no /run/.containerenv, whatever its environment says.
        self.marker.unlink()
        answer, _ = self.hook("cat $f")
        self.assertIn("not running in a container", answer["systemMessage"])
        answer, _ = self.hook('bash -c "echo \'x"')
        self.assertEqual("ask", self.decision(answer))
        answer, _ = self.hook("git push --force origin x")
        self.assertEqual("deny", self.decision(answer))
        self.assertIn("refused", answer["systemMessage"])

    def test_refused_for_codex(self):
        answer, err = self.hook("cat $f", agent="codex")
        # Codex reads only the decision; its notice goes to standard error.
        self.assertEqual("deny", self.decision(answer))
        self.assertNotIn("systemMessage", answer)
        self.assertIn("not Claude Code", err)

    def test_other_modes_need_nothing(self):
        answer, err = self.hook("cat $f", level=None, mode="unattended")
        self.assertEqual({}, answer)
        self.assertEqual("", err)

    def test_a_refused_session_is_still_approved_and_checked(self):
        allow = self.tmp / "guard-allow.json"
        allow.write_text(json.dumps({"prefixes": [["git", "status"]]}))
        payload = json.dumps({"tool_input": {"command": "git -C /x status"}, "cwd": "/w"})
        out = io.StringIO()
        with (
            mock.patch.dict(os.environ, {"HOME": "/home/user"}, clear=True),
            mock.patch.object(sys, "stdin", io.StringIO(payload)),
            contextlib.redirect_stdout(out),
        ):
            self.guard.main(["--mode", "permissive", "--allow", str(allow)])
        answer = json.loads(out.getvalue())
        self.assertEqual("allow", answer["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("refused", answer["systemMessage"])
        out = io.StringIO()
        with (
            mock.patch.dict(os.environ, {"HOME": "/home/user"}, clear=True),
            mock.patch.object(sys, "stdin", io.StringIO("not json")),
            contextlib.redirect_stdout(out),
        ):
            self.guard.main(["--mode", "permissive"])
        answer = json.loads(out.getvalue())
        self.assertEqual("deny", answer["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("refused", answer["systemMessage"])


class PartialReading(unittest.TestCase):
    """segments(partial=True) skips what it cannot read and keeps the rest."""

    def commands(self, line):
        return [seg.words for seg in segments(line, partial=True)]

    def test_a_nested_script_that_does_not_tokenize_is_skipped(self):
        self.assertEqual([["bash", "-c", "echo 'x"]], self.commands('bash -c "echo \'x"'))

    def test_nesting_is_read_past_the_default_depth_and_then_stops(self):
        self.assertIn(["true"], self.commands("eval " * 6 + "true"))
        self.assertNotIn(["true"], self.commands("eval " * 20 + "true"))

    def test_the_top_level_still_has_to_tokenize(self):
        with self.assertRaises(ParseError):
            self.commands("echo 'x")


if __name__ == "__main__":
    unittest.main()
