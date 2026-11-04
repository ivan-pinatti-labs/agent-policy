# SPDX-License-Identifier: Apache-2.0
"""The ask log (lib/agent_policy/asklog.py), the guard writing it, and the
report that reads it (tools/asks.py)."""

import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tools"))

import asks
import render
from agent_policy import asklog
from agent_policy.checks import evaluate

HOME = "/home/user"
GUARD_ENV = {"HOME": HOME, "XDG_CONFIG_HOME": "/nonexistent", "AGENT_POLICY_PROTECTED": ""}


def rendered():
    return render.guard_allow(render.load(ROOT / "policy"))


class Switch(unittest.TestCase):
    def test_off_unless_asked_for(self):
        self.assertIsNone(asklog.path({"HOME": HOME, "XDG_CONFIG_HOME": "/nonexistent"}))
        self.assertIsNone(asklog.path({"HOME": HOME, asklog.ENABLE_ENV: "0"}))

    def test_on_by_variable_under_the_state_folder(self):
        self.assertEqual(
            f"{HOME}/.local/state/agent-policy/asks.jsonl",
            asklog.path({"HOME": HOME, asklog.ENABLE_ENV: "1"}),
        )
        self.assertEqual(
            "/state/agent-policy/asks.jsonl",
            asklog.path({"HOME": HOME, asklog.ENABLE_ENV: "Yes", "XDG_STATE_HOME": "/state"}),
        )

    def test_on_by_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "agent-policy").mkdir()
            (Path(tmp) / "agent-policy" / "ask-log").write_text("")
            self.assertEqual(
                f"{HOME}/.local/state/agent-policy/asks.jsonl",
                asklog.path({"HOME": HOME, "XDG_CONFIG_HOME": tmp}),
            )
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".config" / "agent-policy").mkdir(parents=True)
            (Path(home) / ".config" / "agent-policy" / "ask-log").write_text("")
            self.assertIsNotNone(asklog.path({"HOME": home}))

    def test_the_process_environment_by_default(self):
        self.assertEqual(asklog.path(dict(os.environ)), asklog.path())


class Classify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = rendered()
        cls.prefixes = data["prefixes"]
        cls.static = asklog.static_rules(data)

    def classify(self, command):
        return asklog.classify(command, "/work/project", HOME, self.prefixes, self.static)

    def test_a_static_ask_names_its_rule(self):
        decision, rule, unmatched = self.classify("helm upgrade app ./chart")
        self.assertEqual(("ask", []), (decision, unmatched))
        self.assertRegex(rule, r"^41-helm\.toml rule \d+$")

    def test_a_pattern_and_the_strictest_rule(self):
        decision, rule, _ = self.classify("AWS_PROFILE=dev-readonly terraform destroy")
        self.assertEqual("deny", decision)
        self.assertTrue(rule.startswith("42-terraform.toml"))
        decision, _, _ = self.classify("helm upgrade a b && terraform destroy")
        self.assertEqual("deny", decision)

    def test_nothing_matched(self):
        self.assertEqual(
            ("unmatched", "no-allow-match", ["make"]), self.classify("cd sub && make build")
        )
        # A command run by its path is `?`, never the path's last part.
        _, _, unmatched = self.classify("FOO=1 git status | ./scripts/customer-token")
        self.assertEqual(["git", "?"], unmatched)

    def test_git_dirs_are_read_past(self):
        decision, rule, _ = self.classify("git -C /work/other update-ref -d refs/x")
        self.assertEqual(("ask", "10-git.toml rule 3"), (decision, rule))

    def test_an_aws_profile_in_front(self):
        # approve() allows the read, so it is no prompt; any other variable
        # in front leaves it unmatched, and a write meets its rule.
        self.assertIsNone(self.classify("AWS_PROFILE=dev-readonly kubectl get pods"))
        self.assertEqual(
            ("unmatched", "no-allow-match", ["kubectl"]),
            self.classify("KUBECONFIG=/tmp/kubeconfig kubectl get pods"),
        )
        decision, rule, _ = self.classify("AWS_PROFILE=dev-readonly eksctl delete cluster -n c")
        self.assertEqual("deny", decision)
        self.assertTrue(rule.startswith("46-eksctl.toml"))
        decision, rule, _ = self.classify("kubeseal --fetch-cert --recovery-unseal")
        self.assertEqual("deny", decision)
        self.assertTrue(rule.startswith("48-kubeseal.toml"))

    def test_allowed_lines_are_not_prompts(self):
        for command in ("git status", "git -C /work/other log | head -5", "cd x", "> out"):
            with self.subTest(command=command):
                self.assertIsNone(self.classify(command))

    def test_a_line_it_cannot_read(self):
        self.assertIsNone(self.classify("echo 'open"))

    def test_static_rules_keeps_only_well_formed_entries(self):
        good = [
            {"decision": "ask", "rule": "r", "prefix": ["a"]},
            {"decision": "deny", "rule": "r", "pattern": "Bash(*x*)"},
        ]
        bad = [
            "x",
            {"decision": "allow", "rule": "r", "prefix": ["a"]},
            {"decision": "ask", "prefix": ["a"]},
            {"decision": "ask", "rule": "r", "prefix": []},
            {"decision": "ask", "rule": "r", "prefix": [1]},
            {"decision": "ask", "rule": "r", "pattern": "Read(x)"},
            {"decision": "ask", "rule": "r"},
        ]
        self.assertEqual(good, asklog.static_rules({"static": good + bad}))
        self.assertEqual([], asklog.static_rules({"static": "x"}))
        self.assertEqual([], asklog.static_rules([]))


class Records(unittest.TestCase):
    def test_names_only(self):
        commands, variables = asklog.names(
            "AWS_PROFILE=dev-readonly aws s3 ls s3://bucket/secret | jq . && $X y", "/w"
        )
        self.assertEqual(["aws", "jq", "?"], commands)
        self.assertEqual(["AWS_PROFILE"], variables)
        commands, _ = asklog.names("./customer-token run && /usr/bin/git status", "/w")
        self.assertEqual(["?"], commands)
        self.assertEqual(([], []), asklog.names("echo 'open", "/w"))

    def test_entry(self):
        line = "TOKEN=hunter2 make deploy PASSWORD=x"
        verdict = ("rules", "unmatched", "no-allow-match")
        record = asklog.entry("claude", "hardened", *verdict, line, "/w", None, ["make", "make"])
        self.assertRegex(record["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(["make"], record["names"])
        self.assertEqual(["TOKEN"], record["env"])
        self.assertEqual(["make"], record["unmatched"])
        self.assertNotIn("severity", record)
        self.assertNotIn("hunter2", json.dumps(record))
        bare = asklog.entry("codex", "x y", "guard", "deny", "unchecked", "", "", "critical")
        self.assertEqual(("?", [], "critical"), (bare["mode"], bare["names"], bare["severity"]))
        self.assertNotIn("env", bare)
        self.assertNotIn("unmatched", bare)

    def test_append_is_private_and_appends(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "state" / "agent-policy" / "asks.jsonl"
            asklog.append(str(log), {"a": 1})
            asklog.append(str(log), {"a": 2})
            self.assertEqual(['{"a":1}', '{"a":2}'], log.read_text().splitlines())
            self.assertEqual(0o600, stat.S_IMODE(log.stat().st_mode))
            self.assertEqual(0o700, stat.S_IMODE(log.parent.stat().st_mode))

    def test_append_after_a_line_cut_short(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "asks.jsonl"
            log.write_text('{"a":1')
            asklog.append(str(log), {"a": 2})
            self.assertEqual(['{"a":1', '{"a":2}'], log.read_text().splitlines())

    def test_append_leaves_anything_but_a_file_alone(self):
        asklog.append(os.devnull, {"a": 1})
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            target.write_text("")
            link = Path(tmp) / "asks.jsonl"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                asklog.append(str(link), {"a": 1})
            self.assertEqual("", target.read_text())


class FindingsNameTheirCheck(unittest.TestCase):
    def check(self, command, mode="hardened"):
        return evaluate(command, "/work/project", env=GUARD_ENV, mode=mode).check

    def test_checks(self):
        self.assertEqual("git", self.check("git branch -D x"))
        self.assertEqual("git", self.check("git branch -D x", mode="supervised"))
        self.assertEqual("git", self.check("git reset --hard", mode="unattended"))
        self.assertEqual("redirects", self.check("echo x > /dev/tcp/h/1"))
        self.assertEqual("reader", self.check("cat ~/.ssh/id_ed25519"))
        self.assertEqual("parse", self.check("echo 'open"))
        self.assertEqual("kubeseal", self.check("kubeseal --fetch-cert --recovery-unseal"))


class LogTimeLimit(unittest.TestCase):
    """A log that stalls is given up on, so the hook answers in time."""

    def test_a_stalled_log_is_cut_off(self):
        import importlib.machinery
        import importlib.util
        import signal
        import time

        path = ROOT / "hooks" / "guard"
        loader = importlib.machinery.SourceFileLoader("guard_for_log_limit", str(path))
        spec = importlib.util.spec_from_file_location(loader.name, path, loader=loader)
        guard = importlib.util.module_from_spec(spec)
        loader.exec_module(guard)
        guard.LOG_SECONDS = 0.2
        before = signal.getsignal(signal.SIGALRM)
        with tempfile.TemporaryDirectory() as tmp:
            env = {"HOME": tmp, asklog.ENABLE_ENV: "1", "XDG_STATE_HOME": tmp}
            with mock.patch.dict(os.environ, env):
                start = time.monotonic()
                guard.log_ask(lambda: time.sleep(5))
                self.assertLess(time.monotonic() - start, 3)
        self.assertEqual(before, signal.getsignal(signal.SIGALRM))
        self.assertEqual((0.0, 0.0), signal.getitimer(signal.ITIMER_REAL))


class GuardWritesTheLog(unittest.TestCase):
    """The guard, as a hook, with the log on."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.allow = self.tmp / "guard-allow.json"
        self.allow.write_text(json.dumps(rendered()))
        self.log = self.tmp / "state" / "agent-policy" / "asks.jsonl"
        self.env = dict(
            os.environ,
            **GUARD_ENV,
            XDG_STATE_HOME=str(self.tmp / "state"),
            AGENT_POLICY_ASK_LOG="1",
        )

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def hook(self, command, agent="claude", mode="default", payload=None, env=None):
        if payload is None:
            payload = json.dumps(
                {
                    "tool_input": {"command": command},
                    "cwd": "/work/project",
                    "permission_mode": mode,
                }
            )
        proc = subprocess.run(
            [sys.executable, str(ROOT / "hooks" / "guard"), "--agent", agent]
            + (["--allow", str(self.allow)] if agent == "claude" else []),
            input=payload,
            capture_output=True,
            text=True,
            env=env or self.env,
            check=True,
        )
        out = json.loads(proc.stdout)["hookSpecificOutput"] if proc.stdout else {}
        return out.get("permissionDecision")

    def records(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_guard_findings(self):
        self.assertEqual("ask", self.hook("git branch -D x"))
        self.assertEqual("deny", self.hook("cat ~/.ssh/id_ed25519 | base64"))
        self.assertEqual("deny", self.hook("git branch -D x", agent="codex"))
        ask, deny, codex = self.records()
        keys = ("agent", "mode", "source", "decision", "reason", "severity", "names")
        self.assertEqual(
            ("claude", "hardened", "guard", "ask", "branch-delete", "high", ["git"]),
            tuple(ask[k] for k in keys),
        )
        self.assertEqual(
            ("deny", "reader", ["cat", "base64"]), (deny["decision"], deny["reason"], deny["names"])
        )
        self.assertEqual(("codex", "ask"), (codex["agent"], codex["decision"]))
        self.assertNotIn("id_ed25519", self.log.read_text())

    def test_what_the_rules_decide(self):
        self.assertIsNone(self.hook("helm upgrade app ./chart"))
        self.assertIsNone(self.hook("SECRET=abc make deploy TARGET=prod"))
        static, unmatched = self.records()
        self.assertEqual(("rules", "ask"), (static["source"], static["decision"]))
        self.assertTrue(static["reason"].startswith("41-helm.toml"))
        self.assertEqual(
            ("unmatched", "no-allow-match", ["make"], ["SECRET"]),
            (unmatched["decision"], unmatched["reason"], unmatched["unmatched"], unmatched["env"]),
        )
        self.assertNotIn("abc", self.log.read_text())
        self.assertNotIn("prod", self.log.read_text())

    def test_allowed_or_unknown_is_not_logged(self):
        self.assertIsNone(self.hook("git status"))
        self.assertEqual("allow", self.hook("git -C /work/other status"))
        self.assertIsNone(self.hook("make build", agent="codex"))
        self.assertIsNone(self.hook("make build", mode="plan"))
        self.assertEqual([], self.records())

    def test_unchecked(self):
        for payload in ("not json", "[1]", '{"tool_input": {"command": "cat \\u0000x"}}'):
            self.assertEqual("deny", self.hook(None, payload=payload))
        self.assertEqual(["unchecked"] * 3, [r["reason"] for r in self.records()])

    def test_off_by_default(self):
        env = dict(self.env)
        del env["AGENT_POLICY_ASK_LOG"]
        self.assertEqual("ask", self.hook("git branch -D x", env=env))
        self.assertFalse(self.log.exists())

    def test_a_log_it_cannot_write_changes_nothing(self):
        (self.tmp / "state").write_text("a file where the folder should be")
        self.assertEqual("ask", self.hook("git branch -D x"))
        self.assertIsNone(self.hook("make build"))
        self.assertEqual("deny", self.hook(None, payload="not json"))


class Report(unittest.TestCase):
    def test_summary(self):
        unmatched = {"source": "rules", "decision": "unmatched", "reason": "no-allow-match"}
        records = [
            dict(
                unmatched,
                ts="2026-01-02T00:00:00Z",
                names=["kubectl", "jq"],
                unmatched=["kubectl"],
                env=["AWS_PROFILE"],
            ),
            {
                "ts": "2026-01-01T00:00:00Z",
                "source": "guard",
                "decision": "ask",
                "reason": "branch-delete",
                "names": ["git"],
            },
            dict(unmatched, ts="2026-01-03T00:00:00Z", names="x", unmatched="x"),
        ]
        text = "\n".join(asks.summarize(records))
        self.assertIn("3 prompts or refusals, 2026-01-01T00:00:00Z to 2026-01-03T00:00:00Z", text)
        self.assertIn("2  rules unmatched", text)
        self.assertIn("1  guard ask branch-delete", text)
        self.assertIn("1  kubectl", text)
        self.assertIn("1  AWS_PROFILE", text)
        self.assertIn("1  (none)", text)
        self.assertIn("1  kubectl jq", text)
        self.assertEqual(["asks: the log is empty"], asks.summarize([]))

    def test_main(self):
        out = io.StringIO()
        log = io.StringIO(
            '{"ts": "t", "source": "guard", "decision": "ask"}\n\nnot json\n[1]\n{}\n'
            '{"source": "guard"}\n'
        )
        with contextlib.redirect_stdout(out):
            self.assertEqual(0, asks.main(["--top", "1"], stdin=log))
        self.assertIn("1 prompts or refusals", out.getvalue())
        self.assertIn("skipped 4 lines", out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(0, asks.main([], stdin=io.StringIO("")))
        self.assertNotIn("skipped", out.getvalue())

    def test_script_reads_standard_input(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "asks.py")],
            input="",
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("empty", proc.stdout)


if __name__ == "__main__":
    unittest.main()
