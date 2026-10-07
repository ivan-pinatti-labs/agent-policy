# SPDX-License-Identifier: Apache-2.0
import json
import os
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from agent_policy.checks import evaluate

ENV = {
    "HOME": "/home/user",
    "AGENT_POLICY_PROTECTED": "/home/user/live",
    "XDG_CONFIG_HOME": "/nonexistent",
}
CONTAINERS = {
    "live-app": {
        "Config": {"Labels": {"com.docker.compose.project.working_dir": "/home/user/live"}},
        "Mounts": [],
    },
    "dev-app": {
        "Config": {"Labels": {"com.docker.compose.project.working_dir": "/work/project"}},
        "Mounts": [],
    },
}


def fake_inspect(engine, kind, target, timeout=5):
    return CONTAINERS.get(target)


class GuardCases(unittest.TestCase):
    def test_cases(self):
        with open(ROOT / "tests" / "guard_cases.toml", "rb") as handle:
            cases = tomllib.load(handle)["case"]
        for case in cases:
            with self.subTest(command=case["command"]):
                finding = evaluate(
                    case["command"],
                    case.get("cwd", "/work/project"),
                    env=ENV,
                    inspector=fake_inspect,
                )
                got = finding.decision if finding else "none"
                self.assertEqual(case["expect"], got, finding.reason if finding else "no finding")


class Symlinks(unittest.TestCase):
    """A path is judged by where it leads, not by its own name."""

    def setUp(self):
        import tempfile

        self.root = Path(tempfile.mkdtemp())
        self.home = self.root / "home"
        (self.home / ".ssh").mkdir(parents=True)
        (self.home / ".ssh" / "id_ed25519").write_text("secret")
        (self.home / ".bashrc").write_text("")
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "key").symlink_to(self.home / ".ssh" / "id_ed25519")
        (self.project / "rc").symlink_to(self.home / ".bashrc")
        (self.project / "notes.md").write_text("")
        (self.home / ".claude").mkdir()
        (self.home / ".claude" / ".credentials.json").write_text("secret")
        session = self.home / ".claude" / "projects" / "-project" / "session"
        session.mkdir(parents=True)
        (session / "tool-results").symlink_to(self.home / ".claude")
        # A real tool-results folder, holding an output and a link out of it.
        results = self.home / ".claude" / "projects" / "-project" / "other" / "tool-results"
        results.mkdir(parents=True)
        (results / "b1.txt").write_text("output")
        (results / "out").symlink_to(self.home / ".claude" / ".credentials.json")
        self.env = {"HOME": str(self.home), "XDG_CONFIG_HOME": "/nonexistent"}

    def tearDown(self):
        import shutil

        shutil.rmtree(self.root)

    def decide(self, command):
        finding = evaluate(command, str(self.project), env=self.env, inspector=fake_inspect)
        return finding.decision if finding else "none"

    def test_reading_through_a_link(self):
        self.assertEqual("deny", self.decide("cat key"))
        self.assertEqual("deny", self.decide("base64 < ./key"))

    def test_tool_results_link_to_credentials(self):
        results = "~/.claude/projects/-project/session/tool-results"
        self.assertEqual("deny", self.decide(f"grep x {results}/.credentials.json"))
        self.assertEqual("deny", self.decide(f"cat {results}/x"))

    def test_tool_results_files_but_not_the_folder(self):
        results = "~/.claude/projects/-project/other/tool-results"
        self.assertEqual("none", self.decide(f"grep -n output {results}/b1.txt"))
        self.assertEqual("deny", self.decide(f"cat {results}/out"))
        # grep -R follows the link inside; the folder itself stays refused.
        self.assertEqual("deny", self.decide(f"grep -R token {results}"))
        self.assertEqual("deny", self.decide(f"grep -rn token {results}/"))

    def test_writing_through_a_link(self):
        self.assertEqual("deny", self.decide("echo x >> rc"))
        self.assertEqual("deny", self.decide("cp notes.md rc"))

    def test_mounting_through_a_link(self):
        self.assertEqual("deny", self.decide("podman run --rm -v ./key:/k alpine true"))

    def test_ordinary_files_are_unaffected(self):
        self.assertEqual("none", self.decide("cat notes.md"))


class HookProtocol(unittest.TestCase):
    """The hook's stdout, as each agent reads it."""

    def run_hook(self, agent, command):
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": "/work/project",
            "session_id": "test",
        }
        env = dict(os.environ, **ENV)
        proc = subprocess.run(
            [sys.executable, str(ROOT / "hooks" / "guard"), "--agent", agent],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        return json.loads(proc.stdout)["hookSpecificOutput"] if proc.stdout else None

    def test_silent_when_nothing_found(self):
        self.assertIsNone(self.run_hook("claude", "git status"))

    def test_deny_hands_off_to_the_user(self):
        for agent in ("claude", "codex"):
            out = self.run_hook(agent, "git push origin main --force")
            self.assertEqual("deny", out["permissionDecision"])
            self.assertIn("! git push origin main --force", out["permissionDecisionReason"])

    def test_ask_is_a_prompt_for_claude_and_a_deny_for_codex(self):
        self.assertEqual("ask", self.run_hook("claude", "git branch -D x")["permissionDecision"])
        out = self.run_hook("codex", "git branch -D x")
        self.assertEqual("deny", out["permissionDecision"])
        self.assertIn("approval", out["permissionDecisionReason"])

    def test_any_failure_to_check_refuses(self):
        for payload in ("[1, 2]", '"text"', '{"tool_input": {"command": "cat \\u0000x"}}'):
            with self.subTest(payload=payload):
                proc = subprocess.run(
                    [sys.executable, str(ROOT / "hooks" / "guard")],
                    input=payload,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                out = json.loads(proc.stdout)["hookSpecificOutput"]
                self.assertEqual("deny", out["permissionDecision"])

    def test_unreadable_payload_fails_closed(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "hooks" / "guard")],
            input="not json",
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(
            "deny", json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"]
        )


if __name__ == "__main__":
    unittest.main()
