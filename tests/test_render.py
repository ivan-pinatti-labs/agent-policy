# SPDX-License-Identifier: Apache-2.0
import json
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import render


class Render(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        assert render.main(["--out", cls.tmp]) == 0
        cls.claude = json.loads((Path(cls.tmp) / "claude" / "50-agent-policy.json").read_text())
        cls.rules_file = Path(cls.tmp) / "codex" / "agent-policy.rules"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def test_nothing_machine_specific(self):
        for path in Path(self.tmp).rglob("*"):
            if path.is_file():
                self.assertNotIn("/home/", path.read_text(), path)

    def test_claude_permissions(self):
        perms = self.claude["permissions"]
        for decision in render.DECISIONS:
            self.assertTrue(perms[decision], decision)
            self.assertEqual(len(perms[decision]), len(set(perms[decision])), decision)
        self.assertIn("Bash(git push *)", perms["allow"])
        self.assertIn("Bash(git -C * push *)", perms["allow"])
        self.assertIn("Bash(*git*push*--force*)", perms["deny"])
        self.assertNotIn("Bash(env *)", perms["allow"])

    def test_agent_logins_cannot_be_read_or_written_by_file_tools(self):
        deny = self.claude["permissions"]["deny"]
        for tool in ("Read", "Edit", "Write"):
            for path in ("~/.claude*/.credentials.json", "~/.codex/auth.json", "~/.ssh/id_*"):
                self.assertIn(f"{tool}({path})", deny)

    def test_unlisted_podman_subcommands_now_ask(self):
        ask = self.claude["permissions"]["ask"]
        for words in (
            "podman container init",
            "podman pod clone",
            "podman pod pause",
            "podman pod unpause",
        ):
            self.assertIn(f"Bash({words} *)", ask)

    def test_the_scratchpad_by_default(self):
        perms = self.claude["permissions"]
        self.assertEqual(["~/scratch"], perms["additionalDirectories"])
        self.assertIn("Write(~/scratch/**)", perms["allow"])
        self.assertIn("Bash(agent-scratch *)", perms["allow"])
        self.assertIn("agent-scratch", self.rules_file.read_text())

    def test_no_scratch_leaves_the_scratchpad_out(self):
        tmp = tempfile.mkdtemp()
        try:
            self.assertEqual(0, render.main(["--out", tmp, "--no-scratch"]))
            claude = json.loads((Path(tmp) / "claude" / "50-agent-policy.json").read_text())
            trial = json.loads((Path(tmp) / "claude" / "sandbox-trial.json").read_text())
            text = json.dumps(claude) + json.dumps(trial)
            text += (Path(tmp) / "codex" / "agent-policy.rules").read_text()
            self.assertNotIn("scratch", text)
            self.assertNotIn("additionalDirectories", claude["permissions"])
            # Everything else is still there.
            self.assertIn("Bash(git push *)", claude["permissions"]["allow"])
            self.assertIn("git *", trial["sandbox"]["excludedCommands"])
            self.assertIn("~/.ssh", trial["sandbox"]["filesystem"]["denyRead"])
        finally:
            shutil.rmtree(tmp)

    def test_claude_hook(self):
        hook = self.claude["hooks"]["PreToolUse"][0]
        self.assertEqual("Bash", hook["matcher"])
        self.assertTrue(hook["hooks"][0]["command"].endswith("/guard --agent claude"))

    def test_paths_outside_the_repo_are_refused(self):
        import contextlib
        import io

        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(1, render.main(["--out", "/etc/agent-policy-test"]))
            self.assertEqual(1, render.main(["--policy", "/etc", "--out", self.tmp]))

    def test_codex_requirements(self):
        with open(Path(self.tmp) / "codex" / "requirements.toml", "rb") as handle:
            req = tomllib.load(handle)
        self.assertIs(True, req["features"]["hooks"])
        managed = req["hooks"]["managed_dir"]
        command = req["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertTrue(command.startswith(managed + "/guard "), command)
        self.assertTrue(command.endswith("--agent codex"))

    def test_sandbox_trial_file(self):
        trial = json.loads((Path(self.tmp) / "claude" / "sandbox-trial.json").read_text())
        sandbox = trial["sandbox"]
        self.assertTrue(sandbox["enabled"])
        self.assertFalse(sandbox["autoAllowBashIfSandboxed"])
        deny_read = sandbox["filesystem"]["denyRead"]
        for path in ("~/.ssh", "~/.aws", "~/.config/gh", "~/.codex", "~/.netrc"):
            self.assertIn(path, deny_read)
        self.assertIn("~/.local/bin", sandbox["filesystem"]["denyWrite"])
        self.assertIn("git *", sandbox["excludedCommands"])

    def test_sandbox_stays_out_of_the_drop_in_until_installed(self):
        cfg = render.load_sandbox(ROOT / "policy")
        self.assertEqual("sandbox" in self.claude, bool(cfg.get("install")))

    def test_sandbox_lists_follow_the_guard(self):
        sys.path.insert(0, str(ROOT / "lib"))
        from agent_policy import containers

        sandbox = render.render_sandbox({})
        for rel in containers.CREDENTIAL_DIRS + containers.CREDENTIAL_FILES:
            self.assertIn(f"~/{rel}", sandbox["filesystem"]["denyRead"])

    def test_every_rule_has_a_known_severity(self):
        rules = render.load(ROOT / "policy")
        for rule in rules:
            self.assertIn(rule["severity"], render.SEVERITY, rule["source"])

    def test_severity_map_matches_checks(self):
        # The guard and the renderer must agree on severity -> decision.
        sys.path.insert(0, str(ROOT / "lib"))
        from agent_policy.checks import SEVERITY as GUARD_SEVERITY

        for name, decision in render.SEVERITY.items():
            self.assertEqual(decision, GUARD_SEVERITY[name][0], name)

    def test_policy_errors_are_reported(self):
        with tempfile.TemporaryDirectory() as bad:
            Path(bad, "x.toml").write_text(
                '[[rule]]\nseverity = "maybe"\nreason = "r"\nprefix = [["ls"]]\n'
            )
            with self.assertRaises(render.PolicyError):
                render.load(bad)

    @unittest.skipUnless(shutil.which("codex"), "codex is not installed")
    def test_codex_cases(self):
        with open(ROOT / "tests" / "codex_cases.toml", "rb") as handle:
            cases = tomllib.load(handle)["case"]
        for case in cases:
            with self.subTest(command=case["command"]):
                proc = subprocess.run(
                    [
                        "codex",
                        "execpolicy",
                        "check",
                        "-r",
                        str(self.rules_file),
                        *case["command"],
                    ],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                got = json.loads(proc.stdout).get("decision", "none")
                self.assertEqual(case["expect"], got, proc.stdout)


if __name__ == "__main__":
    unittest.main()
