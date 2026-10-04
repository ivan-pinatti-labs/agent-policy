# SPDX-License-Identifier: Apache-2.0
import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import harvest


class Harvest(unittest.TestCase):
    """tools/harvest.py over a staging folder like the one collect.sh writes."""

    def setUp(self):
        self.staging = Path(tempfile.mkdtemp())
        settings = {
            "permissions": {
                "allow": [
                    "Bash(git status *)",  # the policy already grants it
                    "Bash(podman rm *)",  # the policy asks: never takes effect
                    "Bash(zzz-tool list *)",  # generic candidate
                    "Bash(zzz-run /home/someone/notes.txt)",  # local: home path
                    "mcp__server__tool",  # local: MCP tool
                    "Bash(python3:*)",  # runs arbitrary code
                ],
                "ask": ["Bash(git push --force *)"],  # the policy denies it
            }
        }
        (self.staging / "001-settings.local.json").write_text(json.dumps(settings))
        (self.staging / "002-default.rules").write_text(
            'prefix_rule(pattern=["zzz-other", "run"], decision="prompt")\n'
        )
        (self.staging / "index.tsv").write_text(
            "001-settings.local.json\t~/project/.claude/settings.local.json\n"
            "002-default.rules\t~/.codex/rules/default.rules\n"
        )

    def tearDown(self):
        shutil.rmtree(self.staging)

    def run_harvest(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(0, harvest.main([str(self.staging)]))
        return out.getvalue()

    def test_sorts_every_rule(self):
        out = self.run_harvest()
        self.assertIn("== ~/project/.claude/settings.local.json", out)
        self.assertIn("allow Bash(zzz-tool list *)", out)
        self.assertIn("Bash(podman rm *)   (policy:", out)
        self.assertIn("[home path]", out)
        self.assertIn("[MCP tool]", out)
        self.assertIn("runs arbitrary code", out)
        self.assertIn("== ~/.codex/rules/default.rules", out)
        self.assertIn("ask   Bash(zzz-other run *)", out)

    def test_totals(self):
        last = self.run_harvest().strip().splitlines()[-1]
        self.assertTrue(last.startswith("harvest: "), last)
        totals = dict(item.rsplit(" ", 1) for item in last[len("harvest: ") :].split(", "))
        self.assertEqual("1", totals["dead"])
        self.assertEqual("2", totals["redundant"])

    def test_normalize_legacy_suffix(self):
        self.assertEqual("Bash(ls *)", harvest.normalize("Bash(ls:*)"))

    def test_unreadable_settings_are_skipped(self):
        (self.staging / "001-settings.local.json").write_text("{not json")
        self.assertNotIn("settings.local.json", self.run_harvest())
