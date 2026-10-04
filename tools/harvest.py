#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Compare the permission files on this machine with the shared policy.

Reads a folder made by tools/collect.sh and prints, per file:

  candidates  rules the policy does not cover yet. "generic" ones may be
              worth adding to policy/*.toml; "local" ones (home paths,
              ARNs, account IDs, env-prefixed commands, MCP tools) stay in
              that project's settings.local.json.
  dead        local allow rules the policy asks or denies on, so they never
              take effect (ask and deny win over allow in every scope).
  redundant   rules the policy already grants; safe to delete locally.

Nothing is changed. Promoting a candidate is a normal edit to policy/ with a
test case, through a pull request.
"""

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render

CODEX_RULE = re.compile(r"prefix_rule\(\s*pattern\s*=\s*(\[.*?\])\s*,\s*decision\s*=\s*\"(\w+)\"")
CODEX_TO_TIER = {"allow": "allow", "prompt": "ask", "forbidden": "deny"}
LOCAL_HINTS = [
    (re.compile(r"/home/|/Users/"), "home path"),
    (re.compile(r"arn:aws"), "AWS ARN"),
    (re.compile(r"\b\d{10,}\b"), "account or resource id"),
    (re.compile(r"^Bash\([A-Z_]+=\S+ "), "env-prefixed"),
    (re.compile(r"^mcp__"), "MCP tool"),
    (re.compile(r"\brepos/[^/ ]+/[^/ ]+"), "specific repository"),
]
BROAD = re.compile(r"^Bash\((python3?|bash|sh|env|ssh|sudo|node|npx|perl|ruby|eval)\b[ :]")


def glob_regex(pattern):
    return re.compile("^" + ".*".join(re.escape(p) for p in pattern.split("*")) + "$", re.DOTALL)


def normalize(rule):
    rule = rule.strip()
    if rule.endswith(":*)"):
        rule = rule[:-3] + " *)"
    return rule


def inner(rule):
    match = re.match(r"^(\w+)\((.*)\)$", rule, re.DOTALL)
    return (match.group(1), match.group(2)) if match else (rule, "")


STAGED_NAME = re.compile(r"[0-9]{3}-[A-Za-z0-9._-]+")


def read_rules(path):
    """[(tier, rule)] from a Claude settings file or a Codex .rules file."""
    if path.suffix == ".rules":
        out = []
        for pattern, decision in CODEX_RULE.findall(path.read_text()):
            for words in render.expand(json.loads(pattern)):
                out.append((CODEX_TO_TIER.get(decision, "ask"), f"Bash({' '.join(words)} *)"))
        return out
    try:
        perms = json.loads(path.read_text()).get("permissions") or {}
    except ValueError:
        return []
    return [
        (tier, normalize(rule))
        for tier in render.DECISIONS
        for rule in perms.get(tier, [])
        if isinstance(rule, str)
    ]


def matches(rule, patterns):
    tool, arg = inner(rule)
    for pattern in patterns:
        ptool, parg = inner(pattern)
        if ptool != tool:
            continue
        if pattern == rule or (parg and glob_regex(parg).match(arg)):
            return pattern
    return None


def classify(rule):
    hints = [label for regex, label in LOCAL_HINTS if regex.search(rule)]
    if BROAD.search(rule):
        hints.append("runs arbitrary code")
    return hints


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("staging", help="folder written by tools/collect.sh")
    args = parser.parse_args(argv)
    try:
        # make harvest mounts the staging folder at /staging; tests use a
        # temporary folder. Nothing else is a staging folder.
        staging = render.confine(args.staging, ["/staging", tempfile.gettempdir()], "staging")
    except render.PolicyError as err:
        print(f"harvest: {err}", file=sys.stderr)
        return 1
    policy = render.claude_rules(render.load(render.REPO_ROOT / "policy"))
    index = {}
    for line in (staging / "index.tsv").read_text().splitlines():
        name, tab, original = line.partition("\t")
        # collect.sh writes plain names (NNN-basename); anything else, such
        # as a path with a separator or `..`, is not one of its files.
        if tab and STAGED_NAME.fullmatch(name):
            index[name] = original
    totals = {"generic": 0, "local": 0, "dead": 0, "redundant": 0}
    for name, original in sorted(index.items()):
        rules = read_rules(staging / name)
        if not rules:
            continue
        generic, local, dead, redundant = [], [], [], []
        for tier, rule in rules:
            stricter = None
            if tier == "allow":
                stricter = matches(rule, policy["deny"]) or matches(rule, policy["ask"])
            if stricter:
                dead.append(f"{rule}   (policy: {stricter})")
            elif matches(rule, policy[tier]) or (tier == "ask" and matches(rule, policy["deny"])):
                redundant.append(rule)
            else:
                hints = classify(rule)
                entry = f"{tier:5} {rule}" + (f"   [{', '.join(hints)}]" if hints else "")
                (local if hints else generic).append(entry)
        print(f"\n== {original}  ({len(rules)} rules)")
        for title, items in (
            ("candidates, generic", generic),
            ("candidates, local", local),
            ("dead", dead),
            ("redundant", redundant),
        ):
            if items:
                print(f"  -- {title} ({len(items)})")
                for item in items if title != "redundant" else items[:5]:
                    print(f"     {item}")
                if title == "redundant" and len(items) > 5:
                    print(f"     ... and {len(items) - 5} more")
        totals["generic"] += len(generic)
        totals["local"] += len(local)
        totals["dead"] += len(dead)
        totals["redundant"] += len(redundant)
    print("\nharvest: " + ", ".join(f"{k} {v}" for k, v in totals.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
