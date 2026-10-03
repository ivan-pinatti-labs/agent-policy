#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Render policy/*.toml into each agent's native files.

  dist/claude/50-agent-policy.json   a managed-settings.d drop-in:
                                      permissions + the guard hook
  dist/codex/agent-policy.rules      Codex prefix_rule()s
  dist/codex/requirements.toml       the guard hook for /etc/codex

Standard library only. Nothing machine-specific goes in: paths under the
home folder are written with `~`, and the install prefix is an argument.
"""

import argparse
import itertools
import json
import sys
import tomllib
from pathlib import Path

# The sandbox's denied paths come from the guard's own lists.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from agent_policy import containers

DECISIONS = ("allow", "ask", "deny")
AGENTS = ("claude", "codex")
# The severity scale (docs/POLICY.md), each mapped to the decision an agent
# acts on. Kept in step with lib/agent_policy/checks.py's SEVERITY map.
SEVERITY = {
    "read": "allow",
    "low": "allow",
    "moderate": "ask",
    "high": "ask",
    "severe": "deny",
    "critical": "deny",
}
CODEX_DECISION = {"allow": "allow", "ask": "prompt", "deny": "forbidden"}
MARKER = "# Managed by agent-policy (tools/render.py). Local edits are overwritten."


def decision_of(rule):
    return SEVERITY[rule["severity"]]


class PolicyError(ValueError):
    pass


def load(policy_dir):
    rules = []
    for path in sorted(Path(policy_dir).glob("*.toml")):
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
        for index, rule in enumerate(data.get("rule", [])):
            where = f"{path.name} rule {index + 1}"
            validate(rule, where)
            rule = dict(rule, source=where)
            rule.setdefault("agents", list(AGENTS))
            rule.setdefault("prefix", [])
            rule.setdefault("claude", [])
            rules.append(rule)
    return rules


def validate(rule, where):
    unknown = set(rule) - {"severity", "reason", "agents", "prefix", "claude"}
    if unknown:
        raise PolicyError(f"{where}: unknown keys {sorted(unknown)}")
    if rule.get("severity") not in SEVERITY:
        raise PolicyError(f"{where}: severity must be one of {tuple(SEVERITY)}")
    if not isinstance(rule.get("reason"), str) or not rule["reason"]:
        raise PolicyError(f"{where}: reason is required")
    agents = rule.get("agents", list(AGENTS))
    if not agents or set(agents) - set(AGENTS):
        raise PolicyError(f"{where}: agents must be a non-empty subset of {AGENTS}")
    if rule.get("claude") and "claude" not in agents:
        raise PolicyError(f"{where}: claude patterns on a rule that excludes claude")
    for prefix in rule.get("prefix", []):
        if not isinstance(prefix, list) or not prefix:
            raise PolicyError(f"{where}: each prefix must be a non-empty list")
        for word in prefix:
            alts = word if isinstance(word, list) else [word]
            if not alts or not all(isinstance(a, str) and a and " " not in a for a in alts):
                raise PolicyError(f"{where}: bad word {word!r} in {prefix!r}")
    for pattern in rule.get("claude", []):
        if not isinstance(pattern, str) or not pattern:
            raise PolicyError(f"{where}: bad claude pattern {pattern!r}")
    if not rule.get("prefix") and not rule.get("claude"):
        raise PolicyError(f"{where}: needs prefix or claude patterns")


def expand(prefix):
    choices = [w if isinstance(w, list) else [w] for w in prefix]
    return [list(words) for words in itertools.product(*choices)]


def claude_bash(words):
    text = " ".join(words)
    out = [f"Bash({text})", f"Bash({text} *)"]
    if words[0] == "git" and len(words) > 1:
        rest = " ".join(words[1:])
        out += [f"Bash(git -C * {rest})", f"Bash(git -C * {rest} *)"]
    return out


def claude_rules(rules):
    perms = {d: [] for d in DECISIONS}
    for rule in rules:
        if "claude" not in rule["agents"]:
            continue
        bucket = perms[decision_of(rule)]
        for prefix in rule["prefix"]:
            for words in expand(prefix):
                bucket.extend(claude_bash(words))
        bucket.extend(rule["claude"])
    return {d: list(dict.fromkeys(v)) for d, v in perms.items()}


def render_claude(rules, libexec):
    return {
        "permissions": {**claude_rules(rules), "additionalDirectories": ["~/scratch"]},
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": f"{libexec}/guard --agent claude",
                            "timeout": 10,
                        }
                    ],
                }
            ]
        },
    }


def load_sandbox(policy_dir):
    path = Path(policy_dir) / "sandbox.toml"
    if not path.exists():
        return None
    with open(path, "rb") as handle:
        cfg = tomllib.load(handle).get("sandbox", {})
    known = {
        "install",
        "fail_if_unavailable",
        "auto_allow_bash_if_sandboxed",
        "excluded_commands",
        "allow_write",
    }
    unknown = set(cfg) - known
    if unknown:
        raise PolicyError(f"sandbox.toml: unknown keys {sorted(unknown)}")
    return cfg


def render_sandbox(cfg):
    deny_read = [f"~/{d}" for d in containers.CREDENTIAL_DIRS]
    deny_read += [f"~/{f}" for f in containers.CREDENTIAL_FILES]
    deny_read += [f"~/{p}*/.credentials.json" for p in containers.CREDENTIAL_PREFIXES]
    return {
        "enabled": True,
        "failIfUnavailable": bool(cfg.get("fail_if_unavailable", False)),
        "autoAllowBashIfSandboxed": bool(cfg.get("auto_allow_bash_if_sandboxed", False)),
        "excludedCommands": list(cfg.get("excluded_commands", [])),
        "filesystem": {
            "denyRead": deny_read,
            "denyWrite": [f"~/{d}" for d in containers.EXEC_DIRS],
            "allowWrite": list(cfg.get("allow_write", [])),
        },
    }


def render_codex_rules(rules):
    lines = [MARKER, ""]
    for rule in rules:
        if "codex" not in rule["agents"] or not rule["prefix"]:
            continue
        lines.append(f"# {rule['source']} [{rule['severity']}]: {rule['reason']}")
        justification = f"[{rule['severity']}] {rule['reason']}"
        for prefix in rule["prefix"]:
            lines.append(
                f"prefix_rule(pattern={json.dumps(prefix)}, "
                f"decision={json.dumps(CODEX_DECISION[decision_of(rule)])}, "
                f"justification={json.dumps(justification)})"
            )
        lines.append("")
    return "\n".join(lines)


def render_codex_requirements(libexec):
    return "\n".join(
        [
            MARKER,
            "",
            "[[hooks.PreToolUse]]",
            'matcher = "^Bash$"',
            "",
            "[[hooks.PreToolUse.hooks]]",
            'type = "command"',
            f'command = "{libexec}/guard --agent codex"',
            "timeout = 10",
            "",
        ]
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--policy", default=Path(__file__).resolve().parent.parent / "policy")
    parser.add_argument("--out", default="dist")
    parser.add_argument("--libexec", default="/usr/local/libexec/agent-policy")
    args = parser.parse_args(argv)
    try:
        rules = load(args.policy)
    except PolicyError as err:
        print(f"render: {err}", file=sys.stderr)
        return 1
    out = Path(args.out)
    (out / "claude").mkdir(parents=True, exist_ok=True)
    (out / "codex").mkdir(parents=True, exist_ok=True)
    claude = render_claude(rules, args.libexec)
    try:
        sandbox_cfg = load_sandbox(args.policy)
    except PolicyError as err:
        print(f"render: {err}", file=sys.stderr)
        return 1
    if sandbox_cfg is not None:
        sandbox = render_sandbox(sandbox_cfg)
        trial = {"sandbox": sandbox}
        (out / "claude" / "sandbox-trial.json").write_text(json.dumps(trial, indent=2) + "\n")
        if sandbox_cfg.get("install"):
            claude["sandbox"] = sandbox
    (out / "claude" / "50-agent-policy.json").write_text(json.dumps(claude, indent=2) + "\n")
    (out / "codex" / "agent-policy.rules").write_text(render_codex_rules(rules))
    (out / "codex" / "requirements.toml").write_text(render_codex_requirements(args.libexec))
    counts = ", ".join(f"{d} {len(claude['permissions'][d])}" for d in DECISIONS)
    sev = {s: sum(1 for r in rules if r["severity"] == s) for s in SEVERITY}
    sev_line = ", ".join(f"{s} {n}" for s, n in sev.items() if n)
    print(
        f"render: {len(rules)} rules ({sev_line}) -> claude ({counts}), codex "
        f"{sum(1 for r in rules if 'codex' in r['agents'] for _ in r['prefix'])} prefix rules"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
