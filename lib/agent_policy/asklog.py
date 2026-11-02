# SPDX-License-Identifier: Apache-2.0
"""The ask log: an opt in, local record of the prompts and refusals the
guard can see, to measure how often the policy stops an agent and why.

Off unless AGENT_POLICY_ASK_LOG=1 is set or the file
$XDG_CONFIG_HOME/agent-policy/ask-log exists. When on, the guard appends one
JSON line per ask or deny to $XDG_STATE_HOME/agent-policy/asks.jsonl. A line
holds the time (UTC), the agent, the mode, where the decision came from, the
decision, a fixed reason id (a finding's key or check, a policy rule's file
and number), and the names of the commands on the line and of the variables
set in front of them. Never an argument, a value, a path or the command line
itself, so no secret can land in it.

Two sources, as far as the guard can tell (docs/OPERATIONS.md, "The ask
log"):

  guard   the guard itself asked or refused (a finding). Certain.
  rules   the guard was silent, and the rendered Claude Code rules decide:
          `ask` or `deny` when one of their ask or deny rules matches the
          line, `unmatched` when none does and a command on the line
          matches no allow rule either, so Claude Code falls to its prompt
          (or auto mode's classifier). Claude only, since only Claude Code's
          hook is given the rules.

The guard cannot see what Claude Code finally does: a project's own allow
rules or an answer saved with "don't ask again" may still let a line
through. So a `rules` line is an estimate of a prompt.

Writing the log never changes a decision: the guard swallows every failure.
"""

import json
import os
import re
import stat
from datetime import UTC, datetime

from . import checks
from .shell import ParseError, segments

ENABLE_ENV = "AGENT_POLICY_ASK_LOG"
ON = ("1", "true", "yes", "on")
# A command or variable name is logged only in this shape; anything else (a
# computed name, a path's last part that is not a plain word) is "?".
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,39}")
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
# Commands Claude Code decides on its own, without a rule.
BUILTIN = {"cd"}


def _home(env):
    return env.get("HOME") or os.path.expanduser("~")


def path(env=None):
    """The log file when the log is on, else None."""
    env = os.environ if env is None else env
    home = _home(env)
    config = env.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    switch = os.path.join(config, "agent-policy", "ask-log")
    if env.get(ENABLE_ENV, "").lower() not in ON and not os.path.exists(switch):
        return None
    state = env.get("XDG_STATE_HOME") or os.path.join(home, ".local", "state")
    return os.path.join(state, "agent-policy", "asks.jsonl")


def static_rules(data):
    """The ask and deny rules from a guard-allow.json object, the well formed
    ones only."""
    entries = data.get("static") if isinstance(data, dict) else None
    out = []
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict) or entry.get("decision") not in ("ask", "deny"):
            continue
        if not isinstance(entry.get("rule"), str):
            continue
        prefix, pattern = entry.get("prefix"), entry.get("pattern")
        if isinstance(prefix, list) and prefix and all(isinstance(w, str) for w in prefix):
            out.append(entry)
        elif isinstance(pattern, str) and pattern.startswith("Bash(") and pattern.endswith(")"):
            out.append(entry)
    return out


def _glob(pattern):
    """A Claude Code `Bash(...)` pattern as a regular expression: `*` is any
    text, everything else is literal."""
    body = pattern[len("Bash(") : -1]
    return re.compile("".join(".*" if c == "*" else re.escape(c) for c in body), re.DOTALL)


def _name(word):
    return word if NAME.fullmatch(word) else "?"


def classify(command, cwd, home, prefixes, static):
    """What the rendered Claude Code rules make of a line the guard was
    silent on: (decision, rule, unmatched names), or None when they allow
    it. decision is "deny" or "ask" for a static rule (the strictest that
    matches), or "unmatched" when some command matches no rule at all. A
    command counts as allowed exactly when approve() would count it."""
    try:
        segs = [seg for seg in segments(command, cwd=cwd) if seg.words]
    except ParseError:
        return None
    line = " ".join(command.split())
    texts = [line, *(" ".join(seg.words) for seg in segs)]
    best = None
    for entry in static:
        if "prefix" in entry:
            hit = any(seg.words[: len(entry["prefix"])] == entry["prefix"] for seg in segs)
        else:
            regex = _glob(entry["pattern"])
            hit = any(regex.fullmatch(text) for text in texts)
        if hit and (best is None or (entry["decision"] == "deny" and best["decision"] == "ask")):
            best = entry
    if best:
        return best["decision"], best["rule"], []
    allowed = {tuple(p) for p in prefixes}
    unmatched = [
        _name(seg.name)
        for seg in segs
        if seg.name not in BUILTIN and checks._approval(seg, allowed, cwd, home) is None
    ]
    if unmatched:
        return "unmatched", "no-allow-match", unmatched
    return None


def names(command, cwd):
    """The command names and the names of the variables set in front of
    them, in order, each once."""
    try:
        segs = [seg for seg in segments(command, cwd=cwd) if seg.words]
    except ParseError:
        return [], []
    commands = list(dict.fromkeys(_name(seg.name) for seg in segs))
    variables = [k if ENV_NAME.fullmatch(k) else "?" for seg in segs for k in seg.env]
    return commands, list(dict.fromkeys(variables))


def entry(agent, mode, source, decision, reason, command, cwd, severity=None, unmatched=()):
    """One log line, as a dict."""
    commands, variables = names(command, cwd) if command else ([], [])
    out = {
        "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent": _name(agent),
        "mode": _name(mode),
        "source": source,
        "decision": decision,
        "reason": reason,
        "names": commands,
    }
    if severity:
        out["severity"] = severity
    if variables:
        out["env"] = variables
    if unmatched:
        out["unmatched"] = list(dict.fromkeys(unmatched))
    return out


def append(log, record):
    """Append `record` to the file `log` as one line, creating it (and its
    folder) private to the user. A link or anything but a regular file at
    that path is left alone, and the open never blocks on a FIFO."""
    os.makedirs(os.path.dirname(log), mode=0o700, exist_ok=True)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(log, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return
        os.write(fd, (json.dumps(record, separators=(",", ":")) + "\n").encode())
    finally:
        os.close(fd)
