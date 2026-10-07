# SPDX-License-Identifier: Apache-2.0
"""Split a shell command line into simple commands, well enough for policy.

This is not a shell parser. It recognizes the operators an agent actually
writes (&&, ||, ;, |, &, newlines, subshell parentheses), drops heredoc
bodies, looks inside $(...), backticks and `bash -c '...'`, and peels off
wrappers (env, timeout, xargs, sudo...) so that `timeout 5 git push ...` is
judged as `git push ...`. When the line cannot be tokenized at all it says
so, and the caller decides how careful to be.
"""

import re
import shlex
from dataclasses import dataclass, field

OPERATOR_CHARS = set(";&|()")

# Wrappers that run the rest of the line as a command. For each, the options
# that take a separate value, so the value is not mistaken for the command.
WRAPPERS = {
    "command": set(),
    "builtin": set(),
    "exec": set(),
    "nohup": set(),
    "time": set(),
    "setsid": set(),
    "noglob": set(),
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "-n", "--class", "--classdata"},
    "stdbuf": {"-i", "-o", "-e"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "--user", "--group"},
    "doas": {"-u", "-C"},
    "xargs": {
        "-I",
        "-i",
        "-n",
        "-P",
        "-L",
        "-l",
        "-s",
        "-d",
        "-E",
        "-e",
        "-a",
        "--max-args",
        "--max-procs",
        "--delimiter",
        "--arg-file",
        "--replace",
    },
    "watch": {"-n", "--interval", "-d"},
    "flock": {"-w", "--timeout", "-E", "--conflict-exit-code"},
    "env": {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"},
}
# Wrappers followed by one positional argument before the command.
WRAPPER_POSITIONAL = {"timeout": 1, "flock": 1}
SHELLS = {"bash", "sh", "zsh", "dash"}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


class ParseError(ValueError):
    """The command line could not be tokenized (unbalanced quotes and the like)."""


@dataclass
class Segment:
    words: list
    env: dict = field(default_factory=dict)
    # (operator, target) pairs, such as (">", "out.txt") or ("<", "in"),
    # taken out of words so a redirect target is never read as an argument.
    redirects: list = field(default_factory=list)
    # True when a wrapper (sudo, env, xargs...) was peeled off the front.
    wrapped: bool = False

    @property
    def name(self):
        return self.words[0].rsplit("/", 1)[-1] if self.words else ""


def strip_heredoc_bodies(text):
    """Keep the line that opens a heredoc, drop its body up to the terminator."""
    out, terminator = [], None
    for line in text.split("\n"):
        if terminator is not None:
            if line.strip() == terminator:
                terminator = None
            continue
        out.append(line)
        match = HEREDOC.search(line)
        if match:
            terminator = match.group(2)
    return "\n".join(out)


def _substitutions(text):
    """Bodies of $(...) and `...`, innermost-first enough for policy purposes."""
    found = re.findall(r"\$\(([^()]*)\)", text)
    found += re.findall(r"`([^`]*)`", text)
    return found


# A descriptor duplication such as `2>&1` or `>&-`. Only the `>&N` part is
# matched and rewritten; a descriptor number before it stays in the text.
DUP_REDIRECT = re.compile(r">&(\d+|-)")
PATH_CHARS = frozenset("_./~-")
# A descriptor number written against its redirect (`2>`, `12<`). Splitting
# `<` and `>` into tokens would otherwise leave the number behind as a word,
# and a command judged by its last argument (cp, mv) would read `2` as its
# destination. Which descriptor it is does not matter to the policy, so the
# number is dropped. The single-character lookbehind only lets a run of
# digits start at a word boundary, so the scan stays linear.
FD_NUMBER = re.compile(r"(?<![^\s;&|()<>])\d+(?=[<>])")


def _drop_duplication(match, text):
    """`2>&1` becomes `2>/dev/null`; `>&2x`, a csh-style `>&FILE`, is left for
    the file-redirect rewrite below."""
    following = text[match.end() : match.end() + 1]
    if following and (following.isalnum() or following in PATH_CHARS):
        return match.group(0)
    return ">/dev/null"


def _tokens(text):
    text = FD_NUMBER.sub("", text)
    # Redirections that contain & would otherwise read as the & operator.
    text = DUP_REDIRECT.sub(lambda m: _drop_duplication(m, text), text)
    # `&>file`, `&>>file` and the csh-style `>&file` all send output to a
    # file: rewrite them to `>`/`>>` so the target is checked as one.
    text = text.replace("&>>", ">>").replace("&>", ">")
    text = re.sub(r">&(?=\s*[^\s\d-])", ">", text)
    text = text.replace("\n", " ; ")
    lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|()<>")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError as err:
        raise ParseError(str(err)) from err


def _unwrap(words):
    """Drop leading assignments and wrappers; return (words, env, wrapped)."""
    env, wrapped = {}, False
    words = list(words)
    changed = True
    while words and changed:
        changed = False
        while words and ASSIGNMENT.match(words[0]):
            key, _, value = words.pop(0).partition("=")
            env[key] = value
            changed = True
        if not words:
            break
        head = words[0].rsplit("/", 1)[-1]
        if head in WRAPPERS:
            words.pop(0)
            wrapped = True
            takes_value = WRAPPERS[head]
            while words and words[0].startswith("-") and words[0] != "--":
                flag = words.pop(0)
                if flag in takes_value and words:
                    words.pop(0)
            if words and words[0] == "--":
                words.pop(0)
            for _ in range(WRAPPER_POSITIONAL.get(head, 0)):
                if words:
                    words.pop(0)
            changed = True
    return words, env, wrapped


REDIRECT = re.compile(r"^(\d*)(>>|>\||<<<|<<|<>|>|<)(.*)$")


def _split_redirects(tokens):
    """(words, redirects): words without redirections, and each redirection
    as (operator, target). Heredoc terminators and here-strings are data, so
    they are dropped rather than kept as targets."""
    words, redirects, i = [], [], 0
    while i < len(tokens):
        match = REDIRECT.match(tokens[i])
        if not match:
            words.append(tokens[i])
            i += 1
            continue
        op, target = match.group(2), match.group(3)
        if not target and i + 1 < len(tokens):
            target = tokens[i + 1]
            i += 1
        if op not in ("<<", "<<<"):
            redirects.append((op, target))
        i += 1
    return words, redirects


def segments(command, _depth=0):
    """Yield a Segment for every simple command the line would run."""
    if _depth > 4:
        # Deeper nesting is not read, so it cannot pass as checked.
        raise ParseError("command substitution or eval nested too deep to check")
    text = strip_heredoc_bodies(command)
    for inner in _substitutions(text):
        yield from segments(inner, _depth + 1)
    current = []
    for token in [*_tokens(text), ";"]:
        if token and set(token) <= OPERATOR_CHARS:
            if current:
                plain, redirects = _split_redirects(current)
                words, env, wrapped = _unwrap(plain)
                if words or redirects:
                    seg = Segment(words, env, redirects, wrapped)
                    yield seg
                    nested = _nested_script(seg)
                    if nested is not None:
                        yield from segments(nested, _depth + 1)
            current = []
        else:
            current.append(token)


def _nested_script(seg):
    """The script string of `bash -c '...'` or `eval '...'`, if any."""
    if seg.name in SHELLS:
        for i, word in enumerate(seg.words[1:], start=1):
            if word == "-c" or (word.startswith("-") and not word.startswith("--") and "c" in word):
                return seg.words[i + 1] if i + 1 < len(seg.words) else None
    if seg.name == "eval":
        return " ".join(seg.words[1:])
    return None
