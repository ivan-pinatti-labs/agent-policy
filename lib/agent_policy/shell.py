# SPDX-License-Identifier: Apache-2.0
"""Split a shell command line into simple commands, well enough for policy.

This is not a shell parser. It recognizes the operators an agent actually
writes (&&, ||, ;, |, &, newlines, subshell parentheses), drops heredoc
bodies, looks inside $(...), backticks and `bash -c '...'`, and peels off
reserved words (do, then, !, {...) and wrappers (env, timeout, xargs,
sudo...) so that `do timeout 5 git push ...` is judged as `git push ...`.
When the line cannot be tokenized at all it says so, and the caller
decides how careful to be.
"""

import os
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
# Reserved words that open, continue or close a compound command. In command
# position each is followed by the command that actually runs (`do git push`,
# `then cat`, `! cat`, `{ cat`), so they are dropped like a wrapper is.
RESERVED_PREFIX = {
    "!",
    "{",
    "}",
    "if",
    "then",
    "elif",
    "else",
    "fi",
    "while",
    "until",
    "do",
    "done",
    "esac",
}
# Reserved words whose words up to the next operator run nothing: the loop
# variable and word list of `for` and `select`, the word and first pattern
# of `case`. What they expand ($(...)) is still read, as its own command.
RESERVED_HEADER = {"for", "select", "case"}
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
    """Drop leading reserved words, assignments and wrappers; return
    (words, env, wrapped)."""
    env, wrapped = {}, False
    words = list(words)
    changed = True
    while words and changed:
        changed = False
        if words[0] in RESERVED_HEADER:
            return [], env, wrapped
        if words[0] == "function" and len(words) > 1:
            # `function name { ...`: the name is not a command, the body is.
            del words[:2]
            changed = True
            continue
        while words and words[0] in RESERVED_PREFIX:
            words.pop(0)
            changed = True
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


def segments(command, cwd=None, _depth=0, _known=None):
    """Yield a Segment for every simple command the line would run, with the
    variables the line itself certainly sets substituted where it uses them
    (see Variables), and `$PWD` as `cwd` when it is given."""
    if _depth > 4:
        # Deeper nesting is not read, so it cannot pass as checked.
        raise ParseError("command substitution or eval nested too deep to check")
    text = strip_heredoc_bodies(command)
    raw, current = [], []
    for token in [*_tokens(text), None]:
        if token is None or (token and set(token) <= OPERATOR_CHARS):
            raw.append((current, token))
            current = []
        else:
            current.append(token)
    variables = Variables(text, raw, cwd) if _depth == 0 else None
    # A substitution body is read where it is found in the text, which the
    # tokens do not record, so it gets only what holds on the whole line:
    # the variables set before anything else on it, and $PWD.
    prologue = variables.prologue() if variables else _known
    for inner in _substitutions(text):
        yield from segments(inner, _depth=_depth + 1, _known=prologue)
    for i, (tokens, _) in enumerate(raw):
        if not tokens:
            continue
        plain, redirects = _split_redirects(tokens)
        words, env, wrapped = _unwrap(plain)
        if not (words or redirects):
            continue
        if variables:
            expanded = variables.expand(i, words, env, redirects)
        elif _known:
            expanded = [_substitute(_known, words, env, redirects)]
        else:
            expanded = [(words, env, redirects)]
        for words, env, redirects in expanded:
            seg = Segment(words, env, redirects, wrapped)
            yield seg
            nested = _nested_script(seg)
            if nested is not None:
                yield from segments(nested, _depth=_depth + 1)


def _nested_script(seg):
    """The script string of `bash -c '...'` or `eval '...'`, if any."""
    if seg.name in SHELLS:
        for i, word in enumerate(seg.words[1:], start=1):
            if word == "-c" or (word.startswith("-") and not word.startswith("--") and "c" in word):
                return seg.words[i + 1] if i + 1 < len(seg.words) else None
    if seg.name == "eval":
        return " ".join(seg.words[1:])
    return None


# Variables
#
# A path written through a variable the line itself sets (`S=/tmp/x; cat
# $S/out`) is judged at the value it holds, so the guard need not ask about
# it. The rule is that a substituted line gets exactly the verdict the same
# line gets with the value written out, so a variable is substituted only
# where the value it holds there is certain:
#
# - It is set once on the whole line, by an assignment that is a statement
#   of its own, at the top level (not in a subshell, a loop, a condition, a
#   group or a function), that runs whatever ran before it (it follows `;`,
#   a newline or the start of the line, never `&&` or `||`) and is not sent
#   to the background or into a pipe. Its uses after that statement are
#   substituted, the ones before it are not.
# - Or it is the variable of a `for` loop over literal words, and is used in
#   that loop's body: each use is judged once per word.
# - Its value is literal: letters, digits and `_./:@%+,=-` once the line's
#   other certain variables are substituted. No space, glob, quote, `~` or
#   `$` is left, so word splitting and globbing cannot change what the shell
#   makes of it.
# - Nothing else on the line could change it: no second assignment (an
#   array element or `+=` included), no `read`, `unset`, `export`,
#   `declare`, `local`, `readonly`, `printf -v`, `mapfile` or the like
#   naming it, and no `eval`, `source` or `.` (which could set anything) and
#   no assignment to IFS (which changes word splitting) anywhere on the line.
# - It is never written inside single quotes or with an escaped `$`, where
#   the shell does not expand it: the tokens no longer record the quoting, so
#   one such use rules the name out everywhere.
#
# `$PWD` is the working directory the hook was given, unless the line runs
# `cd`, `pushd` or `popd`. HOME is never taken from the line. Anything else
# (a value from `$(...)`, from the environment, `${NAME:-x}` and other
# operators) stays unresolved, so the guard still asks about the path.

LITERAL = re.compile(r"^[A-Za-z0-9_./:@%+,=-]+$")
NAME_RE = r"[A-Za-z_][A-Za-z0-9_]*"
SETTERS = {
    "read",
    "unset",
    "export",
    "declare",
    "typeset",
    "local",
    "readonly",
    "printf",
    "mapfile",
    "readarray",
    "getopts",
    "let",
    "select",
    "for",
    "wait",
    "coproc",
}
# Commands that could set any variable: eval and source run code the line
# does not show, and declare, typeset and local can make a name a reference
# to another (-n), so an assignment to one changes the other.
ANYTHING_SETTERS = {"eval", "source", ".", "declare", "typeset", "local"}
# Never taken from the line: HOME is the guard's own, the others are set by
# the shell itself, are read only, or change how the line runs.
NEVER_RESOLVED = {
    "HOME",
    "PWD",
    "OLDPWD",
    "PATH",
    "IFS",
    "RANDOM",
    "SRANDOM",
    "SECONDS",
    "LINENO",
    "EPOCHSECONDS",
    "EPOCHREALTIME",
    "BASHPID",
    "PPID",
    "UID",
    "EUID",
    "GROUPS",
    "HISTCMD",
    "FUNCNAME",
    "SHELLOPTS",
    "BASHOPTS",
    "CDPATH",
}
OPENERS = {"if", "while", "until", "case", "for", "select"}
CLOSERS = {"fi", "done", "esac"}
DIR_CHANGERS = {"cd", "pushd", "popd"}
LOOP_LIMIT = 16
EXPANSION_LIMIT = 32


def _not_expanded(text):
    """Names written where the shell does not expand them: inside single
    quotes (or $'...'), or after a backslash."""
    names, quote, i = set(), None, 0
    while i < len(text):
        ch = text[i]
        if quote == "'":
            if ch == "'":
                quote = None
            elif ch == "$":
                match = re.match(r"\$\{?(" + NAME_RE + ")", text[i:])
                if match:
                    names.add(match.group(1))
        elif ch == "\\":
            match = re.match(r"\\\$\{?(" + NAME_RE + ")", text[i:])
            if match:
                names.add(match.group(1))
            i += 1
        elif ch == '"':
            quote = None if quote == '"' else '"'
        elif ch == "'" and quote is None:
            quote = "'"
        i += 1
    return names


def _substitute_word(word, known):
    def value(match):
        name = match.group(1) or match.group(2)
        return known.get(name, match.group(0))

    return re.sub(r"\$\{(" + NAME_RE + r")\}|\$(" + NAME_RE + ")(?![A-Za-z0-9_])", value, word)


def _substitute(known, words, env, redirects):
    return (
        [_substitute_word(w, known) for w in words],
        {k: _substitute_word(v, known) for k, v in env.items()},
        [(op, _substitute_word(t, known)) for op, t in redirects],
    )


class Variables:
    """What the line's own variables certainly hold, statement by statement."""

    def __init__(self, text, raw, cwd):
        self.text, self.raw = text, raw
        self.ruled_out = _not_expanded(text) | NEVER_RESOLVED
        heads = [_head(tokens) for tokens, _ in raw]
        self.disabled = any(h in ANYTHING_SETTERS for h in heads) or bool(
            re.search(r"(?<![A-Za-z0-9_$-])IFS(\+?=|\[)", text)
        )
        base = {}
        if (
            cwd
            and os.path.isabs(cwd)
            and LITERAL.match(cwd)
            and "PWD" not in _not_expanded(text)
            and not any(h in DIR_CHANGERS for h in heads)
            and self._set_count("PWD") == 0
        ):
            base["PWD"] = cwd
        self.prologue_known = {}
        self.known_at, self.loops_at = [], []
        if not self.disabled:
            self._walk(base)

    def _set_count(self, name):
        """How many places on the line could set `name`."""
        pattern = r"(?<![A-Za-z0-9_$-])" + re.escape(name) + r"(\+?=|\[)"
        count = len(re.findall(pattern, self.text))
        for tokens, _ in self.raw:
            words = _skip_reserved(tokens)
            if words and words[0] in SETTERS and name in words[1:]:
                count += 1
        return count

    def _walk(self, base):
        known, loops = dict(base), []
        depth = parens = 0
        prev_op, pending_loop, prologue_open = None, None, True
        self.prologue_known = dict(base)
        for tokens, op in self.raw:
            lead = _leading_reserved(tokens)
            # A loop body starts at its `do` and ends at its `done`, both of
            # which lead the segment they open or close.
            for word in lead:
                if word == "do":
                    loops.append(pending_loop)
                    pending_loop = None
                elif word == "done" and loops:
                    loops.pop()
            self.known_at.append(dict(known))
            self.loops_at.append([scope for scope in loops if scope])
            depth += sum(w in OPENERS for w in lead) - sum(w in CLOSERS for w in lead)
            depth += tokens.count("{") - tokens.count("}")
            depth = max(depth, 0)
            if "for" in lead:
                pending_loop = self._loop(tokens[lead.index("for") :], known)
            op_chars = (op or "").replace("(", "").replace(")", "")
            recorded = False
            if (
                tokens
                and all(ASSIGNMENT.match(t) for t in tokens)
                and depth == 0
                and parens == 0
                and prev_op in (None, ";")
                and op_chars in ("", ";", "&&")
                and "(" not in (op or "")
            ):
                recorded = True
                for token in tokens:
                    name, _, value = token.partition("=")
                    value = _substitute_word(value, known)
                    if (
                        LITERAL.match(value)
                        and name not in self.ruled_out
                        and self._set_count(name) == 1
                    ):
                        known[name] = value
                    else:
                        recorded = False
            # The prologue is the run of statements, from the start of the
            # line, that each set every variable in them to a certain value.
            if prologue_open and (tokens or op):
                if recorded:
                    self.prologue_known = {**base, **known}
                else:
                    prologue_open = False
            if op:
                parens = max(parens + op.count("(") - op.count(")"), 0)
            prev_op = op_chars if op is not None else None

    def _loop(self, tokens, known):
        """{name: [values]} for `for NAME in WORD...`, when it is certain."""
        if len(tokens) < 3 or tokens[2] != "in" or not re.fullmatch(NAME_RE, tokens[1]):
            return None
        name, words = tokens[1], [_substitute_word(w, known) for w in tokens[3:]]
        if (
            not words
            or len(words) > LOOP_LIMIT
            or not all(LITERAL.match(w) for w in words)
            or name in self.ruled_out
            or self._set_count(name) != 1
        ):
            return None
        return {name: words}

    def prologue(self):
        """The variables certain on the whole line: set before anything else."""
        return {} if self.disabled else dict(self.prologue_known)

    def expand(self, i, words, env, redirects):
        """The segment at index i with its certain variables substituted:
        one copy, or one per combination of the loop words it uses."""
        if self.disabled:
            return [(words, env, redirects)]
        choices = [{}]
        joined = " ".join([*words, *env.values(), *(t for _, t in redirects)])
        for scope in self.loops_at[i]:
            for name, values in scope.items():
                if re.search(r"\$\{?" + name + r"(?![A-Za-z0-9_])", joined):
                    choices = [{**c, name: v} for c in choices for v in values]
        if len(choices) > EXPANSION_LIMIT:
            choices = [{}]
        known = self.known_at[i]
        return [_substitute({**known, **choice}, words, env, redirects) for choice in choices]


def _leading_reserved(tokens):
    lead = []
    for token in tokens:
        if token not in RESERVED_PREFIX and token not in RESERVED_HEADER:
            break
        lead.append(token)
        if token in RESERVED_HEADER:
            break
    return lead


def _skip_reserved(tokens):
    words = list(tokens)
    while words and (words[0] in RESERVED_PREFIX or ASSIGNMENT.match(words[0])):
        words.pop(0)
    return words


def _head(tokens):
    words, _, _ = _unwrap(_split_redirects(tokens)[0])
    return words[0].rsplit("/", 1)[-1] if words else ""
