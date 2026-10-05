# SPDX-License-Identifier: Apache-2.0
"""The checks a command prefix cannot express.

evaluate() returns the single worst Finding for a command line, or None.
Every Finding carries a severity from the scale in docs/POLICY.md; the
decision (allow, ask, deny) follows from it. The guard never emits allow
findings, so in practice a finding is moderate or high (ask) or severe or
critical (deny, a hand-off to the user).
"""

import os
import re
from dataclasses import dataclass

from . import containers
from .shell import ParseError, segments

# severity -> (decision, rank). Higher rank wins when several fire. Kept in
# step with tools/render.py's SEVERITY map and docs/POLICY.md.
SEVERITY = {
    "read": ("allow", 0),
    "low": ("allow", 1),
    "moderate": ("ask", 2),
    "high": ("ask", 3),
    "severe": ("deny", 4),
    "critical": ("deny", 5),
}
HOOK_BYPASS_ENV = {"HUSKY": "0", "PRE_COMMIT_ALLOW_NO_CONFIG": None, "SKIP": None}


@dataclass
class Finding:
    severity: str
    reason: str

    @property
    def decision(self):
        return SEVERITY[self.severity][0]

    @property
    def rank(self):
        return SEVERITY[self.severity][1]


def evaluate(command, cwd, env=None, inspector=containers.inspect):
    env = os.environ if env is None else env
    home = env.get("HOME", os.path.expanduser("~"))
    ctx = {
        "cwd": cwd or os.getcwd(),
        "home": home,
        "env": env,
        "inspect": inspector,
        "protected": containers.protected_paths(env),
    }
    try:
        segs = list(segments(command))
    except ParseError:
        return Finding("high", "the command line could not be parsed, so it was not checked")
    worst = None
    for seg in segs:
        for finding in _check(seg, ctx):
            if worst is None or finding.rank > worst.rank:
                worst = finding
    return worst


# Commands whose path arguments are read. Copy, move, sync and archive tools
# are here too: their source is read, so a credential path anywhere among
# their arguments is caught, not only the destination _writer checks.
READERS = {
    "cp",
    "mv",
    "install",
    "rsync",
    "scp",
    "ln",
    "dd",
    "tar",
    "zip",
    "gzip",
    "bzip2",
    "xz",
    "zstd",
    "7z",
    "7za",
    "cpio",
    "split",
    "cat",
    "bat",
    "base64",
    "base32",
    "head",
    "tail",
    "xxd",
    "od",
    "hexdump",
    "strings",
    "openssl",
    "less",
    "more",
    "nl",
    "tac",
    "rev",
    "cut",
    "cmp",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "b2sum",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "awk",
    "gawk",
    "sort",
    "uniq",
    "column",
    "fold",
    "fmt",
    "gpg",
}
WRITERS = {"cp", "mv", "install", "rsync", "ln", "tee", "dd", "truncate", "sed", "yq", "jq"}


def _check(seg, ctx):
    yield from _hook_bypass_env(seg)
    yield from _redirects(seg, ctx)
    if seg.name in ("mount", "umount", "sshfs", "bindfs") or (
        seg.name == "rclone" and seg.words[1:2] == ["mount"]
    ):
        yield from _mount(seg, ctx)
    if seg.name in READERS:
        yield from _reader(seg, ctx)
    if seg.name in WRITERS:
        yield from _writer(seg, ctx)
    handler = {
        "git": _git,
        "gh": _gh,
        "curl": _curl,
        "wget": _wget,
        "rm": _rm,
        "aws": _aws,
        "podman": _engine,
        "docker": _engine,
        "podman-compose": _compose,
        "docker-compose": _compose,
    }.get(seg.name)
    if handler:
        yield from handler(seg, ctx)


# Redirections

OUTPUT_REDIRECTS = (">", ">>", ">|", "<>")
INPUT_REDIRECTS = ("<", "<>")


def _redirects(seg, ctx):
    """Check each redirection's target: a write through `>` is judged like
    any other write, and a read through `<` like any other read."""
    for op, target in seg.redirects:
        if target.startswith(("/dev/tcp/", "/dev/udp/")):
            yield Finding("high", f"redirects to a network socket ({target})")
            continue
        if target in ("/dev/null", "/dev/stdout", "/dev/stderr") or target.startswith("&"):
            continue
        if _unresolved(target):
            yield Finding("high", f"redirects to {target}, a path this guard cannot resolve")
            continue
        path = containers.expand(target, ctx["cwd"], ctx["home"])
        if op in INPUT_REDIRECTS:
            cred = containers.credential_target(path, ctx["home"])
            if cred:
                yield Finding(
                    "critical", f"reads {cred} through a redirect, which holds credentials"
                )
                continue
        if op in OUTPUT_REDIRECTS:
            finding = _write_finding(path, ctx)
            if finding:
                yield finding


# Mounts

MOUNT_WITH_VALUE = {
    "-t",
    "--types",
    "-o",
    "--options",
    "-L",
    "--label",
    "-U",
    "--uuid",
    "--source",
    "--target",
    "-O",
    "--test-opts",
    "-N",
    "--namespace",
}


def _mount(seg, ctx):
    name = seg.name
    args = seg.words[2:] if name == "rclone" else seg.words[1:]
    positional, i = [], 0
    while i < len(args):
        arg = args[i]
        if arg in MOUNT_WITH_VALUE:
            i += 2
            continue
        if not arg.startswith("-"):
            positional.append(arg)
        i += 1
    home = ctx["home"]
    if name == "umount":
        targets, source = positional, None
    elif len(positional) >= 2:
        source, targets = positional[0], [positional[-1]]
    else:
        source, targets = None, positional
    # sshfs and rclone sources are remotes (host:path, remote:path).
    if source and name in ("mount", "bindfs") and containers.is_host_path(source):
        cred = containers.credential_target(containers.expand(source, ctx["cwd"], home), home)
        if cred:
            yield Finding(
                "critical", f"{name} exposes {cred}, which holds credentials, at another path"
            )
            return
    for target in targets:
        path = containers.expand(target, ctx["cwd"], home)
        cred = containers.credential_target(path, home)
        runs = containers.exec_target(path, ctx["cwd"], home)
        if cred and name != "umount":
            yield Finding("critical", f"{name} mounts over {cred}, which holds credentials")
        elif runs and name != "umount":
            yield Finding("critical", f"{name} mounts over {runs}")
        elif any(containers.under(path, root) for root in ctx["protected"]):
            yield Finding("severe", f"{name} acts inside a protected deployment")
        elif name != "umount" and (path == home or containers.under(home, path)):
            yield Finding("severe", f"{name} mounts over the home folder or a parent of it")


# Reading and writing files


def _paths(words):
    """Non-flag tokens, plus the value of an if=/of= argument."""
    for word in words:
        if word.startswith(("if=", "of=")):
            yield word.split("=", 1)[1]
        elif not word.startswith("-"):
            yield word


# Shell expansion the guard cannot evaluate: $(...), backticks, ${...} and
# $NAME. `$HOME`, `${HOME}` and `~` at the start are expanded, so they are not
# counted; a `$` not followed by a name (a regex anchor) is not one. A lone
# `$` is what `$(...)` leaves once the line is split around the parentheses.
UNRESOLVED = re.compile(r"\$\(|`|\$\{|\$[A-Za-z_]")
# Commands whose first operand is a pattern or program, not a path.
PATTERN_FIRST = {"grep", "egrep", "fgrep", "rg", "awk", "gawk", "sed"}


def _unresolved(word):
    word = word[containers.home_prefix(word) :]
    return word == "$" or bool(UNRESOLVED.search(word))


# How the commands whose first operand is a pattern or program take their
# options: which short letters and long names supply that pattern (so the
# first operand is a file after all), which name a file to read, and which
# take a value that is neither.
PROGRAM_OPTIONS = {
    "grep": (
        "e",
        "f",
        "mABCdD",
        ("--regexp",),
        ("--file",),
        (
            "--max-count",
            "--after-context",
            "--before-context",
            "--context",
            "--label",
            "--include",
            "--exclude",
            "--exclude-dir",
            "--devices",
            "--directories",
        ),
    ),
    "rg": (
        "e",
        "f",
        "mABCgtTMjEr",
        ("--regexp",),
        ("--file",),
        (
            "--max-count",
            "--after-context",
            "--before-context",
            "--context",
            "--glob",
            "--iglob",
            "--type",
            "--type-not",
            "--max-columns",
            "--threads",
            "--encoding",
            "--replace",
            "--max-depth",
            "--max-filesize",
        ),
    ),
    "sed": ("e", "f", "l", ("--expression",), ("--file",), ("--line-length",)),
    "awk": ("e", "f", "vF", ("--source",), ("--file",), ("--assign", "--field-separator")),
}
PROGRAM_OPTIONS["egrep"] = PROGRAM_OPTIONS["fgrep"] = PROGRAM_OPTIONS["grep"]
PROGRAM_OPTIONS["gawk"] = PROGRAM_OPTIONS["awk"]


def _program_operands(name, args):
    """The file operands of grep, rg, sed or awk: files named by -f, then the
    positional operands without the leading pattern or program, unless an
    option supplied it. Attached (-ePAT, -fFILE, --file=FILE), separate and
    clustered (-ie PAT) forms are all read."""
    pattern, file_, valued, long_pattern, long_file, long_valued = PROGRAM_OPTIONS[name]
    files, positional, supplied, i, done = [], [], False, 0, False
    while i < len(args):
        arg = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else None
        if done or arg == "-" or not arg.startswith("-"):
            positional.append(arg)
        elif arg == "--":
            done = True
        elif arg.startswith("--"):
            opt, eq, value = arg.partition("=")
            if opt in long_pattern or opt in long_file or opt in long_valued:
                if not eq:
                    value, i = nxt, i + 1
                if opt in long_pattern:
                    supplied = True
                elif opt in long_file:
                    supplied = True
                    if value is not None:
                        files.append(value)
        else:
            for j, letter in enumerate(arg[1:], start=1):
                if name == "sed" and letter == "i":
                    break  # -i[SUFFIX]: the rest is the suffix
                if letter in pattern or letter in file_ or letter in valued:
                    value = arg[j + 1 :] or nxt
                    if not arg[j + 1 :]:
                        i += 1
                    if letter in pattern:
                        supplied = True
                    elif letter in file_:
                        supplied = True
                        if value is not None:
                            files.append(value)
                    break
        i += 1
    if not supplied and positional:
        positional = positional[1:]
    return files + positional


def _operands(seg):
    """The path operands of a reader."""
    if seg.name in PROGRAM_OPTIONS:
        return _program_operands(seg.name, seg.words[1:])
    return list(_paths(seg.words[1:]))


def _reader(seg, ctx):
    # Every operand is checked: an unresolvable one asks, and a credential
    # path after it still earns its own (stricter) finding.
    for token in _operands(seg):
        if _unresolved(token):
            yield Finding("high", f"{seg.name} reads {token}, a path this guard cannot resolve")
            continue
        path = containers.expand(token, ctx["cwd"], ctx["home"])
        cred = containers.credential_target(path, ctx["home"])
        if cred:
            yield Finding("critical", f"{seg.name} reads {cred}, which holds credentials")


def _writer(seg, ctx):
    args = seg.words[1:]
    name = seg.name
    if name in ("cp", "mv", "install", "rsync", "ln"):
        dests = list(_paths(args))[-1:]
    elif name in ("tee", "truncate"):
        dests = list(_paths(args))
    elif name == "dd":
        dests = [a.split("=", 1)[1] for a in args if a.startswith("of=")]
    elif name == "sed":
        in_place = any(
            a == "--in-place"
            or a.startswith("--in-place=")
            or (a.startswith("-") and not a.startswith("--") and "i" in a[1:])
            for a in args
        )
        dests = _program_operands("sed", args) if in_place else []
    elif name in ("yq", "jq"):
        dests = list(_paths(args)) if any(a in ("-i", "--in-place") for a in args) else []
    else:
        dests = []
    for token in dests:
        if _unresolved(token):
            yield Finding("high", f"{name} writes {token}, a path this guard cannot resolve")
            continue
        path = containers.expand(token, ctx["cwd"], ctx["home"])
        finding = _write_finding(path, ctx)
        if finding:
            yield finding


def _write_finding(path, ctx):
    cred = containers.credential_target(path, ctx["home"])
    if cred:
        return Finding("critical", f"overwrites {cred}, which holds credentials")
    runs = containers.exec_target(path, ctx["cwd"], ctx["home"])
    if runs:
        return Finding("critical", f"writes {runs}")
    for root in ctx["protected"]:
        if containers.under(path, root):
            return Finding("critical", f"writes inside the protected deployment {root}")
    return None


# git

GIT_GLOBAL_WITH_VALUE = {
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--config-env",
    "--super-prefix",
    "--exec-path",
}


def _hook_bypass_env(seg):
    if seg.name not in ("git", "pre-commit"):
        return
    for key, bad in HOOK_BYPASS_ENV.items():
        if key in seg.env and (bad is None or seg.env[key] == bad):
            yield Finding("critical", f"sets {key} to skip the git hooks")


def _split_git(words):
    i, config, config_env = 1, [], False
    while i < len(words) and words[i].startswith("-"):
        flag = words[i]
        if flag == "--config-env" or flag.startswith("--config-env="):
            config_env = True
            i += 1 if "=" in flag else 2
        elif flag in GIT_GLOBAL_WITH_VALUE:
            if flag == "-c" and i + 1 < len(words):
                config.append(words[i + 1])
            i += 2
        else:
            if flag.startswith("-c") and len(flag) > 2:
                config.append(flag[2:])
            i += 1
    if i >= len(words):
        return None, [], config, config_env
    return words[i], words[i + 1 :], config, config_env


def _short_cluster(arg):
    return arg.startswith("-") and not arg.startswith("--") and len(arg) > 1


def _dangerous_git_config(key):
    k = key.lower().split("=", 1)[0]
    if k.startswith(
        (
            "core.hookspath",
            "core.sshcommand",
            "core.pager",
            "core.editor",
            "core.fsmonitor",
            "core.askpass",
            "credential.helper",
            "sequence.editor",
            "gpg.program",
            "gpg.ssh.program",
            "uploadpack.packobjectshook",
            "diff.external",
            "alias.",
        )
    ):
        return True
    return k.endswith((".external", ".textconv", ".process"))


def _git(seg, ctx):
    sub, args, config, config_env = _split_git(seg.words)
    if config_env:
        yield Finding("critical", "git --config-env passes config this guard cannot read")
    for item in config:
        if item.lower().startswith("core.hookspath"):
            yield Finding("critical", "overrides core.hooksPath to skip the git hooks")
        elif _dangerous_git_config(item):
            yield Finding("critical", f"sets a git config that runs an external command ({item})")
    if sub is None:
        return
    if sub == "push":
        yield from _git_push(args)
    elif sub == "commit":
        yield from _git_commit(args)
    elif sub in ("filter-branch", "filter-repo"):
        yield Finding("severe", f"git {sub} rewrites history")
    elif sub == "reset" and "--hard" in args:
        if any(a.startswith(("origin/", "upstream/", "@{u", "@{upstream")) for a in args):
            yield Finding("severe", "git reset --hard onto a remote branch discards local commits")
        else:
            yield Finding("high", "git reset --hard discards uncommitted work")
    elif sub == "clean" and any(a == "--force" or (_short_cluster(a) and "f" in a) for a in args):
        yield Finding("high", "git clean deletes untracked files")
    elif sub == "checkout" and any(
        a in ("--", ".", "-f", "--force", "--ours", "--theirs") for a in args
    ):
        yield Finding("high", "this git checkout overwrites changes in the working tree")
    elif sub == "restore" and (
        "--staged" not in args or any(a in ("-W", "--worktree") for a in args)
    ):
        yield Finding("high", "git restore discards changes in the working tree")
    elif sub == "branch" and any(
        a in ("-D", "-M", "-C", "--force")
        or (_short_cluster(a) and ("D" in a or ("d" in a and "f" in a)))
        for a in args
    ):
        yield Finding("high", "force-deletes or overwrites a branch")
    elif sub == "tag" and any(a in ("-d", "--delete", "-f", "--force") for a in args):
        yield Finding("high", "deletes or moves a tag")
    elif sub == "stash" and args[:1] and args[0] in ("drop", "clear"):
        yield Finding("high", f"git stash {args[0]} throws stashed work away")
    elif sub == "remote" and args[:1] and args[0] in ("remove", "rm", "set-url", "rename", "add"):
        yield Finding("high", f"git remote {args[0]} changes where this clone pushes")
    elif sub == "worktree" and args[:1] == ["remove"] and any(a in ("-f", "--force") for a in args):
        yield Finding("high", "force-removes a worktree, with any uncommitted work in it")
    elif sub in ("update-ref", "replace") or (sub == "reflog" and args[:1] == ["expire"]):
        yield Finding("high", f"git {sub} rewrites refs directly")
    elif (
        sub == "config"
        and any(_dangerous_git_config(a) for a in args)
        and len([a for a in args if not a.startswith("-")]) > 1
    ):
        yield Finding("critical", "sets a git config that runs an external command or skips hooks")


PUSH_WITH_VALUE = {"-o", "--push-option", "--repo", "--receive-pack", "--exec"}
PUSH_DESTRUCTIVE = {
    "--force",
    "--force-with-lease",
    "--force-if-includes",
    "--mirror",
    "--delete",
    "--prune",
}


def _looks_like_url(ref):
    return "://" in ref or (":" in ref and "@" in ref.split(":", 1)[0])


def _git_push(args):
    positional, i = [], 0
    while i < len(args):
        arg = args[i]
        if arg in PUSH_WITH_VALUE:
            i += 2
            continue
        if arg == "--no-verify":
            yield Finding("critical", "git push --no-verify skips the pre-push hooks")
        elif arg.split("=", 1)[0] in PUSH_DESTRUCTIVE:
            yield Finding(
                "severe", f"git push {arg.split('=', 1)[0]} can overwrite or delete remote history"
            )
        elif _short_cluster(arg) and ("f" in arg or "d" in arg):
            yield Finding("severe", f"git push {arg} forces or deletes on the remote")
        elif arg in ("--tags",):
            yield Finding("moderate", "git push --tags pushes tags, which can start a release")
        elif not arg.startswith("-"):
            positional.append(arg)
        i += 1
    if positional and _looks_like_url(positional[0]):
        yield Finding(
            "high", f"pushes to an explicit URL ({positional[0]}), not a configured remote"
        )
    for refspec in positional[1:]:
        if refspec.startswith("+"):
            yield Finding("severe", f"the refspec {refspec} force-pushes")
        elif refspec.startswith(":"):
            yield Finding("severe", f"the refspec {refspec} deletes a remote branch")
        elif refspec.split(":")[-1].split("/")[-1] in ("main", "master") and ":" in refspec:
            yield Finding("high", f"pushes directly to {refspec.split(':')[-1]}")


COMMIT_WITH_VALUE = set("mFCct")


def _git_commit(args):
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--no-verify":
            yield Finding("critical", "git commit --no-verify skips the pre-commit hooks")
        elif _short_cluster(arg):
            for char in arg[1:]:
                if char == "n":
                    yield Finding("critical", "git commit -n skips the pre-commit hooks")
                    break
                if char in COMMIT_WITH_VALUE:
                    if arg.endswith(char):
                        i += 1
                    break
        elif arg in (
            "--message",
            "--file",
            "--author",
            "--date",
            "--template",
            "--fixup",
            "--squash",
            "--trailer",
            "--cleanup",
            "--reuse-message",
            "--reedit-message",
        ):
            i += 1
        i += 1


# GitHub CLI


def _gh(seg, ctx):
    args = seg.words[1:]
    if args[:1] == ["api"]:
        yield from _gh_api(args[1:])
    elif args[:2] == ["pr", "merge"] and "--admin" in args:
        yield Finding("severe", "gh pr merge --admin skips the merge queue and branch protection")
    elif args[:2] == ["repo", "delete"]:
        yield Finding("severe", "gh repo delete removes the repository")
    elif args[:2] == ["auth", "token"]:
        yield Finding("critical", "gh auth token prints the GitHub token")
    elif args[:2] == ["auth", "status"] and any(
        a in ("-t", "--show-token") or (_short_cluster(a) and "t" in a) for a in args[2:]
    ):
        yield Finding("critical", "gh auth status --show-token prints the GitHub token")


GH_FIELD_FLAGS = ("-f", "-F", "--field", "--raw-field", "--input")


def _gh_api(args):
    method, has_body, mutation, body_from_file = None, False, False, False
    for i, arg in enumerate(args):
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if arg in ("-X", "--method"):
            method = nxt
        elif arg.startswith("--method="):
            method = arg.split("=", 1)[1]
        elif arg.startswith("-X") and len(arg) > 2:
            method = arg[2:]
        elif (
            arg in GH_FIELD_FLAGS
            or arg.startswith(("--field=", "--raw-field=", "--input="))
            or (arg[:2] in ("-f", "-F") and len(arg) > 2)
        ):
            has_body = True
            value = nxt if arg in GH_FIELD_FLAGS else arg.split("=", 1)[-1]
            if "mutation" in value:
                mutation = True
            if "@" in value:
                body_from_file = True
    if "graphql" in args:
        if mutation:
            yield Finding("moderate", "a GraphQL mutation changes data on GitHub")
        elif body_from_file:
            yield Finding("moderate", "a GraphQL query read from a file may be a mutation")
        return
    if method is None:
        method = "POST" if has_body else "GET"
    if method.upper() not in ("GET", "HEAD"):
        yield Finding("moderate", f"gh api {method.upper()} changes data on GitHub")


# HTTP clients

CURL_BODY = (
    "-d",
    "--data",
    "--data-ascii",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "--json",
    "-F",
    "--form",
    "--form-string",
    "-T",
    "--upload-file",
)


def _curl_outputs(args):
    """Every local path curl would write: -o/--output in any spelling, and
    --output-dir, where -O and --remote-name-all write."""
    for i, arg in enumerate(args):
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if arg in ("-o", "--output", "--output-dir") and nxt:
            yield nxt
        elif arg.startswith(("--output=", "--output-dir=")):
            yield arg.split("=", 1)[1]
        elif _short_cluster(arg) and "o" in arg[1:]:
            # -ofile, or a cluster such as -sSLo with the path next.
            rest = arg[arg.index("o", 1) + 1 :]
            if rest:
                yield rest
            elif nxt:
                yield nxt


def _curl(seg, ctx):
    method = None
    for target in _curl_outputs(seg.words[1:]):
        finding = _write_finding(containers.expand(target, ctx["cwd"], ctx["home"]), ctx)
        if finding:
            yield finding
            return
    for i, arg in enumerate(seg.words[1:], start=1):
        nxt = seg.words[i + 1] if i + 1 < len(seg.words) else ""
        if arg in ("-X", "--request"):
            method = nxt
        elif arg.startswith("--request="):
            method = arg.split("=", 1)[1]
        elif arg.startswith("-X") and len(arg) > 2:
            method = arg[2:]
        elif arg.split("=", 1)[0] in CURL_BODY or (arg[:2] in ("-d", "-F", "-T") and len(arg) > 2):
            yield Finding("moderate", "curl sends a request body")
            return
    if method and method.upper() not in ("GET", "HEAD", "OPTIONS"):
        yield Finding("moderate", f"curl {method.upper()} changes data on the server")


def _wget(seg, ctx):
    if any(
        a.startswith(("--post-data", "--post-file", "--method", "--body-data", "--body-file"))
        for a in seg.words[1:]
    ):
        yield Finding("moderate", "wget sends a request that changes data on the server")


# rm


def _rm(seg, ctx):
    args = seg.words[1:]
    recursive = any(
        a in ("-r", "-R", "--recursive") or (_short_cluster(a) and ("r" in a or "R" in a))
        for a in args
    )
    if "--no-preserve-root" in args:
        yield Finding("critical", "rm --no-preserve-root")
        return
    if not recursive:
        return
    home = ctx["home"]
    targets = [a for a in args if not a.startswith("-")]
    for target in targets:
        if target in ("*", "/*", "~/*", "$HOME/*", "${HOME}/*", ".*"):
            yield Finding("severe", f"rm -r {target} matches far more than a project")
            continue
        path = containers.expand(target, ctx["cwd"], home)
        if path == "/" or containers.under(home, path):
            yield Finding(
                "severe", f"rm -r {target} removes the home folder or everything above it"
            )
        elif containers.credential_target(path, home):
            yield Finding("critical", f"rm -r {target} removes credentials")
        elif any(containers.under(path, root) for root in ctx["protected"]):
            yield Finding("severe", f"rm -r {target} is inside a protected deployment")


# AWS CLI

AWS_VALUE_GLOBALS = {
    "--region",
    "--profile",
    "--output",
    "--endpoint-url",
    "--ca-bundle",
    "--cli-read-timeout",
    "--cli-connect-timeout",
    "--color",
    "--query",
    "--page-size",
    "--max-items",
    "--starting-token",
}
AWS_READ_PREFIXES = ("describe-", "list-", "get-", "head-", "lookup-", "search-", "batch-get-")
AWS_SECRET_READS = {
    "get-secret-value",
    "get-login-password",
    "get-session-token",
    "get-federation-token",
    "get-authorization-token",
    "decrypt",
}
AWS_IRREVERSIBLE = {"schedule-key-deletion", "delete-secret"}


def _aws(seg, ctx):
    service, op = _aws_service_op(seg.words[1:])
    if service is None or op is None:
        return
    rest = seg.words[1:]
    if service == "s3":
        if op == "rm" and "--recursive" in rest:
            yield Finding("severe", "aws s3 rm --recursive deletes every matching object")
        elif op == "rb" and "--force" in rest:
            yield Finding("severe", "aws s3 rb --force deletes a bucket and its contents")
        elif op in ("cp", "mv", "rm", "rb", "mb", "sync"):
            yield Finding("moderate", f"aws s3 {op} changes stored objects")
        return
    if op in AWS_IRREVERSIBLE or (op.startswith("delete-") and "--skip-final-snapshot" in rest):
        yield Finding("severe", f"aws {service} {op} cannot be undone")
    elif op in AWS_SECRET_READS:
        yield Finding("high", f"aws {service} {op} returns a secret value")
    elif op.startswith("get-parameter") and "--with-decryption" in rest:
        yield Finding("high", f"aws {service} {op} --with-decryption returns a secret value")
    elif op.startswith(AWS_READ_PREFIXES):
        return
    else:
        yield Finding("moderate", f"aws {service} {op} changes AWS resources")


def _aws_service_op(words):
    i, found = 0, []
    while i < len(words) and len(found) < 2:
        word = words[i]
        if word.startswith("-"):
            if word in AWS_VALUE_GLOBALS:
                i += 2
                continue
            i += 1
            continue
        found.append(word)
        i += 1
    if len(found) < 2:
        return (found[0] if found else None), None
    return found[0], found[1]


# container engines

ENGINE_TARGETED = {
    "stop",
    "kill",
    "rm",
    "restart",
    "exec",
    "pause",
    "unpause",
    "update",
    "rename",
    "start",
    "attach",
    "cp",
    "commit",
    "export",
}
ENGINE_WITH_VALUE = {
    "-t",
    "--time",
    "-s",
    "--signal",
    "-e",
    "--env",
    "--env-file",
    "-w",
    "--workdir",
    "-u",
    "--user",
    "--detach-keys",
    "--preserve-fds",
    "--depend",
    "--cidfile",
    "--filter",
}
COMPOSE_READ_ONLY = {"ps", "logs", "config", "images", "top", "version", "ls", "port", "events"}


def _engine(seg, ctx):
    engine = seg.name
    args = seg.words[1:]
    if args and args[0].startswith("-") and args[0] not in ("--version", "-v", "--help", "-h"):
        yield Finding("high", f"{engine} {args[0]} changes which engine or storage is used")
        return
    if args[:1] == ["container"]:
        args = args[1:]
    if not args:
        return
    sub, rest = args[0], args[1:]
    if sub == "compose":
        yield from _compose(seg, ctx, rest)
    elif sub in ("run", "create"):
        for severity, reason in containers.run_findings(
            rest, ctx["cwd"], ctx["home"], ctx["protected"]
        ):
            yield Finding(severity, f"{engine} {sub} {reason}")
    elif sub == "cp":
        yield from _engine_cp(engine, rest, ctx)
    elif sub in ENGINE_TARGETED:
        yield from _targeted(engine, sub, rest, ctx)


def _engine_cp(engine, rest, ctx):
    dests = [a for a in rest if not a.startswith("-")]
    # podman cp SRC DEST; a host DEST has no leading "container:".
    for token in dests[1:]:
        if ":" in token.split("/", 1)[0]:
            continue  # container:path
        finding = _write_finding(containers.expand(token, ctx["cwd"], ctx["home"]), ctx)
        if finding:
            yield finding
            return


def _targets(sub, rest):
    targets, i = [], 0
    while i < len(rest):
        arg = rest[i]
        if arg in ENGINE_WITH_VALUE:
            i += 2
            continue
        if not arg.startswith("-"):
            targets.append(arg.split(":", 1)[0] if sub == "cp" else arg)
            if sub in ("exec", "attach", "commit", "export", "rename", "update"):
                break
        i += 1
    return targets


def _targeted(engine, sub, rest, ctx):
    roots = ctx["protected"]
    if any(a in ("-a", "--all", "-l", "--latest") for a in rest):
        if roots:
            yield Finding("high", f"{engine} {sub} --all can reach the protected deployment")
        return
    if not roots:
        return
    for target in _targets(sub, rest):
        info = ctx["inspect"](engine, "container", target)
        root = containers.container_protected(info, roots)
        if root:
            yield Finding("severe", f"{target} belongs to the protected deployment in {root}")


def _compose(seg, ctx, rest=None):
    if rest is None:
        rest = seg.words[1:]
    files = [rest[i + 1] for i, a in enumerate(rest[:-1]) if a in ("-f", "--file")]
    sub = next((a for a in rest if not a.startswith("-") and a not in files), None)
    if sub in COMPOSE_READ_ONLY or sub is None:
        return
    places = [ctx["cwd"]] + [containers.expand(f, ctx["cwd"], ctx["home"]) for f in files]
    for root in ctx["protected"]:
        if any(containers.under(p, root) for p in places):
            yield Finding("severe", f"compose {sub} acts on the protected deployment in {root}")
            return
