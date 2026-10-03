# SPDX-License-Identifier: Apache-2.0
"""Host path and container-engine checks shared by the guard and agent-scratch.

The functions here answer questions a command prefix cannot: does a path hold
credentials, would writing it change what runs next, does a container run
widen what it can reach, does a container belong to a protected deployment.
Each returns a (severity, reason) pair or None; severities are the scale in
docs/POLICY.md (read, low, moderate, high, severe, critical).
"""

import json
import os
import subprocess

# Folders under $HOME whose contents are credentials: reading one, mounting
# one into a container, or writing one is treated as critical.
CREDENTIAL_DIRS = [
    ".ssh",
    ".gnupg",
    ".aws",
    ".docker",
    ".password-store",
    ".pki",
    ".codex",
    ".config/gh",
    ".config/gcloud",
    ".kube",
]
# Top-level names matched by prefix: Claude Code keeps its login under
# ~/.claude, and a second profile usually sits next to it under a similar
# name (CLAUDE_CONFIG_DIR).
CREDENTIAL_PREFIXES = [".claude"]
# Single files under $HOME that hold secrets.
CREDENTIAL_FILES = [
    ".netrc",
    ".git-credentials",
    ".pgpass",
    ".npmrc",
    ".pypirc",
    ".terraformrc",
    ".terraform.d/credentials.tfrc.json",
]
# Basenames that are secrets wherever they sit.
CREDENTIAL_NAMES = {
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".credentials.json",
    "auth.json",
}
CREDENTIAL_SUFFIXES = (".pem",)

# Files whose contents run as code the next time a shell or tool starts, so
# writing one turns a file write into code execution. Dirs on PATH or that a
# runtime scans are included.
EXEC_FILES = [
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".kshrc",
    ".gitconfig",
    ".inputrc",
]
EXEC_DIRS = [".local/bin", ".asdf", ".config/fish", ".config/environment.d"]

# Broader agent, config and system state: mounting it into a container is
# high rather than critical (no raw credential, but still not the project).
SENSITIVE_HOME = [".config", ".mozilla", ".local/share/containers", ".gitconfig"]
SENSITIVE_SYSTEM = ["/etc", "/root", "/var", "/usr", "/boot", "/proc", "/sys", "/dev", "/run"]

HOST_NAMESPACES = {"--pid", "--ipc", "--uts", "--network", "--net", "--cgroupns", "--userns"}
SCRATCH_LABEL = "io.agent-policy.scratch"


def under(path, root):
    path, root = os.path.normpath(path), os.path.normpath(root)
    return path == root or path.startswith(root.rstrip("/") + "/")


def expand(path, cwd, home):
    for var in ("${HOME}", "$HOME"):
        if path.startswith(var):
            path = home + path[len(var) :]
    if path == "~" or path.startswith("~/"):
        path = home + path[1:]
    if not os.path.isabs(path):
        path = os.path.join(cwd, path)
    # realpath follows any symlink on the way, so a link that points at a
    # credential or a startup file is judged by where it leads. A path that
    # does not exist yet is only normalized.
    return os.path.realpath(path)


def has_unexpanded(source):
    """A mount or path source carrying a shell variable or substitution the
    guard cannot resolve, so it cannot judge where it points."""
    return "$" in source or "`" in source


def credential_target(path, home):
    """The credential location `path` (absolute) reads or writes, or None."""
    for rel in CREDENTIAL_DIRS:
        full = os.path.join(home, rel)
        if under(path, full) or under(full, path):
            return f"~/{rel}"
    if under(path, home) and path != home:
        top = os.path.relpath(path, home).split(os.sep, 1)[0]
        if any(top.startswith(p) for p in CREDENTIAL_PREFIXES):
            return f"~/{top}"
    for rel in CREDENTIAL_FILES:
        if path == os.path.join(home, rel):
            return f"~/{rel}"
    base = os.path.basename(path)
    if base in CREDENTIAL_NAMES or base.endswith(CREDENTIAL_SUFFIXES):
        return base
    return None


def sensitive_home_entry(path, home):
    """The broader home state `path` overlaps (not a raw credential), or None."""
    for rel in SENSITIVE_HOME:
        full = os.path.join(home, rel)
        if under(path, full) or under(full, path):
            return rel
    return None


def exec_target(path, cwd, home):
    """Why writing `path` (absolute) would change what runs next, or None."""
    for rel in EXEC_FILES:
        if path == os.path.join(home, rel):
            return f"~/{rel}, a startup file that runs on the next shell"
    for rel in EXEC_DIRS:
        if under(path, os.path.join(home, rel)):
            return f"~/{rel}, which is on PATH or scanned by a runtime"
    if os.sep + ".git" + os.sep + "hooks" + os.sep in path + os.sep:
        return "a git hook, which runs on the next git command"
    return None


def is_host_path(source):
    return source.startswith(("/", "~", ".", "$HOME", "${HOME}"))


def mount_finding(source, cwd, home, protected):
    """(severity, reason) for mounting this host path or volume, or None."""
    if has_unexpanded(source):
        return ("high", f"mounts {source}, a path this guard cannot resolve")
    if not is_host_path(source):
        return None  # a named volume
    path = expand(source, cwd, home)
    if "podman.sock" in path or "docker.sock" in path:
        return ("critical", f"mounts the container engine socket ({path})")
    cred = credential_target(path, home)
    if cred:
        return ("critical", f"mounts {path}, which holds credentials ({cred})")
    for root in protected:
        if under(path, root) or under(root, path):
            return ("critical", f"mounts {path}, inside the protected deployment {root}")
    if path == "/" or (under(path, home) and path == home):
        return ("critical", f"mounts {path}, which contains the whole home folder")
    if under(home, path):  # a parent of home
        return ("critical", f"mounts {path}, a parent of the home folder")
    rel = sensitive_home_entry(path, home)
    if rel:
        return ("high", f"mounts {path}, which holds agent or tool state (~/{rel})")
    for root in SENSITIVE_SYSTEM:
        if under(path, root):
            return ("high", f"mounts the system path {path}")
    return None


def mount_sources(args):
    """(flag, host-or-volume source) pairs from -v/--volume/--mount options."""
    out = []
    for i, arg in enumerate(args):
        value = None
        if arg in ("-v", "--volume", "--mount") and i + 1 < len(args):
            value, flag = args[i + 1], arg
        elif arg.startswith(("--volume=", "--mount=")):
            flag, _, value = arg.partition("=")
        elif arg.startswith("-v") and len(arg) > 2 and arg[2] in "/~.$":
            flag, value = "-v", arg[2:]
        if value is None:
            continue
        if flag == "--mount":
            fields = dict(p.partition("=")[::2] for p in value.split(","))
            if fields.get("type", "volume") not in ("bind", "glob"):
                continue
            source = fields.get("source") or fields.get("src") or ""
        else:
            source = value.split(":", 1)[0]
        out.append((flag, source))
    return out


# Flags on `run`/`create` that widen what the container can reach, with the
# severity each one earns.
def run_findings(args, cwd, home, protected=()):
    """List of (severity, reason) for a `run`/`create` argument list."""
    found = []
    for i, arg in enumerate(args):
        name, eq, value = arg.partition("=")
        if eq == "" and i + 1 < len(args):
            value = args[i + 1]
        if name in ("--privileged",) and value.lower() not in ("false",):
            found.append(("high", "runs a privileged container"))
        elif name == "--rootfs":
            found.append(("critical", "runs directly on a host directory tree (--rootfs)"))
        elif name in ("--security-opt",) and any(
            s in value
            for s in ("unconfined", "label=disable", "label:disable", "label=type", "label:type")
        ):
            found.append(("high", f"turns off or rewrites confinement (--security-opt {value})"))
        elif name in HOST_NAMESPACES and value == "host":
            found.append(("high", f"shares the host's namespace ({name}=host)"))
        elif name in HOST_NAMESPACES and value.startswith("container:"):
            found.append(("high", f"joins another container's namespace ({name}={value})"))
        elif name in ("--cap-add", "--device", "--device-cgroup-rule"):
            found.append(("high", f"adds host capabilities or devices ({name})"))
        elif name == "--volumes-from":
            found.append(("high", f"inherits another container's mounts (--volumes-from {value})"))
        elif name == "--secret":
            found.append(
                ("critical", f"reads an engine secret into the container (--secret {value})")
            )
        elif name in ("--pids-limit",):
            continue
    for _flag, source in mount_sources(args):
        finding = mount_finding(source, cwd, home, protected)
        if finding:
            found.append(finding)
    return found


def inspect(engine, kind, target, timeout=5):
    """`<engine> <kind> inspect <target>` as a dict, or None if it does not exist."""
    try:
        proc = subprocess.run(
            [engine, kind, "inspect", target],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        return None
    if isinstance(data, list):
        data = data[0] if data else None
    return data


def labels_of(info):
    if not info:
        return {}
    return (info.get("Config") or {}).get("Labels") or info.get("Labels") or {}


def protected_paths(env=None):
    """Folders whose containers agents must never stop, remove or exec into.

    Machine-specific, so it is never committed: AGENT_POLICY_PROTECTED
    (os.pathsep separated) plus one path per line in
    $XDG_CONFIG_HOME/agent-policy/protected-paths.
    """
    env = os.environ if env is None else env
    home = env.get("HOME", os.path.expanduser("~"))
    paths = [p for p in env.get("AGENT_POLICY_PROTECTED", "").split(os.pathsep) if p]
    config = os.path.join(
        env.get("XDG_CONFIG_HOME") or os.path.join(home, ".config"),
        "agent-policy",
        "protected-paths",
    )
    try:
        with open(config, encoding="utf-8") as handle:
            paths += [line.strip() for line in handle if line.strip() and not line.startswith("#")]
    except OSError:
        pass
    return [expand(p, "/", home) for p in paths]


def container_protected(info, roots):
    """The protected root this container belongs to, or None."""
    if not info or not roots:
        return None
    labels = labels_of(info)
    candidates = [labels.get("com.docker.compose.project.working_dir", "")]
    candidates += [m.get("Source", "") for m in info.get("Mounts") or []]
    for path in candidates:
        for root in roots:
            if path and under(path, root):
                return root
    return None
