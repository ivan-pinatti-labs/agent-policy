# The policy

Every command the policy lists carries a severity. The severity is the one
scale we categorize by; the decision an agent acts on (allow, ask, deny)
follows from it. This document is the scale, the rule format, and how to
change a rule.

## Severity scale

| Severity   | Decision | Meaning                                                                                                                                                       |
| ---------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `read`     | allow    | Read-only. No side effects.                                                                                                                                   |
| `low`      | allow    | Reversible, local, small blast radius (the git flow, a podman build, `agent-scratch`).                                                                        |
| `moderate` | ask      | Mutates recoverable state (remove a container, a `gh api` write, a request body).                                                                             |
| `high`     | ask      | Sensitive data, wide blast radius, or runs code; still recoverable (`terraform apply`, `kubectl apply`, discarding uncommitted work, reading a secret value). |
| `severe`   | deny     | Irreversible or destructive: rewrites remote history, destroys infrastructure, deletes data.                                                                  |
| `critical` | deny     | Exposes or exfiltrates credentials, defeats a safety gate (the git hooks), or can take over the host or the agent.                                            |

- **allow** runs with no prompt.
- **ask** is the agent's normal permission prompt.
- **deny** is a hand-off, not "never": the agent is refused and told to ask
  you to run the command yourself (`! <command>`). `severe` and `critical`
  are both deny; the split records why, and both are reported in the guard's
  message so the reason is visible.

Unlisted commands fall through to the agent's own judgment: Claude Code's
auto mode classifier or prompt, Codex's sandbox and approval policy.

A static rule in `policy/` can only name a command by prefix. The guard
(`hooks/guard`) assigns severity to what a prefix cannot see: a credential
path read or written, a container mount, a git config that runs a command,
an AWS write verb mid-line. A guard finding of `severe` or `critical`
overrides an `allow` from the static rules, which is how `cat` stays allowed
in general but `cat ~/.ssh/id_ed25519` is refused.

### Files

One file per tool, numbered so related tools sit together:

| File                 | Covers                                         |
| -------------------- | ---------------------------------------------- |
| `00-base.toml`       | read only shell tools, web fetch, credentials  |
| `10-git.toml`        | git                                            |
| `20-github.toml`     | GitHub CLI                                     |
| `30-podman.toml`     | podman, podman-compose, `agent-scratch`        |
| `31-docker.toml`     | docker, docker-compose                         |
| `32-incus.toml`      | incus, LXD                                     |
| `40-kubectl.toml`    | kubectl                                        |
| `41-helm.toml`       | Helm                                           |
| `42-terraform.toml`  | Terraform                                      |
| `43-opentofu.toml`   | OpenTofu                                       |
| `44-atmos.toml`      | Atmos                                          |
| `45-aws.toml`        | AWS CLI, eksctl                                |
| `50-ansible.toml`    | Ansible                                        |
| `55-asdf.toml`       | asdf                                           |
| `60-mounts.toml`     | mount, umount, FUSE mounts, namespaces         |
| `90-http.toml`       | curl                                           |

A new tool gets its own file.

### Where things land

- **git:** the flow (add, commit, push, rebase, branch, worktree) is
  allowed. Discarding work asks. Rewriting or deleting remote history, and
  skipping hooks, are handed off.
- **GitHub CLI:** reads and the pull request flow are allowed, up to
  `gh pr merge --auto`. Repository settings, secrets, releases, gists and
  any non GET `gh api` call ask. `--admin` merges are handed off.
- **Containers:**
  - rootless podman builds, pulls, runs, execs and stops without asking,
    and the guard asks when a run widens its access;
  - removing anything asks, except through `agent-scratch`;
  - Docker, usually rootful, asks before it runs anything;
  - `system reset` is handed off.
- **Cloud and infrastructure:** reading is allowed. Changes ask (`apply`,
  `import`, state surgery, `kubectl apply/delete/exec`, `helm upgrade`, AWS
  write verbs, reading a secret value). Destroying is handed off.
- **HTTP:** Claude may fetch, and the guard asks before a request with a
  body or a write method. Codex keeps its own approval for `curl`.
- **Credentials and code-on-disk (guard only):** reading a credential file
  (`~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.claude*`, a `.pem`...) through any
  command is critical, and so is writing a credential file, a shell startup
  file, a git hook, or anything on PATH. These override the broad `allow` on
  readers like `cat` and writers like `cp`.

## Rule format

Each file in `policy/` holds `[[rule]]` tables:

```toml
[[rule]]
severity = "high"                # read|low|moderate|high|severe|critical
reason = "Discards uncommitted work"
agents = ["claude", "codex"]     # optional, default both
prefix = [
  ["git", ["clean", "reset"]],   # a word may be a list of alternatives
  ["git", "reflog", "expire"],
]
claude = ["Bash(*git reset --hard origin/*)"]   # Claude only
```

- `severity`: the level from the scale above. The renderer turns it into the
  agent's decision (allow, ask or deny).
- `prefix`: command prefixes, word by word. Rendered for Claude as
  `Bash(<words>)` and `Bash(<words> *)`, plus `Bash(git -C * <rest>)` for
  git. Rendered for Codex as `prefix_rule(pattern=..., decision=...)`, with
  the severity carried into the justification.
- `claude`: raw Claude Code permission rules, for anything a prefix cannot
  express (globs anywhere, `WebFetch(domain:...)`, `Read(...)`).
- `reason`: one line. Codex shows it (with the severity) as the rule's
  justification; for Claude it documents the rule.
- `agents`: limit a rule to one agent. Read only commands are Claude only,
  because a Codex `allow` runs the command outside its sandbox.

`tools/render.py` rejects an unknown severity, unknown keys, empty prefixes,
words containing a space, and Claude patterns on a Codex only rule.

## Changing a rule

1. Edit the file for the area. Give the rule the highest severity that still
   lets the work happen.
2. Add a case to `tests/guard_cases.toml` (guard behavior) or
   `tests/codex_cases.toml` (Codex rule behavior). Include the case that
   shows what is still refused, not only the one that now passes.
3. `make test`, then a pull request.
4. After it merges, `git pull && make install` on each machine.

### What does not belong here

Anything specific to one machine, account or project:

- MCP tool permissions (`mcp__<server>__<tool>`);
- cluster contexts, AWS profiles, account IDs and ARNs;
- repository specific `gh api` paths;
- project scripts (`./scripts/foo.sh`, `make some-target`);
- home folder paths.

Those go in that project's `.claude/settings.local.json`, which this
policy's asks and denies still override. `make harvest` sorts a machine's
local rules into "generic" (candidates for here) and "local" (keep there),
see [OPERATIONS.md](OPERATIONS.md#harvesting-local-rules).

### Never as a side effect

An agent that hits a prompt or a refusal while working on something else
reports it. Changing a tier is always its own change, reviewed on its own.
