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

## Modes

The policy as written is `hardened`, the default everywhere. Three more modes
exist for an environment that knows who is watching, such as a
devcontainer-airlock session, which picks one per session. Each is a
rendering of the same rules (`tools/render.py --mode`), and the guard is told
which one it runs under (`guard --mode`).

| Mode         | Who is there            | What changes                                                                  |
| ------------ | ----------------------- | ----------------------------------------------------------------------------- |
| `hardened`   | the user, at every step | nothing: the policy as written                                                |
| `assisted`   | the user, present       | a read of a path the guard cannot resolve is allowed                          |
| `permissive` | the user, present       | what the guard cannot judge is left to Claude Code's auto mode classifier     |
| `unattended` | nobody                  | nothing asks: what would ask is denied, unless named for this mode            |

Assisted allows `cat $f` and `wc -l < $f`; every static rule and every other
finding is as hardened.

Permissive is for a session with the user present, inside an environment
that holds the boundary itself, and it is there to stop the prompts that
inspecting, parsing and fetching bring. It allows everything assisted does,
and gives up every finding the guard raises only because it cannot judge
the line:

- a read or a write of a path the guard cannot resolve (`cat $f`,
  `cp a "$d"`, `gh pr view 1 > "$f"`);
- a command line it cannot parse, such as an unbalanced quote;
- a script nested in the line (`bash -c`, `eval`, a substitution) that does
  not tokenize, or that nests deeper than the guard reads;
- a yq expression that loads a file it names itself.

The guard returns no decision for these, the same silence it gives a line it
finds nothing on. The static rules then decide, and what no rule names goes
to Claude Code's auto mode classifier: the session runs with
`--permission-mode auto`, as unattended does. Nothing is asked by the policy
there and nothing is allowed by it that the rules would not allow anyway.
The static rules are the ones hardened renders, unchanged, since a command no
rule names already falls to the classifier. Every other finding keeps its
decision: each `high` finding and rule still asks (applying or deploying
infrastructure, pushing straight to `main`, discarding work, a release,
repository settings), and so do the `moderate` ones (`gh api` writes, PUT and
DELETE included, a request body, an AWS write). Every deny stays a deny.

A line the guard cannot read whole is still read as far as it can be, so a
deny written beside the part it gives up stays a deny: in permissive the
guard reads nested scripts and substitutions sixteen levels deep rather than
four, skips only the part it cannot read, and reads a line with an
unbalanced quote one line at a time, since the shell runs each line before it
reads the next. `git push --force origin x` followed by a line with an
unbalanced quote is denied, and so is `eval` five deep around a read of
`~/.ssh`. A credential path hidden behind a variable the guard cannot
resolve is left to the classifier and stopped by the sandbox, which denies
reading every credential path. A write to such a path is confined by the
sandbox too, except through a command the sandbox does not run (its
excluded commands), where only the workbench around it holds.

The guard takes permissive only when the environment declares it, because
the mode is only as safe as what surrounds the agent. Two things must hold:
`AIRLOCK_LEVEL` is `permissive` in the guard's environment, which a
devcontainer-airlock workbench sets for the session and which no command the
agent runs can change for the agent or its hooks; and the guard runs in a
container (`/run/.containerenv`, the file podman writes into every container
it runs, exists). A host has no such file, so a drop-in rendered for
permissive and installed on a plain host cannot take effect there by
accident. When either is missing, or the agent is Codex, the guard runs
hardened and says so: a `systemMessage` on every Bash call in Claude Code,
standard error for Codex. Permissive is Claude Code's alone. Codex has no
classifier to leave a line to, so a permissive rendering writes Codex's files
as hardened, and devcontainer-airlock runs Codex hardened.

Unattended has nobody to answer a prompt, so a rule or finding that would
ask is denied there, unless the policy names it for this mode, and then it
is allowed. Every deny stays a deny, whatever the
mode. What unattended allows is the development cycle, and only that:

- `gh release create/edit/upload`, `gh workflow run`, `gh issue close`,
  `gh label create/edit`, `git push --tags`;
- `gh api` POST and PATCH, and GraphQL mutations, to any endpoint as far as
  this policy is concerned;
- force-deleting a branch (`git branch -D`), merged or not; moving or
  copying over a branch (`-M`, `-C`, `--force`) stays denied;
- removing, stopping or renaming podman containers, images and networks;
  removing a volume stays denied, since its data goes with it;
- reads and writes of a path the guard cannot resolve, credential and
  startup paths included when they hide behind a variable.

These assume an environment around the agent that holds the line the policy
cannot. Permissive and unattended are meant for one, such as a
devcontainer-airlock session: there the gh broker passes only review replies and resolving a
thread among `gh api` writes, the command sandbox (installed, not trial)
confines writes to the session's own folders and denies reading credential
paths, the workbench holds no credentials of its own, and podman reaches
only the session's own L2 engine. Without such an environment, run
hardened.

Everything else that asks under hardened is denied unattended, among it:
discarding work (`git reset --hard`, `restore`, `clean`, a checkout over
changes), `git worktree remove --force`, deleting or moving a tag, pushing
straight to `main`, `find -exec` and `-delete`, a request body sent with
`curl` or `wget`, privileged containers, a GraphQL query read from a file,
`gh api` PUT and DELETE, repository settings, secrets and gists, and a
command line the guard cannot parse. A rule added later starts out denied
there too, so nothing new can stall an unattended run on a prompt.

A static rule names its own exception with `modes`:

```toml
[[rule]]
severity = "high"
reason = "Publishes a release, runs a workflow, ..."
modes = { unattended = "low" }
prefix = [["gh", "release", ["create", "edit", "upload"]]]
```

A guard finding does the same through its key, in `MODE_SEVERITY` in
`lib/agent_policy/checks.py`. Under a mode that allows a rule, its `claude`
patterns that start with a wildcard (`Bash(*gh api*-X POST*)`) are left
out: such a pattern matches any command holding it anywhere, so it can only
ever ask or deny.

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
| `45-aws.toml`        | AWS CLI                                        |
| `46-eksctl.toml`     | eksctl                                         |
| `47-helmfile.toml`   | helmfile                                       |
| `48-kubeseal.toml`   | kubeseal (Sealed Secrets)                      |
| `49-pluto.toml`      | pluto                                          |
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
  `import`, state surgery, `kubectl apply/delete/exec`, `helm upgrade`,
  `helmfile sync/apply`, `eksctl create/upgrade`, AWS write verbs, reading
  a secret value, sealing a secret from a file or re-encrypting one;
  sealing from standard input is unlisted, so it prompts). Destroying is
  handed off (`terraform destroy`, `eksctl delete cluster`, `helmfile
  destroy`), and so is unsealing with the Sealed Secrets private key, which
  the guard refuses wherever the flag sits. The reads of eksctl, helmfile,
  kubeseal and pluto are Claude only, like the base read rules.
  - A read with `AWS_PROFILE`, `AWS_REGION` or `AWS_DEFAULT_REGION` set in
    front (`AWS_PROFILE=x kubectl get pods`) is allowed by the guard, for
    aws, atmos, terraform, tofu, kubectl, helm, eksctl, helmfile, kubeseal
    and pluto: a static rule cannot match a command with a variable in
    front. No other variable is: `KUBECONFIG` names a file whose exec plugin
    runs a program of its choosing, `ATMOS_IDENTITY=false` switches atmos
    to whatever credentials the AWS SDK finds around it, and `TF_*` passes
    options and plugin folders no prefix rule sees. A line with
    `--kubeconfig`, `--helm-binary`, `--kustomize-binary` (helmfile's `-b`
    and `-k` too) or `--post-renderer` is left to the static rules for the
    same reason, and so is one that writes a file the guard does not judge
    (`-out`, `-generate-config-out`) or changes whom an aws read trusts
    (`--no-verify-ssl`, `--ca-bundle`, `--endpoint-url`).
  - helmfile with another helm or kustomize binary (`--helm-binary`, `-b`,
    `--kustomize-binary`, `-k`) asks at `high`, the scale's level for
    running code: it runs the program the prompt names, as `kubectl exec`
    or `helm install` with its hooks would, and nothing about it is
    irreversible or a credential. It is never approved by the guard.
- **HTTP:** Claude may fetch, and the guard asks before a request with a
  body or a write method. Codex keeps its own approval for `curl`.
- **Credentials and code-on-disk (guard only):** reading a credential file
  (`~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.claude*`, a `.pem`...) through any
  command is critical, and so is writing a credential file, a shell startup
  file, a git hook, or anything on PATH. These override the broad `allow` on
  readers like `cat` and writers like `cp`. One read is exempt: Claude Code
  saves a tool output too large to show inline under
  `~/.claude*/projects/<project>/<session>/tool-results/` and tells the agent
  to read it there, so reading a file in that folder is allowed. The folder
  itself is not: a recursive read that follows links (`grep -R`) could walk
  out of it. Writing, mounting or removing it is still critical. The same
  holds for Claude Code's memory notes, the files under
  `~/.claude*/projects/<project>/memory/`: an agent reads its own back.

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
  `Bash(<words>)` and `Bash(<words> *)`, plus `Bash(git -C * <rest>)` for a
  git rule that asks or denies. A git rule that allows gets no `-C` form:
  Claude Code warns about an allow rule with a `*` before the subcommand,
  since it also allows any option put there. The guard allows
  `git -C <dir> <rest>` itself instead, from the prefixes in
  `dist/claude/guard-allow.json`, and so an aws read verb after any
  service. Rendered for Codex as `prefix_rule(pattern=..., decision=...)`,
  with the severity carried into the justification.
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
