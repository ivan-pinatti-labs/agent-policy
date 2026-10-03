# Operations

Installing, keeping a machine in step with this repository in both
directions, and removing it again.

## Installing

```shell
make test
make install
```

`make install` renders the policy in the test container, then copies, with
`sudo`:

| What                       | Where                                                      |
| -------------------------- | ---------------------------------------------------------- |
| Claude Code drop-in        | `/etc/claude-code/managed-settings.d/50-agent-policy.json` |
| guard and shared library   | `/usr/local/libexec/agent-policy/`                         |
| `agent-scratch`            | `/usr/local/bin/agent-scratch` (a link)                    |
| Codex hook                 | `/etc/codex/requirements.toml`                             |
| Codex rules (no sudo)      | `~/.codex/rules/agent-policy.rules`                        |

Every location is a variable: `PREFIX`, `LIBEXEC`, `CLAUDE_MANAGED_DIR`,
`CODEX_SYSTEM_DIR`, and `CODEX_HOMES` (space separated, for more than one
Codex home). If `/etc/codex/requirements.toml` already exists and was not
written by agent-policy, install leaves it alone and says what to add.

New sessions pick the policy up; restart running ones.

## Trying the sandbox

The sandbox needs `bubblewrap` and `socat` (`dnf install bubblewrap socat`,
`apt install bubblewrap socat`). Try it in one session before installing it
everywhere:

```shell
make build
cd ~/path/to/some-repo
claude --settings ~/path/to/agent-policy/dist/claude/sandbox-trial.json
```

In that session, `/sandbox` shows its state and any missing dependency.
Work normally for a while. A command that fails only inside the sandbox
either belongs in `excluded_commands` or needs a folder in `allow_write`.
When it holds up, set `install = true` in `policy/sandbox.toml`, open a
pull request, and `make install` after it merges. Consider
`fail_if_unavailable = true` at the same time, so a machine without
bubblewrap refuses to start rather than silently running unsandboxed.

## Updating

**Repository to machine:** `git pull && make install`. `make diff` first
shows what would change.

**Machine to repository:** see the next section. The policy is never edited
in place on a machine; local changes become pull requests.

## Harvesting local rules

Every "Yes, don't ask again" answer adds a rule to a project's
`.claude/settings.local.json`, and Codex saves its own in
`~/.codex/rules/default.rules`. `make harvest` reads them all and compares
them with the policy:

```shell
make harvest                          # projects next to this clone
make harvest HARVEST_ROOTS="$HOME/src $HOME/work"
CLAUDE_CONFIG_DIRS="$HOME/.claude-other" make harvest
```

`tools/collect.sh` copies only those files (and the user settings of each
Claude Code profile) into a temporary folder, and `tools/harvest.py` reads
them in the test container, which never sees the home folder. For each file
it lists:

| Section             | Meaning                                                                                             |
| ------------------- | --------------------------------------------------------------------------------------------------- |
| candidates, generic | not covered by the policy, nothing machine specific about it: worth a look for `policy/`            |
| candidates, local   | home paths, ARNs, account IDs, env prefixed commands, MCP tools: keep them in the project           |
| dead                | a local allow the policy asks or denies on, so it never takes effect: delete it                     |
| redundant           | the policy already grants it: delete it                                                             |

Nothing is changed. Promote a candidate with an edit to `policy/`, a test
case and a pull request ([POLICY.md](POLICY.md#changing-a-rule)).

## Protected deployments

When a live deployment runs on the same machine as its development clone,
the two often share container names and compose project names. List the
live deployment's folder, one per line:

```text
# ~/.config/agent-policy/protected-paths
~/path/to/live-deployment
```

The guard then refuses, as a hand-off:

- `stop`, `kill`, `rm`, `restart`, `exec`, `pause` and similar on any
  container whose compose working directory, or any bind mount, sits under
  one of those folders (it asks the engine);
- compose commands that change state, run from there or pointed at a
  compose file there;
- `rm -r` inside it.

`--all` on those commands asks whenever a protected path is configured.
`AGENT_POLICY_PROTECTED` (colon separated) works too. The file is per
machine and never committed.

## Telling agents about it

The guard explains each refusal, but agents do better knowing in advance.
Add this to your global instructions for each agent: `~/.claude/CLAUDE.md`
(and the `CLAUDE.md` of any other Claude Code profile) and
`~/.codex/AGENTS.md`:

```markdown
A command refused with "Blocked by agent-policy" is handed to the user: do
not retry it, rephrase it or work around it; ask the user to run it with
`! <command>`. For throwaway containers, networks and volumes use
`agent-scratch <verb> <slug> ...` with the task's branch slug, and
`agent-scratch purge <slug>` when done.
```

## Uninstalling

```shell
make uninstall
```

Removes everything install added. `/etc/codex/requirements.toml` is removed
only if agent-policy wrote it.

## Not verified yet

- That Codex loads every `*.rules` file in `~/.codex/rules/`. The rendered
  rules themselves are checked with `codex execpolicy check`.
- That Codex reads `[[hooks.PreToolUse]]` from
  `/etc/codex/requirements.toml` on a host. A devcontainer-airlock
  workbench does this, and it works there.
- `additionalDirectories` in a Claude Code managed drop-in.
