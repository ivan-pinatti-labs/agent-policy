# Operations

Installing, keeping a machine in step with this repository in both
directions, and removing it again.

## Installing

```shell
make test
make install
```

`make install` first backs up everything it is about to touch (see
"Backups" below); only once that backup is complete and verified does it
render the policy in the test container and copy, with `sudo`:

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

Backs up first, like install, then removes everything install added.
`/etc/codex/requirements.toml` is removed only if agent-policy wrote it.

## Backups

`make install` and `make uninstall` both start with `make backup`, which
copies everything they touch into a new timestamped folder under
`~/.local/state/agent-policy/backups/` (`BACKUP_ROOT` moves it):

- the Claude Code policy folder, `/etc/claude-code` (the drop-in folder and
  any `managed-settings.json` next to it);
- `/etc/codex`;
- the installed scripts, `/usr/local/libexec/agent-policy`, and the
  `agent-scratch` link;
- each Codex `rules` folder (`~/.codex/rules`, including Codex's own
  `default.rules`).

Each copy is checked against its source, and the backup's `manifest.json`
is written last, so a folder without one is not a backup. A path that does
not exist is recorded as absent. If anything fails (a file it cannot read,
a full disk), make stops there: nothing is built and nothing is installed.
The backup itself only reads those paths; it never writes to them.

```shell
make backups                                  # list them, newest first
make restore BACKUP=~/.local/state/agent-policy/backups/<timestamp>
```

`make restore` first prints what it would change (a dry run), then, with
`sudo`, puts every file, symlink and mode back as it was, and removes
anything created since, including a path that was absent when the backup
was taken. Restoring the same backup twice changes nothing the second time.

Restore runs as root on a folder you own, so it trusts the backup only as
far as it has to. It touches only the paths make passes it; it reads each
stored copy without following a symlink and only if its hash matches the
manifest; it writes without following a symlink; it never restores a
setuid, setgid or sticky bit; and a restored path takes the owner of the
folder it is restored into, never one named in the manifest. It opens
every folder from `/` without following a symlink and writes through those
handles, so a symlink anywhere on the way makes it stop rather than follow
(on a system where `/home` itself is a symlink, restore the home folder's
paths by hand). A symlink is put back only if it points inside those same
paths: a link in the policy folder to a file you own would make that file
root-managed policy, and a link at `agent-scratch` to your own script would
run it with no prompt. A backup holding a link that points elsewhere is
refused, naming the link, so you can put that one back by hand. It does
put back whatever content the backup holds, so read the dry run first.

## Not verified yet

- That Codex loads every `*.rules` file in `~/.codex/rules/`. The rendered
  rules themselves are checked with `codex execpolicy check`.
- That Codex reads `[[hooks.PreToolUse]]` from
  `/etc/codex/requirements.toml` on a host. A devcontainer-airlock
  workbench does this, and it works there.
- `additionalDirectories` in a Claude Code managed drop-in.
