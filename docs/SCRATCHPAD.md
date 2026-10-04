# The scratchpad

`agent-scratch` gives an agent a place to prototype with containers,
networks, volumes and files, and to clean up after itself, with no
permission prompts and no way to reach anything it did not create. Both
agents may run it freely (`agent-scratch` is in the allow tier), so the
limits live in the helper itself.

## Ownership

Everything belongs to a **slug**: lowercase letters, digits and dashes, at
most 40 characters. Use the task's branch or worktree slug, so concurrent
sessions do not collide.

| Resource                      | Name                       | Marker                                         |
| ----------------------------- | -------------------------- | ---------------------------------------------- |
| folder                        | `~/scratch/as-<slug>`      | its path (`AGENT_SCRATCH_ROOT` moves the root) |
| containers, networks, volumes | `as-<slug>-<name>`         | label `io.agent-policy.scratch=<slug>`         |

Claude Code may also read and edit `~/scratch/**` without asking.

## Commands

```text
agent-scratch dir     <slug>
agent-scratch run     <slug> [podman run options] <image> [command...]
agent-scratch create  <slug> [podman create options] <image> [command...]
agent-scratch network <slug> <name> [--internal] [--subnet CIDR] [--ipv6] [--disable-dns]
agent-scratch volume  <slug> <name>
agent-scratch exec    <slug> <name> <command...>
agent-scratch rm      <slug> <name>...
agent-scratch ls      [<slug>]
agent-scratch purge   <slug>
```

## What it allows and refuses

**`run` and `create`** add the label and the name prefix (a missing
`--name` gets a random one). They refuse:

- `--privileged`, host namespaces (`--network=host`, `--pid=host` and the
  like), `--cap-add`, `--device`, and turning off confinement;
- bind mounts from anywhere but the slug's folder or the current project
  (its git top level);
- named volumes and networks that are not this slug's, judged by label, not
  by name (a volume named `as-<slug>-*` that lacks the label is refused; one
  that does not exist yet is created with the label first);
- `--pod`.

**`network`** accepts only the options listed above (no `macvlan` or
`ipvlan` drivers that would put a container on the host's network).

**`rm`, `exec` and `purge`** first ask the engine for the target's label,
and refuse unless it is this slug's. `purge` removes every labelled
container, network and volume, then the folder.

A refusal exits with status 2 and says why.

## Example

```shell
agent-scratch dir demo
agent-scratch network demo net --internal
agent-scratch volume demo pgdata
agent-scratch run demo --name db -d --network as-demo-net \
  -v as-demo-pgdata:/var/lib/postgresql/data postgres:17
agent-scratch exec demo db psql -U postgres -c 'select 1'
agent-scratch ls demo
agent-scratch purge demo
```

## In a devcontainer-airlock workbench

There, `podman` talks to the workspace's L2 engine rather than the host's,
which already isolates whatever an agent starts. `agent-scratch` still
works and still keeps one task's resources apart from another's.
