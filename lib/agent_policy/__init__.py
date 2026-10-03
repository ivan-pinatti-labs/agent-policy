# SPDX-License-Identifier: Apache-2.0
"""Shared command policy for coding agents (Claude Code, Codex).

The static rules in policy/*.toml decide by command prefix. This package
holds what a prefix cannot express: flags anywhere on the line, the targets
of a podman command, the host paths a container mounts. hooks/guard and
bin/agent-scratch both import it.
"""
