# Tasks for agent-policy, plus the devcontainer-airlock workbench targets.
#
# Everything that runs this repository's code runs in the test container
# (tests/Containerfile). `install` and `uninstall` are the exceptions: they
# copy files into system folders, so they run on the host, with sudo, and
# only when a person runs them.
#
# checkmake reads only the first physical line of a .PHONY declaration and
# silently drops backslash continuations, so every .PHONY here is written on
# one line (checkmake#280).
.PHONY: all help workbench-help image build test harvest install uninstall diff clean

# Bare `make` shows the target list rather than doing something surprising.
all: help

PREFIX             ?= /usr/local
LIBEXEC            ?= $(PREFIX)/libexec/agent-policy
CLAUDE_MANAGED_DIR ?= /etc/claude-code/managed-settings.d
CODEX_SYSTEM_DIR   ?= /etc/codex
CODEX_HOMES        ?= $(HOME)/.codex
TEST_IMAGE         ?= localhost/agent-policy-test
ENGINE             ?= podman

# The folder holding this repository's main clone, which is where its sibling
# repositories usually live. `make harvest` searches it for project
# .claude/settings*.json files. Set HARVEST_ROOTS to search elsewhere.
WORKSPACE     := $(abspath $(dir $(shell git rev-parse --path-format=absolute --git-common-dir 2>/dev/null))..)
HARVEST_ROOTS ?= $(WORKSPACE)

RUN = $(ENGINE) run --rm --network=none --userns=keep-id -v "$(CURDIR):/work:Z" -w /work $(TEST_IMAGE)

# The workbench targets (make claude, make codex, make unlock and the rest)
# come from a devcontainer-airlock clone, by default the one next to this
# repository's main clone. See .devcontainer/README.md.
WORKBENCH_HOME ?= $(WORKSPACE)/devcontainer-airlock
-include $(WORKBENCH_HOME)/host/workbench.mk

ifeq ($(wildcard $(WORKBENCH_HOME)/host/workbench.mk),)
workbench-help:
	@printf '%s\n' \
		'Workbench: no devcontainer-airlock clone at $(WORKBENCH_HOME).' \
		'  Clone ivan-pinatti-labs/devcontainer-airlock there, or set WORKBENCH_HOME,' \
		'  for make claude, make codex, make unlock and the rest (.devcontainer/README.md).'
endif

help:
	@printf '%s\n' \
		'Usage:' \
		'  make <target>' \
		'' \
		'Targets:' \
		'  help        Show this message.' \
		'  test        Run every test in the test container.' \
		'  build       Build the policy for both agents into dist/.' \
		'  harvest     Compare this machine'"'"'s permission files with the policy.' \
		'  diff        Show how the installed policy differs from this checkout.' \
		'  install     Install for both agents and every profile (sudo).' \
		'  uninstall   Remove everything install added (sudo).' \
		'  clean       Remove dist/.' \
		''
	@$(MAKE) --no-print-directory workbench-help

image:
	$(ENGINE) build -t $(TEST_IMAGE) -f tests/Containerfile tests

build: image
	$(RUN) python3 tools/render.py --out dist --libexec $(LIBEXEC)

test: image
	$(RUN) python3 -m unittest discover -s tests -v

# collect.sh copies only the permission files into a temporary folder, so the
# container never sees the home folder or anything holding credentials.
harvest: image
	@staging="$$(mktemp -d)"; trap 'rm -rf "$$staging"' EXIT; \
	tools/collect.sh "$$staging" $(HARVEST_ROOTS) && \
	$(ENGINE) run --rm --network=none --userns=keep-id -v "$(CURDIR):/work:ro,Z" \
		-v "$$staging:/staging:ro,Z" -w /work $(TEST_IMAGE) python3 tools/harvest.py /staging

install: build
	sudo install -d -m 0755 $(LIBEXEC)/lib/agent_policy $(CLAUDE_MANAGED_DIR) $(CODEX_SYSTEM_DIR)
	sudo install -m 0755 hooks/guard bin/agent-scratch $(LIBEXEC)/
	sudo install -m 0644 lib/agent_policy/*.py $(LIBEXEC)/lib/agent_policy/
	sudo ln -sf $(LIBEXEC)/agent-scratch $(PREFIX)/bin/agent-scratch
	sudo install -m 0644 dist/claude/50-agent-policy.json $(CLAUDE_MANAGED_DIR)/
	@if [ -e $(CODEX_SYSTEM_DIR)/requirements.toml ] && \
		! grep -q 'Managed by agent-policy' $(CODEX_SYSTEM_DIR)/requirements.toml; then \
		echo "install: $(CODEX_SYSTEM_DIR)/requirements.toml exists and is not ours;"; \
		echo "         add the hook from dist/codex/requirements.toml to it by hand."; \
	else \
		sudo install -m 0644 dist/codex/requirements.toml $(CODEX_SYSTEM_DIR)/requirements.toml; \
	fi
	@for home in $(CODEX_HOMES); do \
		install -d "$$home/rules" && install -m 0644 dist/codex/agent-policy.rules "$$home/rules/" && \
		echo "install: codex rules -> $$home/rules/agent-policy.rules"; \
	done

uninstall:
	sudo rm -f $(CLAUDE_MANAGED_DIR)/50-agent-policy.json $(PREFIX)/bin/agent-scratch
	sudo rm -rf $(LIBEXEC)
	@if grep -qs 'Managed by agent-policy' $(CODEX_SYSTEM_DIR)/requirements.toml; then \
		sudo rm -f $(CODEX_SYSTEM_DIR)/requirements.toml; fi
	@for home in $(CODEX_HOMES); do rm -f "$$home/rules/agent-policy.rules"; done

diff: build
	-diff -u $(CLAUDE_MANAGED_DIR)/50-agent-policy.json dist/claude/50-agent-policy.json
	-diff -u $(CODEX_SYSTEM_DIR)/requirements.toml dist/codex/requirements.toml
	-@for home in $(CODEX_HOMES); do diff -u "$$home/rules/agent-policy.rules" dist/codex/agent-policy.rules; done
	-diff -ru -x __pycache__ $(LIBEXEC)/lib/agent_policy lib/agent_policy
	-diff -u $(LIBEXEC)/guard hooks/guard
	-diff -u $(LIBEXEC)/agent-scratch bin/agent-scratch

clean:
	rm -rf dist
