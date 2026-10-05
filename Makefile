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
.PHONY: all help workbench-help image build test coverage harvest backup backups restore install uninstall diff clean

# Bare `make` shows the target list rather than doing something surprising.
all: help

PREFIX             ?= /usr/local
LIBEXEC            ?= $(PREFIX)/libexec/agent-policy
CLAUDE_MANAGED_DIR ?= /etc/claude-code/managed-settings.d
CODEX_SYSTEM_DIR   ?= /etc/codex
CODEX_HOMES        ?= $(HOME)/.codex
TEST_IMAGE         ?= localhost/agent-policy-test
# The host's own Python, never a version manager's shim: backup and restore
# run on the host, as the guard does.
PYTHON             ?= /usr/bin/python3

# Everything install and uninstall touch, backed up whole before either
# writes a byte: the Claude Code policy folder (managed-settings.d and the
# managed-settings.json next to it), /etc/codex, the installed scripts, the
# agent-scratch link, and each Codex rules folder.
BACKUP_ROOT  ?= $(or $(XDG_STATE_HOME),$(HOME)/.local/state)/agent-policy/backups
BACKUP_PATHS  = $(patsubst %/,%,$(dir $(CLAUDE_MANAGED_DIR))) $(CODEX_SYSTEM_DIR)
BACKUP_PATHS += $(LIBEXEC) $(PREFIX)/bin/agent-scratch $(addsuffix /rules,$(CODEX_HOMES))
ENGINE             ?= podman

# The folder holding this repository's main clone, which is where its sibling
# repositories usually live. `make harvest` searches it for project
# .claude/settings*.json files. Set HARVEST_ROOTS to search elsewhere.
WORKSPACE     := $(abspath $(dir $(shell git rev-parse --path-format=absolute --git-common-dir 2>/dev/null))..)
HARVEST_ROOTS ?= $(WORKSPACE)

# The image runs as UID 1000; keep-id:uid=1000 maps whoever runs make onto
# it, so files written to /work (dist/, coverage) belong to that user and the
# container can write them on any host, a CI runner with UID 1001 included.
RUN = $(ENGINE) run --rm --network=none --userns=keep-id:uid=1000,gid=1000 -v "$(CURDIR):/work:Z" -w /work $(TEST_IMAGE)

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
		'  coverage    Run the tests with coverage, writing coverage.xml.' \
		'  build       Build the policy for both agents into dist/.' \
		'  harvest     Compare this machine'"'"'s permission files with the policy.' \
		'  diff        Show how the installed policy differs from this checkout.' \
		'  install     Back up, then install for both agents and every profile (sudo).' \
		'  uninstall   Back up, then remove everything install added (sudo).' \
		'  backup      Back up everything install touches, and nothing else.' \
		'  backups     List the backups, newest first.' \
		'  restore     Put a backup back: make restore BACKUP=<folder> (sudo).' \
		'  clean       Remove dist/.' \
		''
	@$(MAKE) --no-print-directory workbench-help

image:
	$(ENGINE) build -t $(TEST_IMAGE) -f tests/Containerfile tests

build: image
	$(RUN) python3 tools/render.py --out dist --libexec $(LIBEXEC)

test: image
	$(RUN) python3 -m unittest discover -s tests -v

coverage: image
	$(RUN) sh -c 'rm -f .coverage .coverage.* && \
		COVERAGE_PROCESS_START=/work/.coveragerc python3 -m coverage run -m unittest discover -s tests && \
		python3 -m coverage combine -q && python3 -m coverage xml -q -o coverage.xml && \
		python3 -m coverage report'

# collect.sh copies only the permission files into a temporary folder, so the
# container never sees the home folder or anything holding credentials.
harvest: image
	@staging="$$(mktemp -d)"; trap 'rm -rf "$$staging"' EXIT; \
	tools/collect.sh "$$staging" $(HARVEST_ROOTS) && \
	$(ENGINE) run --rm --network=none --userns=keep-id:uid=1000,gid=1000 -v "$(CURDIR):/work:ro,Z" \
		-v "$$staging:/staging:ro,Z" -w /work $(TEST_IMAGE) python3 tools/harvest.py /staging

# A failed backup stops make here, before anything is built or installed.
backup:
	$(PYTHON) tools/backup.py create --root "$(BACKUP_ROOT)" $(BACKUP_PATHS)

backups:
	@$(PYTHON) tools/backup.py list "$(BACKUP_ROOT)"

restore:
	@test -n "$(BACKUP)" || { echo "usage: make restore BACKUP=<folder>  (make backups lists them)"; exit 2; }
	$(PYTHON) tools/backup.py restore --dry-run --backup-root "$(BACKUP_ROOT)" $(addprefix --allow ,$(BACKUP_PATHS)) "$(BACKUP)"
	sudo $(PYTHON) tools/backup.py restore --backup-root "$(BACKUP_ROOT)" $(addprefix --allow ,$(BACKUP_PATHS)) "$(BACKUP)"

install: backup
	@$(MAKE) --no-print-directory build
	sudo install -d -m 0755 $(LIBEXEC)/lib/agent_policy $(PREFIX)/bin $(CLAUDE_MANAGED_DIR) $(CODEX_SYSTEM_DIR)
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

uninstall: backup
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
	rm -rf dist .coverage .coverage.* coverage.xml
