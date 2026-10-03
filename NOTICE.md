# Notice

agent-policy ships no vendored third-party code. The guard, the scratchpad
helper and the tools use the Python standard library only.

The test image (`Containerfile.test`) installs the Codex CLI from npm at
build time, to check the rendered Codex rules with Codex itself. It is a
test dependency, not distributed with this repository.

Copyright 2026 Ivan Pinatti, licensed under the Apache License, Version 2.0.
See [LICENSE.md](LICENSE.md) for the full terms.
