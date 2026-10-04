# Security Policy

## Supported Versions

Only the latest release receives fixes. The policy is installed from a
checkout (`make install`), so updating means pulling `main` and installing
again.

| Version        | Supported |
| -------------- | --------- |
| latest release | Yes       |
| anything older | No        |

A way for an agent to run a command the policy refuses or should ask about
(a spelling the guard does not parse, a wrapper it does not peel off) is a
security issue for this project. Report it privately as below rather than
in a public issue, since the bypass works on every machine that installs
the policy until it is fixed.

## Reporting a Vulnerability

Please do not open a public issue for a security vulnerability. Instead,
use GitHub's private
[report a vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
feature on this repository, if enabled, or contact the maintainer listed in
[.github/CODEOWNERS](.github/CODEOWNERS) through their GitHub profile.

Please include as much detail as possible: steps to reproduce, affected
versions, and the potential impact. Expect an initial response within a
reasonable time, though as an individually maintained project there is no
guaranteed response window.
