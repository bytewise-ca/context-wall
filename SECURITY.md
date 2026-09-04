# Security Policy

## Reporting a vulnerability

If you find a security issue in ContextWall itself, please **do not** open
a public GitHub issue.

Instead, report it privately via:

- **Email:** `security@bytewise.ca` (or `info@bytewise.ca` as a fallback)
- **GitHub Security Advisories:** [Create a private advisory](https://github.com/bytewise-ca/context-wall/security/advisories/new)

Please include:

- A short description of the issue
- Steps to reproduce (a minimal PoC if possible)
- The version of ContextWall affected
- Your contact info for follow-up

## What counts as a vulnerability in ContextWall

- The daemon or CLI can be tricked into exposing secrets or bypassing its own
  auth (e.g. authenticated endpoints reachable without a token).
- The Preflight grader has a systematic bug that classifies a real attack as
  a pass, or a safe response as a fail (grader-drift). File this as a
  security advisory only if the impact is significant; otherwise a
  [grader-drift issue](https://github.com/bytewise-ca/context-wall/issues/new?template=grader-drift.md)
  is the right channel.
- The Preflight scorecard leaks a real secret from evidence into terminal
  output, JSON, SARIF, or a hosted upload (redaction bypass).
- The MCP adapter invokes a write-capable or network-capable tool without
  explicit consent.
- Any dependency of ContextWall has a known vulnerability that materially
  affects users of ContextWall.

## Not a ContextWall vulnerability

- A prompt-injection payload that makes an agent misbehave — that's the
  problem ContextWall exists to help detect. Please add it as a fixture
  proposal instead, or a grader-drift report if the grader misclassifies
  a known-safe response.
- Your own deployment's authorization or configuration mistakes.
- Third-party MCP server vulnerabilities — please report those to the
  MCP server's own maintainers. If you'd like ContextWall to detect the
  pattern in future scans, open a fixture proposal.

## Response timeline

We aim to:

- **Acknowledge** within 3 business days.
- **Fix or reach a decision** within 30 days for reasonable-scope issues.
- **Disclose** coordinated with the reporter after a fix is released.

ContextWall is a small OSS project. We don't run a bug bounty. Public credit
in release notes / advisories is offered by default; opt out if you prefer.

## Scope

This policy applies to:

- `contextwall` (PyPI: [contextwall](https://pypi.org/project/contextwall/))
- `contextwall-sdk` (deprecated shim: [contextwall-sdk](https://pypi.org/project/contextwall-sdk/))
- The `bytewise-ca/context-wall` GitHub repository and its published wheels

The hosted control plane (if you use one) is out of scope for OSS Security
Advisories — report those directly via email.
