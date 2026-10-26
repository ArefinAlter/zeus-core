# Security policy

Zeus handles session cookies, runs a local daemon and writes files from untrusted servers, so security reports are taken seriously.

## Reporting a vulnerability

Please report privately by email to **info@vernesystems.com** with a subject starting `SECURITY:` (the same address as the [website's security policy](https://zeus-site-bay.vercel.app/legal/security/)). GitHub's private vulnerability reporting is not enabled on this repository. Do not open a public issue or pull request for a suspected vulnerability.

Include: affected component and version or commit, a description and impact, steps or a proof of concept, and whether you want to be credited. Do not include real cookies, tokens or personal data.

You can expect an acknowledgement within 5 working days. We aim to triage within 10 working days and to fix confirmed high-severity issues before public disclosure, coordinating a disclosure date with you. Zeus is pre-alpha and maintained by volunteers, so these are targets, not guarantees.

## Scope

In scope: the `zeus`, `zeus-core` and `zeus-extension` repositories, in particular:

- leakage of session material (logs, events, audit records, API results, crash dumps);
- any way for an agent-kind client, a web page or a remote server to approve a request, create a grant or read cookies;
- local IPC authentication, endpoint squatting and privilege issues;
- native-messaging origin pinning and framing;
- path traversal, symlink or reparse-point escapes, reserved-name tricks, archive bombs;
- redaction failures (secrets in URLs);
- supply-chain issues in our own build and release process.

Out of scope: attacks that require an attacker already running arbitrary code as the same OS user and driving a terminal (documented residual risk, ADR 0007), denial of service by a user against their own machine, findings in third-party dependencies without a Zeus-specific impact (report those upstream), and social engineering.

## Supported versions

There are no releases yet. Only the `main` branch receives fixes.

## Design references

The threat model and security invariants are specified in the `zeus` repository (`docs/spec`, document 12) and summarised in `docs/ARCHITECTURE.md`.
