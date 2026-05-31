# Security Policy

`rand-guard` is a study-focused Rust eBPF EDR. It runs privileged code when loading eBPF programs, so vulnerabilities should be reported privately.

## Reporting A Vulnerability

Use GitHub Security Advisories for this repository.

Do not open a public GitHub issue for:

- Privilege boundary problems.
- eBPF verifier safety issues.
- Crashes or denial-of-service paths that affect privileged runtime behavior.
- Sensitive telemetry leaks.
- Bypass details for implemented detections.
- Exploit proof-of-concepts that could harm users or test systems.

## What To Include

Include enough information to reproduce and assess the issue safely:

- Affected commit, branch, or release artifact.
- Host distribution and kernel version.
- Relevant config or rule snippets with secrets removed.
- Build and run commands used.
- Expected behavior and observed behavior.
- Logs or NDJSON output with sensitive paths, users, IP addresses, hostnames, and tokens redacted.
- A minimal reproduction if it is safe to share privately.

Do not publish exploit steps publicly before the issue is resolved.

## Supported Versions

This repository is currently pre-1.0 and study-focused. Unless a release policy is added later, security work targets the active development branch and current release artifacts.

## Response Expectations

There is no commercial support SLA. Reports will be reviewed on a best-effort basis. Valid reports should result in one or more of:

- A code fix.
- A configuration or documentation change.
- A clear explanation of why the behavior is outside the current threat model.
- A public advisory after the issue can be safely disclosed.

## Handling Telemetry

Runtime output can include process names, executable paths, file paths, user IDs, group IDs, ports, and IP addresses. Treat it as sensitive security telemetry. Redact private data before attaching logs to any report.
