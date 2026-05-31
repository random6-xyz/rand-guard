---
name: Bug report
about: Report a reproducible rand-guard bug
title: "bug: "
labels: bug
assignees: ""
---

## Security Check

Do not use this public template for vulnerabilities, exploitable crashes, sensitive telemetry leaks, or detection bypass details. Report those through GitHub Security Advisories.

## Summary

Describe the bug clearly.

## Environment

- rand-guard commit or version:
- Linux distribution:
- Kernel version (`uname -a`):
- Rust stable version (`rustc --version`):
- Rust nightly version (`rustup run nightly rustc --version`):
- `bpf-linker` version if relevant:

## Configuration

Paste the relevant config or rule snippet. Redact secrets, private paths, usernames, hostnames, and internal IP addresses.

```toml

```

## Commands Run

```sh

```

## Expected Behavior

What did you expect to happen?

## Observed Behavior

What happened instead?

## Logs Or Output

Paste relevant logs or NDJSON output. Redact sensitive telemetry.

```text

```

## Reproduction Steps

1. 
2. 
3. 

## Validation Already Tried

- [ ] `cargo run -p xtask -- ci-format`
- [ ] `cargo run -p xtask -- check`
- [ ] `cargo run -p xtask -- test`
- [ ] `cargo run -p xtask -- build`
- [ ] `cargo run -p xtask -- ci-smoke`

## Additional Context

Add anything else that helps diagnose the issue.
