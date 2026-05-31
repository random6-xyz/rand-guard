# Roadmap

`rand-guard` prioritizes a small, correct, explainable EDR pipeline over broad feature coverage. This roadmap is intentionally conservative and reflects the current MVP state.

## Implemented MVP

- Process lifecycle collection for `execve`, `execveat`, `fork`, and `exit`.
- File collection for open, write, rename, and unlink syscall families.
- File watch, pattern, and exclude filtering in the current configuration model.
- Optional network syscall telemetry for `connect`, `bind`, and `listen`.
- Shared fixed-layout event structs in `crates/common`.
- Ring-buffer delivery through the `EVENTS` map.
- Userspace normalization and process context enrichment.
- Stdout newline-delimited JSON output.
- Built-in persistence-sensitive file detections.
- Built-in suspicious network port detections.
- MVP `[[rules]]` support for process, file, and network single-event matching.
- Stable `event_type = "alert"` records for rule matches.
- Packaging, systemd service files, installer script, quickstart docs, and CI checks.

## Near-Term Work

- Improve collaboration docs and issue templates.
- Expand tests around rule evaluation and alert output stability.
- Add more realistic demo scenarios while keeping them safe and reversible.
- Improve benchmark documentation and local reproducibility.
- Tighten config validation errors and troubleshooting guidance.
- Continue documenting false positives for built-in detections.

## Contribution-Friendly Areas

- Add focused tests for existing process, file, network, and rule-engine behavior.
- Improve examples and sample rules without expanding the runtime contract too broadly.
- Document more false positives and expected benign activity for built-in detections.
- Improve installer and packaging ergonomics.
- Improve CI coverage for docs, config examples, and packaging metadata.
- Add small, well-scoped fields to normalized events when they can be collected safely and tested.

## Longer-Term Research

- Scenario-based detections such as reverse shell, web shell execution, credential access, systemd persistence, and drop-and-execute.
- Safer and richer rule-engine semantics after the single-event MVP is stable.
- Socket lifecycle correlation if it can be implemented with clear kernel/userspace boundaries.
- Operational hardening around service supervision, output routing, and deployment documentation.
- Performance measurement under more workloads and kernel versions.

## Explicit Non-Goals For Now

- DNS collection.
- Network payload collection.
- `accept` or `accept4` telemetry.
- Full socket lifecycle correlation.
- Regex or expression-DSL rule matching.
- Multi-event time-window correlation.
- Automatic response actions such as blocking, killing, or quarantining.
- Tamper-proof logging or remote management.
- Production EDR parity.

## How To Propose Roadmap Changes

Open a feature request with the use case, required event fields, likely false positives, safety or performance concerns, and a practical validation plan. Security vulnerabilities should be reported through GitHub Security Advisories instead of public issues.
