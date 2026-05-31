# AGENTS.md

This file gives AI coding assistants project-specific guidance. It is intentionally tool-neutral and does not depend on local agent, skill, or plugin directories.

## Project Goal

`rand-guard` is a Rust eBPF EDR built for deep systems and security study. Prioritize a small, correct, explainable EDR pipeline over broad but shallow feature coverage.

The current working slice is a minimum end-to-end EDR loop:

- Collect process lifecycle and selected file events with eBPF tracepoints.
- Collect network `connect`, `bind`, and `listen` syscall telemetry when explicitly enabled.
- Deliver events to userspace through the `EVENTS` ring buffer.
- Normalize events into stable Rust structs and enrich them with a userspace process table.
- Output newline-delimited JSON for tests, demos, telemetry, and alerts.
- Apply built-in persistence-sensitive file detections from `[[detections.persistence]]`.
- Apply built-in suspicious network port detections from `[[detections.network]]`.
- Emit separate `event_type = "alert"` records for matching MVP `[[rules]]` and built-in rule-engine rules.
- Apply optional `process_names` filtering to network detection rules.

Generic `[[rules]]` evaluation is implemented as an MVP userspace rule engine over normalized events. Enabled `process`, `file`, and `network` rules are supported when they use the current simple matcher fields.

Network collection is implemented for `connect`, `bind`, and `listen` syscall tracepoints only. DNS collection, payload collection, `accept`/`accept4`, socket lifecycle correlation, and listen-to-bind socket table enrichment are not implemented.

## Repository Shape

- `crates/ebpf`: `no_std` eBPF programs using Aya. Keep verifier constraints, bounded memory access, and small stack usage in mind.
- `crates/user`: userspace loader/runtime using Aya and Tokio. Owns config loading, privilege checks, ring-buffer event consumption, normalization/enrichment, built-in detections, JSON output, and shutdown.
- `crates/common`: shared kernel/userspace event schemas. Types crossing the eBPF/userspace boundary must be ABI-stable and `#[repr(C)]`.
- `xtask`: project automation for build, check, clippy, test, run, package, throughput, and CI smoke workflows.
- `docs`: public architecture, threat model, roadmap, benchmark, demo, and quickstart documentation.

## Engineering Principles

- Prefer the smallest working slice that can be built, tested, and explained.
- Treat kernel-space code as constrained code: avoid allocation, recursion, unbounded loops, panics, and complex parsing in eBPF.
- Keep raw syscall/tracepoint collection separate from normalized EDR events.
- Put policy and detection logic in userspace unless a kernel-side filter is required for performance or safety.
- Keep common event structs simple, fixed-size, and explicit about truncation.
- Preserve readability: add short docs and examples when a feature teaches an important eBPF, Linux, or EDR concept.
- Do not add broad compatibility layers unless there is a concrete kernel/version/user requirement.
- Keep documentation aligned with implemented behavior. Do not imply support for unimplemented DNS, payload, `accept`/`accept4`, socket lifecycle correlation, or broad multi-event rule correlation.

## eBPF Rules

- `crates/ebpf` must remain `#![no_std]` and `#![no_main]`.
- Any shared event sent through maps must live in `crates/common` and use `#[repr(C)]`.
- Validate string and pointer reads carefully. Failed helper calls should discard incomplete events rather than emit misleading data.
- For sockaddr reads, keep parsing bounded and limited to stable fixed fields. The current implementation parses AF_INET and AF_INET6 addresses and emits unknown families without address metadata.
- Prefer ring buffer events for the MVP unless a feature specifically needs perf events or another map type.
- Keep map sizes and event payloads intentionally small until throughput is measured.

## Userspace Rules

- Userspace owns config, logging, graceful shutdown, output formatting, enrichment, built-in detection matching, rule evaluation, and demo-friendly reporting.
- Runtime errors should include context with `anyhow::Context` where it helps debugging.
- CI smoke behavior must stay deterministic and short.
- Avoid hiding privilege requirements. Loading eBPF generally requires root or appropriate capabilities.

## Documentation Rules

- Public docs are written in English.
- Keep `README.md` as the open-source entry point and put detailed material in dedicated docs.
- Link to existing docs rather than duplicating long explanations when possible.
- Keep security reporting guidance aligned with `SECURITY.md`.
- Keep branch and contribution guidance aligned with `CONTRIBUTING.md`.

## Detection Work

Build visibility before detection breadth:

1. Process execution and lifecycle: implemented with `execve`, `fork`, `exit`, and `execveat` correlation.
2. File and persistence-sensitive path visibility: implemented for open, write, rename, and unlink syscall families, with userspace watch/exclude path filtering.
3. Network connection/listen visibility: implemented for `connect`, `bind`, and `listen` syscall families.
4. Generic rule engine MVP: implemented for single-event process/file/network matches.
5. Scenario-based detections such as reverse shell, web shell execution, credential access, systemd persistence, and drop-and-execute.
6. Hardening, performance measurement, packaging, and collaboration docs.

Detection work should include:

- Event fields required by the rule.
- Likely false positives.
- Test or demo command when practical.
- Short explanation of the attacker behavior being modeled.

## Validation Commands

Use `xtask` from the repository root.

- Format: `cargo run -p xtask -- format`
- CI format check: `cargo run -p xtask -- ci-format`
- Check all crates: `cargo run -p xtask -- check`
- Clippy all crates: `cargo run -p xtask -- clippy`
- Userspace tests: `cargo run -p xtask -- test`
- Build release artifacts: `cargo run -p xtask -- build`
- Package release artifacts: `cargo run -p xtask -- package`
- Local throughput measurement: `cargo run -p xtask -- throughput`
- CI smoke load/unload: `cargo run -p xtask -- ci-smoke`

Cargo aliases are also available, such as `cargo xf`, `cargo xc`, `cargo xl`, `cargo xt`, `cargo xb`, and `cargo xcs`.

## Commit Guidelines

- Keep commits focused around one working slice.
- Prefer messages such as `docs: prepare collaboration guide`, `feat: capture exec event fields`, or `test: add smoke coverage for exec events`.
- Before committing code changes, run at least `cargo run -p xtask -- ci-format`, `cargo run -p xtask -- check`, and the most relevant test/build command.
- Do not commit generated build outputs under `target/` or local output under `.local/`.
- Do not commit unless explicitly asked.
