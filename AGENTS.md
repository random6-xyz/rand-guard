# AGENTS.md

## Project Goal

This project is a Rust eBPF EDR built for deep systems/security study. Prioritize a small, correct, explainable EDR pipeline over broad but shallow feature coverage.

The current near-term goal is a minimum end-to-end EDR loop:

- collect kernel events with eBPF
- deliver events to userspace safely
- normalize events into stable Rust structs
- output observable results for tests, demos, and future detection rules

## Repository Shape

- `crates/ebpf`: no_std eBPF programs using Aya. Keep verifier constraints, bounded memory access, and small stack usage in mind.
- `crates/user`: userspace loader/runtime using Aya and Tokio. Owns config loading, privilege checks, event consumption, enrichment, output, and shutdown.
- `crates/common`: shared kernel/userspace event schemas. Types crossing the eBPF/userspace boundary must be ABI-stable and `#[repr(C)]`.
- `xtask`: project automation for build, check, clippy, test, run, and CI smoke workflows.

## Engineering Principles

- Prefer the smallest working slice that can be built, tested, and explained.
- Treat kernel-space code as constrained code: avoid allocation, recursion, unbounded loops, panics, and complex parsing in eBPF.
- Keep raw syscall/tracepoint collection separate from normalized EDR events.
- Put policy and detection logic in userspace unless a kernel-side filter is required for performance or safety.
- Keep common event structs simple, fixed-size, and explicit about truncation.
- Preserve readability: add short docs and examples when a feature teaches an important eBPF, Linux, or EDR concept.
- Do not add broad compatibility layers unless there is a concrete kernel/version/user requirement.

## eBPF Rules

- `crates/ebpf` must remain `#![no_std]` and `#![no_main]`.
- Any shared event sent through maps must live in `crates/common` and use `#[repr(C)]`.
- Validate string and pointer reads carefully. Failed helper calls should discard incomplete events rather than emit misleading data.
- Prefer ring buffer events for the MVP unless a feature specifically needs perf events or another map type.
- Keep map sizes and event payloads intentionally small until throughput is measured.

## Userspace Rules

- Userspace owns config, logging, graceful shutdown, output formatting, enrichment, rule matching, and demo-friendly reporting.
- Runtime errors should include context with `anyhow::Context` where it helps debugging.
- CI smoke behavior must stay deterministic and short.
- Avoid hiding privilege requirements. Loading eBPF generally requires root or appropriate capabilities.

## Detection Roadmap

Build visibility before detection breadth:

1. process execution and lifecycle
2. file and persistence-sensitive path visibility
3. network connection/listen visibility
4. rule engine MVP
5. scenario-based detections such as reverse shell, web shell execution, credential access, systemd persistence, and drop-and-execute

Detection work should include:

- event fields required by the rule
- likely false positives
- test or demo command when practical
- short explanation of the attacker behavior being modeled

## Validation Commands

Use `xtask` from the repository root.

- Format: `cargo run -p xtask -- format`
- CI format check: `cargo run -p xtask -- ci-format`
- Check all crates: `cargo run -p xtask -- check`
- Clippy all crates: `cargo run -p xtask -- clippy`
- Userspace tests: `cargo run -p xtask -- test`
- Build release artifacts: `cargo run -p xtask -- build`
- CI smoke load/unload: `cargo run -p xtask -- ci-smoke`

Cargo aliases are also available, such as `cargo xf`, `cargo xc`, `cargo xl`, `cargo xt`, `cargo xb`, and `cargo xcs`.

## Commit Guidelines

- Keep commits focused around one working slice.
- Prefer messages such as `docs: add opencode project guidance`, `feat: capture exec event fields`, or `test: add smoke coverage for exec events`.
- Before committing code changes, run at least `cargo run -p xtask -- ci-format`, `cargo run -p xtask -- check`, and the most relevant test/build command.
- Do not commit generated build outputs under `target/`.
- Can suggest to commit. But do not commit before the user explictly mention.

## Tools Usage

Use project agents and skills under `.opencode/` for focused work:

- `ebpf-implementer`: implement kernel/userspace Rust eBPF changes.
- `edr-architect`: design EDR pipeline, event schema, and detection roadmap changes.
- `security-reviewer`: review eBPF safety, verifier risk, detection quality, and operational risks.
- `repo-explorer`: quickly explain project structure and locate relevant code.
