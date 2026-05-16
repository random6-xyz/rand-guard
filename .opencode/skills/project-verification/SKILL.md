---
name: project-verification
description: Use when deciding how to verify, test, build, lint, smoke-test, or prepare commits for this Rust eBPF EDR repository.
---

# Project Verification

Use this skill for validation and commit preparation.

## Commands

Run from repository root.

- Format all: `cargo run -p xtask -- format`
- CI format check: `cargo run -p xtask -- ci-format`
- Check all: `cargo run -p xtask -- check`
- Clippy all: `cargo run -p xtask -- clippy`
- Userspace tests: `cargo run -p xtask -- test`
- Build release artifacts: `cargo run -p xtask -- build`
- CI smoke: `cargo run -p xtask -- ci-smoke`

Cargo aliases:

- `cargo xf`: format
- `cargo xc`: check
- `cargo xl`: clippy
- `cargo xt`: test
- `cargo xb`: build
- `cargo xcs`: CI smoke

## Validation Strategy

- Documentation-only changes usually need no Rust build, but inspect formatting and paths.
- Shared event schema changes should run check/build because they affect eBPF and userspace.
- eBPF hook/map changes should run check/build and, when feasible, `ci-smoke`.
- Userspace runtime changes should run check, clippy, and tests.
- CI or xtask changes should run the affected xtask command locally.

## Commit Hygiene

- Check `git status --short` before committing.
- Do not commit `target/` or local generated artifacts.
- Keep commits focused on one milestone or documentation slice.
- Use concise conventional-style messages when possible, for example `docs: add opencode project guidance`.
