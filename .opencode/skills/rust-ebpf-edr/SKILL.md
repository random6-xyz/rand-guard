---
name: rust-ebpf-edr
description: Use when editing Rust Aya eBPF EDR code in crates/ebpf, crates/user, or crates/common, especially event schemas, maps, tracepoints, and ring buffer delivery.
---

# Rust eBPF EDR

Use this skill for implementation work that touches the Rust eBPF telemetry pipeline.

## Working Model

- `crates/ebpf` collects minimal kernel telemetry.
- `crates/common` defines the ABI between eBPF and userspace.
- `crates/user` loads programs, consumes the `EVENTS` ring buffer, enriches events, handles config/output, and applies built-in detections.

Current runtime support:

- Process hooks: `execve`, `execveat`, `fork`, `exit`.
- File hooks: `openat`, `openat2`, `write`, `writev`, `pwrite64`, `rename`, `renameat`, `renameat2`, `unlink`, `unlinkat`.
- Network hooks: `connect`, `bind`, `listen` when both `[events].network` and `[network].enabled` are true.
- DNS collection, payload collection, `accept`/`accept4`, socket lifecycle correlation, and listen-to-bind socket table enrichment are not supported yet.
- Enabled generic `[[rules]]` are rejected by runtime validation until the rule engine is implemented.

## eBPF Constraints

- Keep eBPF code `no_std`, allocation-free, panic-free, and verifier-friendly.
- Avoid recursion, unbounded loops, large stack objects, and complex parsing.
- Check helper return values. Discard incomplete events rather than emit misleading events.
- Use fixed-size buffers for strings and paths. Document truncation at userspace boundaries.
- Keep kernel-side filtering simple and measurable.

## ABI Checklist

- Shared event structs live in `crates/common`.
- Event structs crossing maps use `#[repr(C)]`.
- Prefer fixed-width integer types and fixed-size arrays.
- Avoid Rust types with unstable layout across the boundary, such as `String`, `Vec`, `Option`, or references.
- Update both producer and consumer when event fields change.

## Validation

Prefer these commands from repo root:

- `cargo run -p xtask -- check`
- `cargo run -p xtask -- clippy`
- `cargo run -p xtask -- build`
- `cargo run -p xtask -- ci-smoke`

For code-only edits, run the narrowest command that exercises the changed crate. For map/schema changes, run at least check/build when feasible.
