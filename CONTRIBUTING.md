# Contributing

Thanks for helping improve `rand-guard`. This project is a study-focused Rust eBPF EDR, so contributions should favor small, correct, explainable changes over broad feature additions.

## Project Scope

Before proposing larger work, read:

- [Architecture](docs/architecture.md)
- [Threat Model](docs/threat-model.md)
- [Roadmap](docs/roadmap.md)
- [Quickstart](docs/quickstart.md)

Current priorities are a reliable end-to-end telemetry pipeline, clear documentation, focused detections, deterministic tests, and safe eBPF code.

## Development Requirements

- Linux with eBPF, BTF, and tracepoint support for runtime loading.
- Stable Rust for userspace crates.
- Nightly Rust with `rust-src` for the eBPF target.
- `bpf-linker` for building the eBPF object.
- Root or suitable Linux capabilities for commands that load eBPF.

Install the Rust-side tooling:

```sh
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker --locked
```

## Common Commands

Run commands from the repository root.

```sh
cargo run -p xtask -- ci-format
cargo run -p xtask -- check
cargo run -p xtask -- test
cargo run -p xtask -- clippy
cargo run -p xtask -- build
```

Cargo aliases are available:

```sh
cargo xf   # format
cargo xc   # check
cargo xl   # clippy
cargo xt   # test
cargo xb   # build
cargo xcs  # CI smoke
```

Privileged runtime checks generally require `sudo` or suitable capabilities:

```sh
cargo run -p xtask -- run
cargo run -p xtask -- ci-smoke
```

## Expected Validation

For most pull requests, run:

```sh
cargo run -p xtask -- ci-format
cargo run -p xtask -- check
cargo run -p xtask -- test
```

Also run the most relevant extra command for your change:

- `cargo run -p xtask -- clippy` for non-trivial Rust changes.
- `cargo run -p xtask -- build` for eBPF, packaging, or release changes.
- `cargo run -p xtask -- throughput` for performance-sensitive runtime changes.
- `cargo run -p xtask -- ci-smoke` for changes that affect loading, attachment, or runtime event delivery.

If you cannot run a privileged command, explain that in the pull request and include the non-privileged checks you did run.

## eBPF Safety Expectations

Changes under `crates/ebpf` and shared event schemas are security-sensitive.

- Keep `crates/ebpf` `#![no_std]` and `#![no_main]`.
- Avoid allocation, recursion, panics, and unbounded loops.
- Keep loops bounded by compile-time constants.
- Keep stack usage small and predictable.
- Use bounded pointer and string reads.
- Discard incomplete events when helper reads fail.
- Keep shared ABI structs in `crates/common` and use `#[repr(C)]` where they cross the eBPF/userspace boundary.
- Put policy and detection logic in userspace unless kernel-side filtering is clearly needed.

## Detection Contributions

Detection changes should include:

- The attacker behavior being modeled.
- Required event fields.
- Expected false positives.
- A safe demo command or test when practical.
- Clear notes about what is not detected.

Prefer focused single-behavior detections over broad signatures that are difficult to explain or test.

## Pull Request Guidance

- Target pull requests at `dev`. The `main` branch is kept as the runnable/stable branch, while active development happens on `dev`.
- Use short branch names with a type prefix, such as `feat/<topic>`, `fix/<topic>`, `docs/<topic>`, `test/<topic>`, or `chore/<topic>`.
- Keep pull requests focused around one working slice.
- Update docs when behavior, config, output fields, detections, or commands change.
- Add tests for rule-engine, normalization, config, or output changes when practical.
- Do not commit generated build outputs under `target/` or local benchmark output under `.local/`.
- Do not include secrets, private telemetry, internal hostnames, or unredacted investigation data.

## Code Of Conduct

All contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting Security Issues

Do not open a public issue for a vulnerability. Use GitHub Security Advisories as described in [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contribution is provided under the repository license. See [LICENSE](LICENSE).
