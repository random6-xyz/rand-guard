# rand-guard

`rand-guard` is a small Rust eBPF EDR built for systems and security study. It prioritizes a correct, explainable end-to-end telemetry pipeline over broad product-style feature coverage.

The current agent collects process, file, and opt-in network syscall telemetry, normalizes events in userspace, enriches events with process context, evaluates focused detections and MVP rules, and writes newline-delimited JSON for tests, demos, telemetry, and alerts.

## Current Capabilities

- Process lifecycle visibility for `execve`, `execveat`, `fork`, and `exit`.
- File visibility for open, write, rename, and unlink syscall families.
- File `watch_paths`, `watch_patterns`, and `exclude_paths` filtering.
- Optional network visibility for `connect`, `bind`, and `listen` syscall tracepoints.
- Shared eBPF/userspace ABI in `crates/common` using fixed-layout structs.
- Ring-buffer delivery through the `EVENTS` map.
- Userspace process table enrichment for `ppid`, `comm`, and `exe_path` when available.
- Stdout newline-delimited JSON output.
- Built-in persistence-sensitive file detections.
- Built-in suspicious network port detections.
- MVP `[[rules]]` matching for process, file, and network events.
- Stable `event_type = "alert"` records for rule matches.

## Current Limits

- Rule matching is intentionally simple: no expression DSL, regex, multi-event correlation, or time windows.
- Network collection supports only `connect`, `bind`, and `listen`.
- DNS collection, payload collection, `accept`/`accept4`, and socket lifecycle correlation are not implemented.
- Runtime output is stdout JSON only.
- Loading eBPF programs requires root or sufficient Linux capabilities.
- The project is for deep systems/security study, not production EDR parity.

## Project Docs

- [Quickstart](docs/quickstart.md): build, package, install, run, and verify output.
- [Architecture](docs/architecture.md): end-to-end event flow and crate responsibilities.
- [Threat Model](docs/threat-model.md): trust boundaries, assets, assumptions, and non-goals.
- [Roadmap](docs/roadmap.md): implemented MVP, near-term work, contribution areas, and non-goals.
- [Contributing](CONTRIBUTING.md): setup, validation, PR expectations, and eBPF safety rules.
- [Security Policy](SECURITY.md): private vulnerability reporting through GitHub Security Advisories.
- [Code of Conduct](CODE_OF_CONDUCT.md): community behavior expectations and enforcement.
- [Benchmarks](docs/benchmarks.md): local throughput workflow and interpretation caveats.
- [Demo Scenarios](docs/demo-scenarios.md): safe local scenarios for current capabilities.
- [Example Config](config.example.toml): runtime settings, built-in detections, and sample MVP rules.
- [License](LICENSE): Apache License 2.0.

## Repository Layout

- `crates/common`: shared event schema and ABI constants.
- `crates/ebpf`: `no_std` Aya eBPF programs and ring-buffer event producers.
- `crates/user`: userspace loader, config validation, ring-buffer consumer, normalization, enrichment, detections, and JSON output.
- `xtask`: project automation for format, check, clippy, tests, builds, packaging, run, CI smoke, and throughput.
- `packaging`: default config, sample rules, systemd unit, and installer inputs.
- `docs`: collaboration, architecture, benchmark, demo, and quickstart documentation.

## Requirements

- Linux with eBPF, BTF, and tracepoint support.
- Stable Rust for userspace crates.
- Nightly Rust with `rust-src` for the eBPF target.
- `bpf-linker` for building the eBPF object.
- Root or suitable Linux capabilities for actual agent execution.

Install typical Rust tooling:

```sh
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker --locked
```

## Build And Verify

Run from the repository root:

```sh
cargo run -p xtask -- ci-format
cargo run -p xtask -- check
cargo run -p xtask -- test
cargo run -p xtask -- build
```

Cargo aliases are also available:

```sh
cargo xf   # format
cargo xc   # check
cargo xl   # clippy
cargo xt   # test
cargo xb   # build
cargo xcs  # CI smoke
```

Commands that load eBPF generally require `sudo` or suitable capabilities:

```sh
cargo run -p xtask -- run
cargo run -p xtask -- ci-smoke
```

## Quick Start

For the packaged install flow, see [Quickstart](docs/quickstart.md).

For development from the repository checkout:

```sh
cargo run -p xtask -- build
cargo run -p xtask -- run
```

With the default config, process and file events are enabled and network telemetry is disabled.

Generate a process event:

```sh
/bin/true
```

Generate a watched file event:

```sh
sudo sh -c 'printf "# rand-guard quickstart\n" > /etc/rand-guard-quickstart.service'
sudo rm -f /etc/rand-guard-quickstart.service
```

## Configuration

The example config keeps network collection disabled by default to reduce first-run noise:

```toml
[events]
process = true
file = true
network = false

[network]
enabled = false
hooks = ["connect", "bind", "listen"]
collect_dns = false
collect_payload = false
```

Enable network collection manually by setting both flags:

```toml
[events]
network = true

[network]
enabled = true
hooks = ["connect", "bind", "listen"]
collect_dns = false
collect_payload = false
```

See [config.example.toml](config.example.toml) for the full configuration shape.

## Output

The agent writes one JSON object per line. Process events look like:

```json
{"event_type":"process_start","timestamp_ns":123,"pid":100,"tid":100,"ppid":1,"uid":0,"gid":0,"comm":"bash","exe_path":"/usr/bin/bash","source":"execve","filename_truncated":false}
```

File events can include detection fields when a built-in persistence rule matches:

```json
{"event_type":"file_write","timestamp_ns":123,"pid":100,"comm":"systemctl","resolved_path":"/etc/systemd/system/demo.service","alert":true,"detection_type":"systemd_service_modified"}
```

Rule matches emit a separate stable alert event:

```json
{"event_type":"alert","timestamp_ns":123,"rule_id":"FILE-001","rule_name":"Sensitive file touched","rule_type":"file","severity":"high","action":"alert","source_event_type":"file_write","pid":100,"comm":"bash","path":"/etc/shadow","operation":"file_write"}
```

## Kernel And Capability Notes

The eBPF programs rely on modern kernel features:

- Bounded loops, typically kernel 5.3+.
- Ring buffers, kernel 5.8+.
- BTF support for modern eBPF loading.
- Tracepoint programs for scheduler and syscall events.

Loading eBPF requires one of:

- Root.
- `CAP_BPF` plus `CAP_PERFMON` on supported kernels.
- `CAP_SYS_ADMIN` on older kernels.

Verified environments include Ubuntu 22.04+ with kernel 5.15+, Fedora 38+ with kernel 6.2+, and Debian 12+ with kernel 6.1+. Older kernels may work with limitations but are not actively tested.

## Benchmarks And Demos

Run the local throughput workflow:

```sh
cargo run -p xtask -- throughput
```

The workflow writes local summaries under `.local/throughput/`. Treat those numbers as local comparison data, not project-wide guarantees. See [Benchmarks](docs/benchmarks.md).

Safe local demos are documented in [Demo Scenarios](docs/demo-scenarios.md).

## Contributing And Security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Keep changes focused, include relevant validation, and avoid committing generated output.

Contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

Report vulnerabilities privately through GitHub Security Advisories. Do not open public issues for exploitable crashes, verifier safety problems, sensitive telemetry leaks, or detection bypass details. See [SECURITY.md](SECURITY.md).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
