# rand-guard

`rand-guard` is a small Rust eBPF EDR built for systems and security study. It focuses on a correct, explainable telemetry pipeline rather than broad product-style feature coverage.

The current agent can collect process, file, and opt-in network syscall telemetry, normalize it in userspace, enrich events with process context, and print newline-delimited JSON for tests, demos, and future detection rules.

## Current Capabilities

- Process lifecycle visibility for `execve`, `execveat`, `fork`, and `exit`.
- File visibility for open, write, rename, and unlink syscall families.
- Network visibility for `connect`, `bind`, and `listen` syscall tracepoints when explicitly enabled.
- Shared ABI in `crates/common` using fixed-layout `#[repr(C)]` structs.
- eBPF to userspace delivery through the `EVENTS` ring buffer.
- Userspace process table enrichment for `ppid`, `comm`, and `exe_path` when available.
- NDJSON output to stdout.
- Built-in persistence detections from `[[detections.persistence]]`.
- Built-in suspicious network port detections from `[[detections.network]]`.

## Current Limits

- Generic `[[rules]]` are not evaluated yet. Enabled rules fail config validation until the rule-engine slice is implemented.
- Network collection supports only `connect`, `bind`, and `listen`.
- DNS collection, payload collection, `accept`/`accept4`, and socket lifecycle correlation are not implemented.
- `listen` events currently include `fd` and `backlog`; local address/port require future bind-to-listen correlation.
- Runtime output is stdout JSON only.
- Loading eBPF programs requires root or sufficient Linux capabilities such as `CAP_BPF` and `CAP_PERFMON` on supported kernels.

## Repository Layout

- `crates/common`: shared event schema and ABI constants.
- `crates/ebpf`: `no_std` Aya eBPF programs and ring-buffer event producers.
- `crates/user`: userspace loader, config validation, ring-buffer consumer, normalization, enrichment, detections, and JSON output.
- `xtask`: project automation for format, check, clippy, tests, builds, run, and CI smoke.
- `config.example.toml`: example runtime config and built-in detection configuration.

## Requirements

- Linux with eBPF and BTF support for runtime loading.
- Stable Rust for userspace crates.
- Nightly Rust with `rust-src` for the eBPF target.
- `bpf-linker` for building the eBPF object.
- Root or suitable capabilities for actual agent execution.

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

`ci-smoke` and `run` load eBPF and generally require `sudo`:

```sh
cargo run -p xtask -- ci-smoke
cargo run -p xtask -- run
```

## Configuration

The example config keeps network collection disabled by default to keep local and CI behavior low-noise:

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

Generic `[[rules]]` entries may be present as future configuration examples, but they must remain `enabled = false` until the rule engine is implemented.

## Output

The agent writes one JSON object per line. Process events look like:

```json
{"event_type":"process_start","pid":100,"tid":100,"ppid":1,"comm":"bash","exe_path":"/usr/bin/bash","source":"execve","timestamp_ns":123}
```

File detections include alert fields:

```json
{"event_type":"file_open","pid":100,"filename":"/etc/systemd/system/demo.service","alert":true,"detection_type":"systemd_service_modified"}
```

Network events include connection or listener metadata:

```json
{"event_type":"network_connect","pid":100,"comm":"nc","family":"ipv4","socket_fd":3,"remote_addr":"127.0.0.1","remote_port":4444,"alert":true,"detection_type":"suspicious_outbound_port"}
```

## Built-In Detections

Persistence detections are configured under `[[detections.persistence]]` and match canonical operations such as `file_open`, `file_write`, `file_rename`, and `file_unlink`.

Network detections are configured under `[[detections.network]]` and currently match direction plus port:

```toml
[[detections.network]]
name = "suspicious_outbound_port"
directions = ["outbound"]
ports = [4444, 1337, 31337]
```

Expected false positives include netcat labs, CTF tooling, debug listeners, local tunnels, and remote shell experiments.
