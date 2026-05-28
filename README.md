# rand-guard

`rand-guard` is a small Rust eBPF EDR built for systems and security study. It focuses on a correct, explainable telemetry pipeline rather than broad product-style feature coverage.

The current agent can collect process, file, and opt-in network syscall telemetry, normalize it in userspace, enrich events with process context, evaluate MVP rules, and print newline-delimited JSON for tests and demos.

## Current Capabilities

- Process lifecycle visibility for `execve`, `execveat`, `fork`, and `exit`.
- File visibility for open (`openat`, `openat2`), write (`write`, `writev`, `pwrite64`), rename (`rename`, `renameat`, `renameat2`), and unlink (`unlink`, `unlinkat`) syscall families, with `watch_paths`, `watch_patterns`, and `exclude_paths` filtering.
- Network visibility for `connect`, `bind`, and `listen` syscall tracepoints when explicitly enabled.
- Shared ABI in `crates/common` using fixed-layout `#[repr(C)]` structs.
- eBPF to userspace delivery through the `EVENTS` ring buffer.
- Userspace process table enrichment for `ppid`, `comm`, and `exe_path` when available.
- NDJSON output to stdout.
- MVP `[[rules]]` matching for process, file, and network normalized events.
- Stable alert events with `event_type = "alert"`.
- Built-in persistence detections from `[[detections.persistence]]`.
- Built-in suspicious network port detections from `[[detections.network]]`.

## Current Limits

- Rule matching is intentionally simple: no expression DSL, regex, multi-event correlation, or time windows yet.
- Network collection supports only `connect`, `bind`, and `listen`.
- DNS collection, payload collection, `accept`/`accept4`, and socket lifecycle correlation are not implemented.
- `listen` events include `socket_fd`, `backlog`, `local_addr`, and `local_port` parsed directly from the syscall.
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

## Kernel Compatibility

The eBPF programs use features that require specific kernel versions:

- **Bounded loops** (kernel 5.3+): Used in `file_passes_filter()` for prefix matching with compile-time constant bounds (`FILE_FILTER_MAX_PREFIXES = 8`, `FILE_FILTER_PREFIX_LEN = 64`).
- **Ring buffer** (kernel 5.8+): The `EVENTS` map uses `BPF_MAP_TYPE_RINGBUF` for efficient event delivery from kernel to userspace.
- **BTF support**: Required for CO-RE (Compile Once – Run Everywhere) and modern BPF program loading. Most distributions since Linux 5.2 include BTF.
- **Tracepoint programs**: Attached to kernel tracepoints (`sched_process_exec`, `sched_process_exit`, `sched_process_fork`, `sys_enter_*`, `sys_exit_*`).

### Capability Requirements

Loading eBPF programs requires one of:

- **Root** (UID 0)
- **CAP_BPF + CAP_PERFMON** (kernel 5.8+): Fine-grained capabilities for BPF operations and performance monitoring.
- **CAP_SYS_ADMIN** (legacy): Older kernels require this broad capability.

Check capabilities on a running system:

```sh
# Check if running as root
id -u

# Check effective capabilities
cat /proc/self/status | grep Cap

# Grant capabilities to the binary (requires root)
sudo setcap 'cap_bpf,cap_perfmon+ep' target/release/edr-user
```

### Verified Kernels

Tested on:

- Ubuntu 22.04+ (kernel 5.15+)
- Fedora 38+ (kernel 6.2+)
- Debian 12+ (kernel 6.1+)

Older kernels (4.18–5.2) may work with limitations but are not actively tested. Kernels before 4.15 lack eBPF tracepoint support entirely.

### eBPF Verifier Constraints

All eBPF programs satisfy verifier requirements:

- **No unbounded loops**: All loops use compile-time constant bounds.
- **Bounded memory access**: String reads use `bpf_probe_read_user_str_bytes()` with fixed-size buffers.
- **Fixed stack usage**: No dynamic allocation; event structs are `#[repr(C)]` with known sizes.
- **No recursion or function pointer calls**: Programs use direct function calls only.
- **Helper call validation**: Failed helper calls discard incomplete events rather than emit misleading data.

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

## Throughput Measurement

Run the local throughput workflow from the repository root:

```sh
cargo run -p xtask -- throughput
```

The workflow builds release artifacts, starts `edr-user` with a temporary config, generates controlled file-write volume under `/tmp/rand_guard_throughput`, parses `event_type = "health"` records, and writes a Markdown summary under `.local/throughput/`.

The default benchmark keeps process collection enabled but disables process hooks so the measurement focuses on file-write throughput. Network collection is also disabled. Override the run length with environment variables:

```sh
EDR_THROUGHPUT_DURATION_SECS=30 \
EDR_THROUGHPUT_GENERATOR_SECS=25 \
cargo run -p xtask -- throughput
```

The summary includes total raw events, normalized events/sec, userspace drops/sec, max observed RSS, and final process cache sizes. Treat these results as local comparison data, not CI pass/fail thresholds; values depend on kernel version, CPU, disk, scheduler load, and active background processes.

This command loads eBPF and generally requires `sudo` or suitable capabilities. Generated result files are intentionally ignored by git through `.local/`.

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

Supported file hooks: `openat`, `openat2`, `write`, `writev`, `pwrite64`, `rename`, `renameat`, `renameat2`, `unlink`, `unlinkat`.

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

`monitor` and `detect` modes both emit telemetry; matching rules additionally emit adjacent alert records. MVP `[[rules]]` entries support these fields:

```toml
[[rules]]
id = "FILE-001"
name = "Sensitive file touched"
enabled = true
type = "file"
severity = "high"
action = "alert"
paths = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
operations = ["file_open", "file_write", "file_unlink", "file_rename"]
```

Process rules match `process_names` and/or `parent_names`. File rules match `paths`, optional `patterns`, and canonical operations. Network rules match `direction`, `ports`, and optional `process_names`. File rules also accept short operation aliases (`open`, `write`, `rename`, `unlink`) and a `*` wildcard.

## Output

The agent writes one JSON object per line. Process events look like:

```json
{"event_type":"process_start","timestamp_ns":123,"pid":100,"tid":100,"ppid":1,"uid":0,"gid":0,"comm":"bash","exe_path":"/usr/bin/bash","source":"execve","filename_truncated":false}
```

File events include detection fields when a built-in persistence rule matches:

```json
{"event_type":"file_open","timestamp_ns":123,"pid":100,"tid":100,"ppid":1,"uid":0,"gid":0,"comm":"systemctl","exe_path":"/usr/bin/systemctl","filename":"/etc/systemd/system/demo.service","flags":64,"filename_truncated":false,"alert":true,"detection_type":"systemd_service_modified"}
```

Network events include connection or listener metadata:

```json
{"event_type":"network_connect","timestamp_ns":123,"pid":100,"tid":100,"ppid":1,"uid":1000,"gid":1000,"comm":"nc","exe_path":"/usr/bin/nc","family":"ipv4","socket_fd":3,"remote_addr":"127.0.0.1","remote_port":4444,"alert":true,"detection_type":"suspicious_outbound_port"}
```

Listen events include local address, port, and backlog:

```json
{"event_type":"network_listen","timestamp_ns":123,"pid":100,"tid":100,"ppid":1,"uid":0,"gid":0,"comm":"nc","exe_path":"/usr/bin/nc","family":"ipv4","socket_fd":3,"local_addr":"0.0.0.0","local_port":4444,"backlog":128,"alert":false,"detection_type":null}
```

Rule matches emit a separate stable alert event immediately after the source telemetry event:

```json
{"event_type":"alert","timestamp_ns":123,"rule_id":"FILE-001","rule_name":"Sensitive file touched","rule_type":"file","severity":"high","action":"alert","source_event_type":"file_write","pid":100,"tid":100,"ppid":1,"uid":0,"gid":0,"comm":"bash","exe_path":"/usr/bin/bash","process_name":"bash","parent_name":null,"path":"/etc/shadow","operation":"file_write","direction":null,"port":null,"addr":null,"family":null}
```

## Built-In Detections

Persistence detections are configured under `[[detections.persistence]]` and match canonical operations such as `file_open`, `file_write`, `file_rename`, and `file_unlink`.

Network detections are configured under `[[detections.network]]` and currently match direction plus port, with optional process name filtering:

```toml
[[detections.network]]
name = "suspicious_outbound_port"
directions = ["outbound"]
ports = [4444, 1337, 31337]
# process_names = ["nc", "ncat"]  # optional: restrict to specific processes
```

Expected false positives include netcat labs, CTF tooling, debug listeners, local tunnels, and remote shell experiments.

The rule engine also loads first built-in rules for systemd service modifications, cron configuration modifications, and suspicious outbound ports. The older `[[detections.persistence]]` and `[[detections.network]]` paths remain for compatibility with event-local `alert` and `detection_type` fields.
