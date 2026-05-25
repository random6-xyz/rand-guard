# rand-guard

`rand-guard` is a small Rust eBPF EDR built for systems and security study. It focuses on a correct, explainable telemetry pipeline rather than broad product-style feature coverage.

The current agent can collect process, file, and opt-in network syscall telemetry, normalize it in userspace, enrich events with process context, evaluate MVP rules and built-in scenario detections, and print newline-delimited JSON for tests and demos.

## Current Capabilities

- Process lifecycle visibility for `execve`, `execveat`, `fork`, and `exit`.
- File visibility for open, write, rename, and unlink syscall families.
- Network visibility for `connect`, `bind`, and `listen` syscall tracepoints when explicitly enabled.
- Shared ABI in `crates/common` using fixed-layout `#[repr(C)]` structs.
- eBPF to userspace delivery through the `EVENTS` ring buffer.
- Userspace process table enrichment for `ppid`, `comm`, and `exe_path` when available.
- NDJSON output to stdout.
- MVP `[[rules]]` matching for process, file, and network normalized events.
- Stable alert events with `event_type = "alert"`.
- Built-in persistence detections from `[[detections.persistence]]`.
- Built-in suspicious network port detections from `[[detections.network]]`.
- Built-in scenario alerts for reverse shell behavior, web shell process execution, credential path access, systemd persistence, and suspicious binary drop-and-execute.

## Current Limits

- Rule matching is intentionally simple: no expression DSL or regex. Multi-event correlation is limited to built-in scenario detections with a fixed 10 second userspace window.
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

Process rules match `process_names` and/or `parent_names`. File rules match `paths`, optional `patterns`, and canonical operations. Network rules match `direction`, `ports`, and optional `process_names`.

## Output

The agent writes one JSON object per line. Process events look like:

```json
{"event_type":"process_start","pid":100,"tid":100,"ppid":1,"comm":"bash","exe_path":"/usr/bin/bash","source":"execve","timestamp_ns":123}
```

File detections still include legacy event-local alert fields:

```json
{"event_type":"file_open","pid":100,"filename":"/etc/systemd/system/demo.service","alert":true,"detection_type":"systemd_service_modified"}
```

Network events include connection or listener metadata:

```json
{"event_type":"network_connect","pid":100,"comm":"nc","family":"ipv4","socket_fd":3,"remote_addr":"127.0.0.1","remote_port":4444,"alert":true,"detection_type":"suspicious_outbound_port"}
```

Rule matches emit a separate stable alert event immediately after the source telemetry event:

```json
{"event_type":"alert","timestamp_ns":123,"rule_id":"FILE-001","rule_name":"Sensitive file touched","rule_type":"file","severity":"high","action":"alert","source_event_type":"file_write","pid":100,"tid":100,"ppid":1,"uid":0,"gid":0,"comm":"bash","exe_path":"/usr/bin/bash","path":"/etc/shadow","operation":"file_write"}
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

The rule engine also loads built-in alert rules for systemd service modifications, cron configuration modifications, suspicious outbound ports, web shell process execution, and credential path access. The older `[[detections.persistence]]` and `[[detections.network]]` paths remain for compatibility with event-local `alert` and `detection_type` fields.

## Scenario Detections

Scenario detections are built into userspace and emit separate `event_type = "alert"` records using the same stable alert schema as MVP rules.

| Rule ID | Behavior | Telemetry | False positives | Demo or test input |
| --- | --- | --- | --- | --- |
| `BUILTIN-SCENARIO-REVERSE-SHELL-001` | Shell or common network/interpreter process connects to a suspicious outbound port within 10 seconds of start. Ports: `4444`, `1337`, `31337`, `9001`, `5555`. | `process_start` plus `network_connect`; requires network collection enabled. | CTF/lab work, admin reverse-shell tests, tunnels, dev proxies, netcat debugging. | Enable network collection, then use a lab-safe connect such as `sh -c 'nc 127.0.0.1 4444'`. |
| `BUILTIN-SCENARIO-WEB-SHELL-001` | Web server or PHP/CGI runtime forks a shell, interpreter, transfer tool, or network tool. | `process_relationship`. | Deployment hooks, CGI apps, web admin panels, health checks. | Expected shape: `parent_comm = "nginx"`, `child_comm = "sh"`. |
| `BUILTIN-SCENARIO-CREDENTIAL-ACCESS-001` | Sensitive account, credential, SSH key, or KeePass-style path is opened, written, renamed, or unlinked. | File open/write/rename/unlink normalized events. | Package managers, account tools, backups, scanners, user key management. | Root-safe read check: `sudo test -r /etc/shadow`; unit tests cover `/etc/shadow` and `~/.ssh/id_ed25519`. |
| `BUILTIN-FILE-SYSTEMD-001` | Systemd service unit creation, modification, rename, or deletion under system unit directories. | File write/rename/unlink normalized events. | Package installs/upgrades, service deployment, configuration management, administrators. | Rename or write a harmless `*.service` under `/etc/systemd/system/` in a disposable VM. |
| `BUILTIN-SCENARIO-DROP-EXEC-001` | A file is written or renamed into `/tmp/`, `/var/tmp/`, `/dev/shm/`, or `/run/user/`, then the same path is executed within 10 seconds. | File write/rename plus `process_start`. | Compilers, test runners, package installers, self-updaters, build systems, temporary script execution. | Allow a staging path in `[file].watch_paths`, then copy or compile a harmless executable to `/tmp/rg-demo` and run `/tmp/rg-demo`. |

Current scenario limits: correlation state is in-memory only, the time window and port/path lists are constants, reverse shell confidence relies on process/port/time heuristics, and drop-and-execute requires file write path resolution to produce a non-empty path.
