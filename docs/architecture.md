# Architecture

`rand-guard` is a small Rust eBPF EDR built to make host telemetry collection and detection logic easy to study. The architecture intentionally keeps kernel-space collection simple and moves normalization, enrichment, policy, and output decisions into userspace.

## Design Goals

- Collect a small set of process, file, and opt-in network events from Linux tracepoints.
- Keep eBPF programs verifier-friendly, bounded, and explainable.
- Use stable shared event structs between eBPF and userspace.
- Normalize raw events into newline-delimited JSON for tests, demos, and downstream tools.
- Keep detections understandable before adding broader rule-engine complexity.

## Repository Layout

- `crates/common`: shared event kinds, headers, and fixed-layout structs used across the eBPF/userspace boundary.
- `crates/ebpf`: `no_std`, `no_main` Aya eBPF programs that attach to tracepoints and write raw events into the `EVENTS` ring buffer.
- `crates/user`: userspace loader and runtime. It loads config, attaches programs, consumes ring-buffer events, normalizes and enriches events, evaluates detections and MVP rules, and writes NDJSON.
- `xtask`: automation for format, check, clippy, tests, builds, packaging, smoke tests, and throughput measurements.
- `packaging`: default config, sample rules, systemd unit, and installer inputs.

## Event Flow

```text
Linux tracepoints
  |
  v
crates/ebpf
  process/file/network eBPF programs
  |
  | raw #[repr(C)] events defined with crates/common ABI
  v
EVENTS ring buffer
  |
  v
crates/user
  ring-buffer consumer
  |
  v
normalization -> process enrichment -> detections/rules -> NDJSON output
```

1. The userspace runtime reads configuration from `EDR_CONFIG` or `config.toml`.
2. The runtime loads the eBPF object from `EDR_EBPF_OBJECT` or the default build path.
3. Enabled eBPF programs attach to process, file, and network tracepoints.
4. eBPF programs collect bounded event fields and submit raw records to the `EVENTS` ring buffer.
5. Userspace consumes raw records, identifies their event kind, and converts them into normalized Rust structs.
6. The process table enriches events with available process context such as `ppid`, `comm`, and `exe_path`.
7. Built-in detections and enabled MVP `[[rules]]` evaluate normalized events.
8. The output layer writes one JSON object per line to stdout.

## Kernel-Space Collection

The eBPF crate is deliberately narrow. It does not allocate, recurse, parse complex protocols, or perform high-level detection policy. Its job is to safely collect selected syscall and scheduler tracepoint data.

Implemented process visibility includes `execve`, `execveat`, `fork`, and `exit` correlation. Implemented file visibility covers open, write, rename, and unlink syscall families. Implemented network visibility covers `connect`, `bind`, and `listen` syscall tracepoints when network collection is explicitly enabled.

String and pointer reads are bounded. Failed helper reads discard incomplete events rather than emitting misleading data. Shared event structs are fixed-size and defined in `crates/common` with `#[repr(C)]` where they cross the kernel/userspace ABI boundary.

## Userspace Runtime

Userspace owns the work that is easier and safer outside the verifier:

- Configuration loading and validation.
- eBPF object loading and tracepoint attachment.
- Ring-buffer event consumption.
- Event normalization and JSON serialization.
- Process context enrichment.
- Built-in persistence and suspicious-port detections.
- MVP rule evaluation over normalized process, file, and network events.
- Graceful shutdown and runtime health output.

The current output target is stdout NDJSON. This keeps tests and demos simple and makes the output easy to pipe into local tools.

## Configuration Model

`config.example.toml` is the main reference for runtime configuration. Process and file events are enabled by default. Network telemetry is disabled by default and requires both `events.network = true` and `network.enabled = true`.

Rules are configured with `[[rules]]`. The MVP rule engine supports single-event process, file, and network matches using simple fields such as process names, parent names, paths, operations, direction, and ports.

Built-in persistence detections are configured with `[[detections.persistence]]`. Built-in suspicious network port detections are configured with `[[detections.network]]` and can optionally filter by process name.

## Output Model

Every emitted record is one JSON object per line. Normal telemetry events use event types such as `process_start`, `file_write`, `network_connect`, and `network_listen`. Rule matches emit a separate stable `event_type = "alert"` record adjacent to the source telemetry event.

Some built-in detections also annotate source events with event-local fields such as `alert` and `detection_type`. Consumers should prefer the stable `alert` records when they need a uniform detection stream.

## Current Limits

- Rule matching is intentionally simple: no expression DSL, regex, multi-event correlation, or time windows.
- Network collection supports only `connect`, `bind`, and `listen` syscall tracepoints.
- DNS collection, payload collection, `accept`/`accept4`, and socket lifecycle correlation are not implemented.
- Runtime output is stdout JSON only.
- Loading eBPF programs requires root or suitable Linux capabilities.
- The project is optimized for explainability and study, not broad production EDR coverage.

## Related Docs

- [Quickstart](quickstart.md)
- [Threat Model](threat-model.md)
- [Roadmap](roadmap.md)
- [Benchmarks](benchmarks.md)
- [Demo Scenarios](demo-scenarios.md)
