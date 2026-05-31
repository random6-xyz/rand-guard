# Benchmarks

`rand-guard` includes a local throughput workflow for comparing runtime behavior across code changes. Benchmark results are host-dependent and should be treated as local comparison data, not universal performance guarantees.

## What The Benchmark Measures

The current workflow focuses on userspace event processing during controlled file-write volume. It builds release artifacts, starts the agent with a temporary config, generates writes under `/tmp/rand_guard_throughput`, parses `event_type = "health"` records, and writes a Markdown summary under `.local/throughput/`.

The default benchmark keeps process collection enabled but disables process hooks so the run focuses on file-write throughput. Network collection is disabled.

## Run The Benchmark

From the repository root:

```sh
cargo run -p xtask -- throughput
```

This command loads eBPF and generally requires `sudo` or suitable capabilities.

You can override the run length:

```sh
EDR_THROUGHPUT_DURATION_SECS=30 \
EDR_THROUGHPUT_GENERATOR_SECS=25 \
cargo run -p xtask -- throughput
```

## Output Location

Results are written under:

```text
.local/throughput/
```

The `.local/` directory is intentionally for local generated output and should not be committed.

## Reported Metrics

The generated summary includes:

- Total raw events.
- Normalized events per second.
- Userspace drops per second.
- Maximum observed RSS.
- Final process cache sizes.

## Interpreting Results

Benchmark numbers vary with:

- Kernel version and eBPF implementation details.
- CPU model and scheduler behavior.
- Disk and filesystem behavior.
- Background system activity.
- Debug versus release builds.
- Runtime config and enabled hooks.

Use results to compare changes on the same host with similar conditions. Do not use one local run as a project-wide performance claim.

## Suggested Benchmark Notes For Pull Requests

If a pull request changes event volume, normalization, output, rule evaluation, or process-cache behavior, include:

- Command used.
- Kernel version.
- Relevant config changes.
- Before and after summaries if available.
- Any observed drops or memory changes.

## Current Limits

- The benchmark is not a CI pass/fail threshold.
- It does not cover network telemetry.
- It does not model production EDR workloads.
- It does not validate detection accuracy.
- It does not replace targeted tests for normalization, config, rules, or output stability.
