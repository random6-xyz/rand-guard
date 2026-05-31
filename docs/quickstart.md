# Quickstart

This guide builds a rand-guard release tarball, installs it using the FHS layout, starts the systemd service, and verifies NDJSON output.

Run repository commands from the repository root unless noted otherwise.

## Requirements

- Linux with eBPF, BTF, and tracepoint support.
- Stable Rust for userspace crates.
- Nightly Rust with `rust-src` for the eBPF target.
- `bpf-linker` for the eBPF build.
- `tar` and `sha256sum` for release artifact creation and verification.
- Root or suitable Linux capabilities to load eBPF programs.

Install the Rust-side build tools:

```sh
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker --locked
```

Loading eBPF normally requires `root`. On supported kernels, `CAP_BPF` plus `CAP_PERFMON` may be sufficient for the agent binary. Older kernels may require `CAP_SYS_ADMIN`.

## Build And Package

Create release artifacts and a tarball:

```sh
cargo run -p xtask -- package
```

The package command builds:

- `target/release/edr-user`
- `target/bpfel-unknown-none/release/edr-ebpf`
- `target/package/rand-guard-0.1.0-x86_64.tar.gz`
- `target/package/rand-guard-0.1.0-x86_64.tar.gz.sha256`

The version comes from `crates/user/Cargo.toml`. The architecture suffix comes from the build host, so non-`x86_64` hosts will produce a different filename.

Verify the checksum:

```sh
sha256sum -c target/package/rand-guard-0.1.0-x86_64.tar.gz.sha256
```

Inspect the tarball contents:

```sh
tar -tzf target/package/rand-guard-0.1.0-x86_64.tar.gz
```

The tarball includes the user binary, eBPF object, default config, sample rules, systemd unit, and installer script.

## Install

Extract the tarball and run the installer:

```sh
tar -xzf target/package/rand-guard-0.1.0-x86_64.tar.gz -C /tmp
sudo /tmp/rand-guard-0.1.0-x86_64/scripts/install.sh --source-dir /tmp/rand-guard-0.1.0-x86_64
```

The installer writes the FHS layout selected for this project:

- `/usr/local/bin/rand-guard`
- `/usr/local/lib/rand-guard/edr-ebpf`
- `/etc/rand-guard/config.toml`
- `/etc/rand-guard/rules.d/sample-rules.toml`
- `/etc/systemd/system/rand-guard.service`

Existing `/etc/rand-guard/config.toml` is not overwritten by default. To replace it, pass `--force`; the installer creates a timestamp backup first:

```sh
sudo /tmp/rand-guard-0.1.0-x86_64/scripts/install.sh \
  --source-dir /tmp/rand-guard-0.1.0-x86_64 \
  --force
```

For staging or tests, install under a temporary root without touching system paths:

```sh
/tmp/rand-guard-0.1.0-x86_64/scripts/install.sh \
  --source-dir /tmp/rand-guard-0.1.0-x86_64 \
  --root /tmp/rand-guard-root
```

Preview planned install actions:

```sh
./scripts/install.sh --dry-run
```

## Start With Systemd

Reload systemd, then enable and start the service:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now rand-guard.service
```

Check service status and logs:

```sh
sudo systemctl status rand-guard.service
sudo journalctl -u rand-guard.service -f
```

The unit runs `/usr/local/bin/rand-guard` as root and sets:

```sh
EDR_CONFIG=/etc/rand-guard/config.toml
EDR_EBPF_OBJECT=/usr/local/lib/rand-guard/edr-ebpf
```

## Run Manually

Stop the service if it is already running:

```sh
sudo systemctl stop rand-guard.service
```

Run the installed agent directly:

```sh
sudo EDR_CONFIG=/etc/rand-guard/config.toml \
  EDR_EBPF_OBJECT=/usr/local/lib/rand-guard/edr-ebpf \
  /usr/local/bin/rand-guard
```

For development from the repository checkout, build and run through `xtask`:

```sh
cargo run -p xtask -- build
cargo run -p xtask -- run
```

## Verify Output

rand-guard writes newline-delimited JSON. With the default config, process and file events are enabled and network telemetry is disabled.

Generate a process event:

```sh
/bin/true
```

Generate a watched file event:

```sh
sudo sh -c 'printf "# rand-guard quickstart\n" > /etc/rand-guard-quickstart.service'
sudo rm -f /etc/rand-guard-quickstart.service
```

Expected stdout or journal output includes records such as:

```json
{"event_type":"process_start","pid":123,"comm":"true"}
{"event_type":"file_write","resolved_path":"/etc/rand-guard-quickstart.service"}
```

Actual records include more fields, including timestamps, process context, and truncation flags.

## Network Telemetry

Network syscall telemetry is intentionally off by default to keep first-run noise low. Enable it only when needed by editing `/etc/rand-guard/config.toml`:

```toml
[events]
network = true

[network]
enabled = true
hooks = ["connect", "bind", "listen"]
collect_dns = false
collect_payload = false
```

Restart the service after changing the config:

```sh
sudo systemctl restart rand-guard.service
```

Current network support is limited to `connect`, `bind`, and `listen` syscall tracepoints. DNS, payload collection, `accept`/`accept4`, and socket lifecycle correlation are not implemented.

## Uninstall

Stop and disable the service:

```sh
sudo systemctl disable --now rand-guard.service
```

Remove installed files:

```sh
sudo rm -f /etc/systemd/system/rand-guard.service
sudo rm -f /usr/local/bin/rand-guard
sudo rm -rf /usr/local/lib/rand-guard
sudo rm -rf /etc/rand-guard
sudo systemctl daemon-reload
```

If you want to preserve local configuration, copy `/etc/rand-guard/config.toml` before removing `/etc/rand-guard`.

## Troubleshooting

If the service exits immediately, check logs first:

```sh
sudo journalctl -u rand-guard.service -n 100 --no-pager
```

Common causes:

- Missing eBPF permissions: run as root or grant suitable capabilities.
- Missing object path: confirm `/usr/local/lib/rand-guard/edr-ebpf` exists.
- Invalid config: run manually with `EDR_CONFIG=/etc/rand-guard/config.toml` to see the validation error.
- Unsupported kernel features: confirm the host has BTF and a kernel new enough for eBPF ring buffers.
