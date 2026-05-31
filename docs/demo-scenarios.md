# Demo Scenarios

These scenarios demonstrate current `rand-guard` behavior with safe local commands. They are intended for labs and development machines, not production hosts.

Most scenarios require the agent to be running. Loading eBPF generally requires root or suitable Linux capabilities.

## Before You Start

Build the project:

```sh
cargo run -p xtask -- build
```

Run the agent from the repository checkout:

```sh
cargo run -p xtask -- run
```

For installed usage, follow the [Quickstart](quickstart.md).

The agent writes NDJSON records to stdout or the configured service logs. Actual records include timestamps, process context, UIDs, GIDs, and truncation flags.

## Scenario 1: Process Lifecycle Event

Goal: show a process start event.

Run:

```sh
/bin/true
```

Expected output includes a `process_start` record similar to:

```json
{"event_type":"process_start","comm":"true","source":"execve"}
```

Cleanup: none.

## Scenario 2: Watched File Event

Goal: show a file event under a watched path without modifying real service configuration.

The default example config watches `/etc` and `*.service` patterns. Use a temporary file name and remove it immediately:

```sh
sudo sh -c 'printf "# rand-guard demo\n" > /etc/rand-guard-demo.service'
sudo rm -f /etc/rand-guard-demo.service
```

Expected output includes `file_open`, `file_write`, or `file_unlink` records for `/etc/rand-guard-demo.service` depending on enabled hooks and kernel behavior.

Cleanup:

```sh
sudo rm -f /etc/rand-guard-demo.service
```

## Scenario 3: Persistence-Sensitive File Detection

Goal: show a built-in persistence-sensitive file detection using a reversible temporary systemd-style path.

The example config includes a `systemd_service_modified` persistence detection for systemd service directories and `*.service` patterns. If your runtime config enables file events and includes the default detection, run:

```sh
sudo sh -c 'printf "# rand-guard persistence demo\n" > /etc/systemd/system/rand-guard-demo.service'
sudo rm -f /etc/systemd/system/rand-guard-demo.service
```

Expected output may include file records with detection fields such as:

```json
{"event_type":"file_write","resolved_path":"/etc/systemd/system/rand-guard-demo.service","alert":true,"detection_type":"systemd_service_modified"}
```

Cleanup:

```sh
sudo rm -f /etc/systemd/system/rand-guard-demo.service
```

This scenario writes a temporary file under a real persistence-sensitive directory and removes it. Do not enable or start the file as a service.

## Scenario 4: Suspicious Network Port Detection

Goal: show optional network telemetry and a suspicious outbound port detection.

Network collection is disabled by default. Enable it in your runtime config:

```toml
[events]
network = true

[network]
enabled = true
hooks = ["connect", "bind", "listen"]
collect_dns = false
collect_payload = false
```

Restart the agent after changing config.

In one terminal, start a local listener if `nc` is installed:

```sh
nc -l 127.0.0.1 4444
```

In another terminal, connect to it:

```sh
printf 'demo\n' | nc 127.0.0.1 4444
```

Expected output may include `network_listen` and `network_connect` records. If suspicious port detections include port `4444`, the connection may include alert metadata or produce an adjacent `alert` record.

Cleanup: stop the `nc` listener with `Ctrl-C`.

## Scenario 5: MVP Rule Alert

Goal: show that a matching `[[rules]]` entry emits a separate stable alert record.

Use a safe file rule in a temporary config or rules file:

```toml
[[rules]]
id = "DEMO-FILE-001"
name = "Demo service file touched"
enabled = true
type = "file"
severity = "low"
action = "alert"
paths = ["/etc/rand-guard-demo.service"]
operations = ["file_open", "file_write", "file_unlink"]
patterns = []
```

Trigger it:

```sh
sudo sh -c 'printf "# rand-guard rule demo\n" > /etc/rand-guard-demo.service'
sudo rm -f /etc/rand-guard-demo.service
```

Expected output includes a source file event and a separate record similar to:

```json
{"event_type":"alert","rule_id":"DEMO-FILE-001","rule_type":"file","source_event_type":"file_write","path":"/etc/rand-guard-demo.service"}
```

Cleanup:

```sh
sudo rm -f /etc/rand-guard-demo.service
```

## Safety Notes

- Do not run these demos on hosts where temporary writes under `/etc` are unacceptable.
- Do not paste unredacted telemetry into public issues.
- Do not use live malware or destructive payloads for demos.
- Keep network demos on loopback unless you intentionally need a different lab setup.
