---
name: edr-detection-design
description: Use when designing EDR telemetry, detection rules, ATT&CK-style scenarios, false-positive notes, or rule-engine behavior for this Rust eBPF project.
---

# EDR Detection Design

Use this skill when turning Linux telemetry into EDR detections.

## Detection Design Template

For each detection, define:

- behavior: attacker or suspicious admin behavior being modeled
- telemetry: tracepoint/syscall/source needed to observe it
- fields: minimum event fields required
- correlation: process, parent, file, network, or time relationship needed
- false positives: expected benign cases
- output: alert fields useful for a demo or investigation
- validation: command, script, or smoke test idea

## Project Priorities

Current runtime status:

- Process lifecycle telemetry is implemented for exec, fork, exit, and execveat correlation.
- File telemetry is implemented for open, write, rename, and unlink syscall families, with watch/exclude filters.
- Built-in persistence detections are configured under `[[detections.persistence]]` and evaluated in userspace.
- Network telemetry and enabled generic `[[rules]]` are currently rejected by runtime validation.

Next visibility and detection priorities:

1. network connect/listen visibility
2. generic rule engine MVP beyond built-in persistence checks
3. scenario detections

## Scenario Candidates

- reverse shell behavior
- web shell spawning a shell or interpreter
- credential access attempts under sensitive paths
- systemd service persistence
- cron persistence
- suspicious binary drop and execute
- unexpected outbound connection from unusual process ancestry

## Rule Engine Guidance

- Extend built-in Rust detections before designing a user-facing rule language.
- Do not assume `[[rules]]` is active at runtime; enabled rules currently fail validation.
- Keep rules explainable and tied to available fields.
- Prefer normalized EDR events over raw syscall records.
- Include false-positive notes in docs and tests where practical.
