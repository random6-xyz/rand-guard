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

Build visibility in this order:

1. process execution and lifecycle
2. file and persistence-sensitive path visibility
3. network connect/listen visibility
4. simple rule engine
5. scenario detections

## Scenario Candidates

- reverse shell behavior
- web shell spawning a shell or interpreter
- credential access attempts under sensitive paths
- systemd service persistence
- cron persistence
- suspicious binary drop and execute
- unexpected outbound connection from unusual process ancestry

## Rule Engine Guidance

- Start with built-in Rust rules before designing a user-facing rule language.
- Keep rules explainable and tied to available fields.
- Prefer normalized EDR events over raw syscall records.
- Include false-positive notes in docs and tests where practical.
