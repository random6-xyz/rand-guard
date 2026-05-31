# Threat Model

This document describes the security assumptions for `rand-guard` as a study-focused Rust eBPF EDR. It is not a claim of production hardening. The goal is to make current trust boundaries and limits explicit for contributors and evaluators.

## Assets

- Host stability: eBPF programs should not destabilize the kernel or overload the host.
- Telemetry integrity: process, file, and network events should accurately represent the collected tracepoint data.
- Configuration and rules: local config controls what is collected and which detections are enabled.
- eBPF object and userspace binary: runtime artifacts must match the expected source and build output.
- Output stream: NDJSON records may contain sensitive host activity and should be handled as security telemetry.
- Contributor trust: code and rule changes can affect privileged runtime behavior.

## Trust Boundaries

- Kernel to eBPF: eBPF programs run in a constrained kernel context and must satisfy verifier rules.
- eBPF to userspace: raw events cross the `EVENTS` ring buffer using fixed-layout shared structs.
- Userspace runtime to config: config files and rule files are trusted local inputs.
- Runtime to output consumer: stdout, journald, files, or downstream pipelines can expose sensitive telemetry.
- Contributor workflow: pull requests can change privileged code paths, schemas, detections, and packaging.

## Attacker Assumptions

The project currently assumes an attacker may run local user-space commands that generate telemetry. It does not assume the agent can withstand a privileged attacker with full root control of the host. A root attacker can generally stop the service, alter config, replace binaries, tamper with output, or interfere with kernel instrumentation.

The current detections are intended to model selected behaviors such as persistence-sensitive file changes and suspicious network ports. They are not complete malware, intrusion, or rootkit detection coverage.

## In Scope

- Safe collection of selected process lifecycle events.
- Safe collection of selected file events with watch and exclude filtering.
- Optional collection of selected network syscall events.
- Userspace normalization, enrichment, and deterministic JSON output.
- Built-in and MVP rule alerts over single normalized events.
- Documentation of false positives and feature limits.

## Out Of Scope

- Protecting the agent from a fully privileged local attacker.
- Kernel rootkit detection or kernel integrity measurement.
- Network payload inspection, DNS parsing, or TLS visibility.
- Full socket lifecycle tracking.
- Multi-event behavioral correlation and time-window rule evaluation.
- Tamper-proof storage, remote attestation, or guaranteed delivery.
- Commercial EDR-grade coverage, response actions, or SLA-backed support.

## eBPF Runtime Risks

eBPF programs are privileged and run in a sensitive environment. The project mitigates this by keeping kernel-side code small, avoiding allocation and recursion, using bounded loops, and discarding incomplete events when helper reads fail.

Contributors should treat every shared ABI change as security-sensitive. Event structs crossing the eBPF/userspace boundary must remain fixed-layout and explicit about truncation or missing data.

## Telemetry Sensitivity

NDJSON output can include process names, executable paths, file paths, user IDs, group IDs, ports, and IP addresses. These fields can reveal user behavior, system layout, installed software, and investigation targets.

Do not paste sensitive telemetry into public issues. Redact hostnames, internal paths, usernames, IP addresses, tokens, secrets, and any private customer or lab data before sharing logs publicly.

## Reporting Security Issues

Report vulnerabilities through GitHub Security Advisories for this repository. Do not open public issues for exploitable crashes, privilege boundary problems, unsafe eBPF verifier behavior, sensitive data leaks, or bypass details.

See [Security Policy](../SECURITY.md) for the reporting process.
