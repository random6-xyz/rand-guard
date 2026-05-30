use anyhow::{Context, bail};
use serde_json::Value;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const USAGE: &str = "usage: cargo xtask <command> [command...]\n\n\
        commands:\n\n\
        f, format       Format all\n\
        c, check        Check all\n\
        l, clippy       Clippy all\n\
        t, test         Test userspace\n\n\
        b, build        Build release all\n\
        p, package      Build release all and create a tarball\n\
        r, run          Run\n\
        tp, throughput  Build release all and run local throughput measurement\n\n\
        cs, ci-smoke    Build release all, run with CI_SMOKE\n\
        cf, ci-format   Check format for ci\n\n\
        h, help         Print command\n";

fn main() -> anyhow::Result<()> {
    let argc = std::env::args().len();
    if argc <= 1 {
        bail!(USAGE);
    }

    for cmd in std::env::args().skip(1) {
        match cmd.as_str() {
            "f" | "format" => fmt_all(false)?,
            "c" | "check" => check_all()?,
            "l" | "clippy" => clippy_all()?,
            "t" | "test" => test_all()?,
            "b" | "build" => {
                build_ebpf(true)?;
                build_user(true)?;
            }
            "p" | "package" => package_release()?,
            "r" | "run" => run_user(false, false)?,
            "tp" | "throughput" => run_throughput()?,
            "cs" | "ci-smoke" => {
                build_ebpf(true)?;
                build_user(true)?;
                run_user(false, true)?;
            }
            "cf" | "ci-format" => fmt_all(true)?,
            "h" | "help" => println!("{USAGE}"),
            _ => bail!(USAGE),
        }
    }

    Ok(())
}

fn build_user(release: bool) -> anyhow::Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.args(["build", "-p", "edr-user"]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("failed to build user program")?;

    if !status.success() {
        bail!("user program build failed");
    }

    Ok(())
}

fn build_ebpf(release: bool) -> anyhow::Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.args([
        "+nightly",
        "build",
        "-Z",
        "build-std=core",
        "--target",
        "bpfel-unknown-none",
        "-p",
        "edr-ebpf",
    ]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("failed to build eBPF program")?;

    if !status.success() {
        bail!("eBPF build failed");
    }

    Ok(())
}

fn package_release() -> anyhow::Result<()> {
    build_ebpf(true)?;
    build_user(true)?;

    let repo_root = std::env::current_dir().context("failed to get current directory")?;
    let version = package_version(&repo_root.join("crates/user/Cargo.toml"))?;
    let arch = std::env::consts::ARCH;
    let package_name = format!("rand-guard-{version}-{arch}");
    let package_dir = repo_root.join("target/package");
    let stage_dir = package_dir.join(&package_name);
    let tarball = package_dir.join(format!("{package_name}.tar.gz"));
    let checksum = package_dir.join(format!("{package_name}.tar.gz.sha256"));

    if stage_dir.exists() {
        std::fs::remove_dir_all(&stage_dir).context("failed to clean package staging directory")?;
    }
    std::fs::create_dir_all(&package_dir).context("failed to create package output directory")?;

    copy_file(
        &repo_root.join("target/release/edr-user"),
        &stage_dir.join("target/release/edr-user"),
    )?;
    copy_file(
        &repo_root.join("target/bpfel-unknown-none/release/edr-ebpf"),
        &stage_dir.join("target/bpfel-unknown-none/release/edr-ebpf"),
    )?;
    copy_file(
        &repo_root.join("packaging/config/rand-guard.toml"),
        &stage_dir.join("packaging/config/rand-guard.toml"),
    )?;
    copy_file(
        &repo_root.join("packaging/rules.d/sample-rules.toml"),
        &stage_dir.join("packaging/rules.d/sample-rules.toml"),
    )?;
    copy_file(
        &repo_root.join("packaging/systemd/rand-guard.service"),
        &stage_dir.join("packaging/systemd/rand-guard.service"),
    )?;
    copy_file(
        &repo_root.join("scripts/install.sh"),
        &stage_dir.join("scripts/install.sh"),
    )?;

    run(
        Command::new("tar")
            .arg("-czf")
            .arg(&tarball)
            .arg("-C")
            .arg(&package_dir)
            .arg(&package_name),
        "create package tarball",
    )?;

    let output = Command::new("sha256sum")
        .arg(&tarball)
        .output()
        .context("failed to spawn sha256sum")?;
    if !output.status.success() {
        bail!("sha256sum failed with exit code {}", output.status);
    }
    std::fs::write(&checksum, output.stdout).context("failed to write package checksum")?;

    println!("package: {}", tarball.display());
    println!("checksum: {}", checksum.display());

    Ok(())
}

fn package_version(manifest: &Path) -> anyhow::Result<String> {
    let contents = std::fs::read_to_string(manifest)
        .with_context(|| format!("failed to read manifest {}", manifest.display()))?;
    let mut in_package = false;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed == "[package]" {
            in_package = true;
            continue;
        }
        if in_package && trimmed.starts_with('[') {
            break;
        }
        if in_package && trimmed.starts_with("version") {
            let (_, value) = trimmed
                .split_once('=')
                .context("package version line is missing '='")?;
            return Ok(value.trim().trim_matches('"').to_string());
        }
    }

    bail!("failed to find package version in {}", manifest.display())
}

fn copy_file(src: &Path, dst: &Path) -> anyhow::Result<()> {
    let parent = dst
        .parent()
        .with_context(|| format!("destination has no parent: {}", dst.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;
    std::fs::copy(src, dst)
        .with_context(|| format!("failed to copy {} to {}", src.display(), dst.display()))?;

    Ok(())
}

fn run_user(debug: bool, ci_smoke: bool) -> anyhow::Result<()> {
    let repo_root = std::env::current_dir().context("failed to get current directory")?;

    let mode = if debug { "debug" } else { "release" };
    let user_bin = repo_root.join(format!("target/{mode}/edr-user"));
    let user_bin_str = user_bin.to_str().context("path is not valid UTF-8")?;
    let ebpf_obj = repo_root.join(format!("target/bpfel-unknown-none/{mode}/edr-ebpf"));
    let ebpf_obj_str = ebpf_obj.to_str().context("path is not valid UTF-8")?;

    let mut command = Command::new("sudo");
    let mut smoke_helpers = Vec::new();

    let config_path = if ci_smoke {
        smoke_helpers.push(
            Command::new("timeout")
                .args([
                    "12s",
                    "bash",
                    "-c",
                    "sleep 0.2; while true; do /bin/true; sleep 0.1; done",
                ])
                .spawn()?,
        );

        // Spawn a short-lived child that writes under /tmp so the file_write
        // tracepoint has a chance to fire without loading the heavier openat hook.
        smoke_helpers.push(
            Command::new("bash")
                .args([
                    "-c",
                    "sleep 2; exec 3>/tmp/edr_ci_smoke_file; end=$((SECONDS + 5)); while [ \"$SECONDS\" -lt \"$end\" ]; do printf smoke >&3; sleep 0.1; done",
                ])
                .spawn()?,
        );

        let smoke_config =
            std::env::temp_dir().join(format!("edr_ci_smoke_config_{}.toml", std::process::id()));
        let smoke_config_contents = r#"[agent]
id = "ci-smoke"
mode = "monitor"
log_level = "warn"

[ebpf]
enabled = true
buffer_size = 8192

[events]
process = true
file = true
network = false

[process]
enabled = true
hooks = ["execve", "fork", "exit", "execveat"]
collect_args = false
collect_env = false
collect_cwd = false

[file]
enabled = true
hooks = ["write"]
watch_paths = []
watch_patterns = []
exclude_paths = []

[network]
enabled = false
hooks = ["connect"]
collect_dns = false
collect_payload = false

[[rules]]
id = "DUMMY-001"
name = "Dummy"
enabled = false
type = "process"
severity = "low"
action = "alert"
process_names = ["dummy"]

[detections]
persistence = []

[output]
type = "stdout"
format = "json"

[performance]
max_events_per_second = 5000
drop_when_full = true
"#;
        std::fs::write(&smoke_config, smoke_config_contents)
            .context("failed to write CI smoke config")?;
        smoke_config
    } else {
        repo_root.join("config.example.toml")
    };

    if ci_smoke {
        let config_str = config_path.to_str().context("path is not valid UTF-8")?;

        let output_result = command
            .args(["-E", "timeout", "-s", "INT", "12s", user_bin_str])
            .env("EDR_EBPF_OBJECT", ebpf_obj_str)
            .env("EDR_CONFIG", config_str)
            .output();

        cleanup_smoke_helpers(&mut smoke_helpers);

        let output = output_result.context("failed to run user loader with sudo directly")?;

        if !output.status.success() && output.status.code() != Some(124) {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("userspace program failed in CI_SMOKE mode: {stderr}");
        }

        validate_ci_smoke_output(&output.stdout)?;

        return Ok(());
    }

    let status = command
        .args(["-E", user_bin_str])
        .env("EDR_EBPF_OBJECT", ebpf_obj_str)
        .status()
        .context("failed to run user loader with sudo directly")?;

    if !status.success() {
        bail!("userspace program failed in normal mode.");
    }

    Ok(())
}

fn cleanup_smoke_helpers(children: &mut [Child]) {
    for child in children {
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn run_throughput() -> anyhow::Result<()> {
    build_ebpf(true)?;
    build_user(true)?;

    let repo_root = std::env::current_dir().context("failed to get current directory")?;
    let duration_secs = env_u64("EDR_THROUGHPUT_DURATION_SECS", 15)?;
    let generator_secs = env_u64("EDR_THROUGHPUT_GENERATOR_SECS", 10)?;
    let output_dir = std::env::var("EDR_THROUGHPUT_OUTPUT")
        .map(|path| repo_root.join(path))
        .unwrap_or_else(|_| repo_root.join(".local/throughput"));

    let config_path = write_throughput_config()?;
    let config_str = config_path.to_str().context("path is not valid UTF-8")?;
    let user_bin = repo_root.join("target/release/edr-user");
    let user_bin_str = user_bin.to_str().context("path is not valid UTF-8")?;
    let ebpf_obj = repo_root.join("target/bpfel-unknown-none/release/edr-ebpf");
    let ebpf_obj_str = ebpf_obj.to_str().context("path is not valid UTF-8")?;

    let mut generator = spawn_throughput_generator(generator_secs)?;
    let timeout_arg = format!("{duration_secs}s");
    let output_result = Command::new("sudo")
        .args(["-E", "timeout", "-s", "INT", &timeout_arg, user_bin_str])
        .env("EDR_EBPF_OBJECT", ebpf_obj_str)
        .env("EDR_CONFIG", config_str)
        .output();

    let _ = generator.kill();
    let _ = generator.wait();

    let output = output_result.context("failed to run throughput measurement with sudo")?;
    let summary = match parse_throughput_summary(&output.stdout) {
        Ok(summary) => summary,
        Err(e) if !output.status.success() => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("throughput measurement failed before health output: {e}; stderr: {stderr}");
        }
        Err(e) => return Err(e),
    };

    std::fs::create_dir_all(&output_dir).context("failed to create throughput output directory")?;
    let result_path = write_throughput_result(
        &output_dir,
        duration_secs,
        generator_secs,
        output.status.code(),
        &summary,
    )?;

    println!("throughput benchmark complete");
    println!("duration_secs: {duration_secs}");
    println!("generator_secs: {generator_secs}");
    println!("health_records: {}", summary.health_records);
    println!("raw_events_read: {}", summary.raw_events_read);
    println!(
        "normalized_events_output: {}",
        summary.normalized_events_output
    );
    println!("raw_events_per_sec: {:.2}", summary.raw_events_per_sec);
    println!(
        "emitted_events_per_sec: {:.2}",
        summary.emitted_events_per_sec
    );
    println!(
        "userspace_drops_per_sec: {:.2}",
        summary.userspace_drops_per_sec
    );
    println!("max_observed_rss_kb: {}", summary.max_observed_rss_kb);
    println!(
        "final_process_table_size: {}",
        summary.final_process_table_size
    );
    println!(
        "final_pending_exec_source_size: {}",
        summary.final_pending_exec_source_size
    );
    println!("result: {}", result_path.display());

    Ok(())
}

fn env_u64(name: &str, default: u64) -> anyhow::Result<u64> {
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .with_context(|| format!("failed to parse {name} as an integer")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(e) => Err(e).with_context(|| format!("failed to read {name}")),
    }
}

fn write_throughput_config() -> anyhow::Result<std::path::PathBuf> {
    let config_path =
        std::env::temp_dir().join(format!("edr_throughput_config_{}.toml", std::process::id()));
    let config_contents = r#"[agent]
id = "throughput"
mode = "monitor"
log_level = "warn"

[ebpf]
enabled = true
buffer_size = 8192

[events]
process = true
file = true
network = false

[process]
enabled = true
hooks = []
collect_args = false
collect_env = false
collect_cwd = false

[file]
enabled = true
hooks = ["write"]
watch_paths = ["/tmp/rand_guard_throughput"]
watch_patterns = []
exclude_paths = []

[network]
enabled = false
hooks = ["connect", "bind", "listen"]
collect_dns = false
collect_payload = false

[[rules]]
id = "THROUGHPUT-DUMMY"
name = "Throughput dummy"
enabled = false
type = "process"
severity = "low"
action = "alert"
process_names = ["dummy"]

[detections]
persistence = []
network = []

[output]
type = "stdout"
format = "json"

[performance]
max_events_per_second = 5000
drop_when_full = true
max_process_cache_entries = 5000
max_pending_exec_sources = 500
"#;
    std::fs::write(&config_path, config_contents).context("failed to write throughput config")?;
    Ok(config_path)
}

fn spawn_throughput_generator(generator_secs: u64) -> anyhow::Result<Child> {
    let script = format!(
        "sleep 0.5; mkdir -p /tmp/rand_guard_throughput; exec 3> /tmp/rand_guard_throughput/probe; end=$((SECONDS + {generator_secs})); while [ \"$SECONDS\" -lt \"$end\" ]; do printf x >&3; done"
    );

    Command::new("bash")
        .args(["-c", &script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn throughput event generator")
}

#[derive(Debug)]
struct ThroughputSummary {
    health_records: u64,
    raw_events_read: u64,
    normalized_events_output: u64,
    alerts_output: u64,
    userspace_drops: u64,
    raw_events_per_sec: f64,
    emitted_events_per_sec: f64,
    userspace_drops_per_sec: f64,
    max_observed_rss_kb: u64,
    final_process_table_size: u64,
    final_pending_exec_source_size: u64,
    uptime_secs: u64,
}

fn parse_throughput_summary(stdout: &[u8]) -> anyhow::Result<ThroughputSummary> {
    let stdout = std::str::from_utf8(stdout).context("throughput stdout was not valid UTF-8")?;
    let health_events: Vec<Value> = stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["event_type"] == "health")
        .collect();

    let last = health_events
        .last()
        .context("throughput measurement did not emit a health JSON event")?;
    let uptime_secs = json_u64(last, "uptime_secs").unwrap_or(0).max(1);
    let raw_events_read = json_u64(last, "raw_events_read").unwrap_or(0);
    let normalized_events_output = json_u64(last, "normalized_events_output").unwrap_or(0);
    let alerts_output = json_u64(last, "alerts_output").unwrap_or(0);
    let userspace_drops = json_u64(last, "userspace_filtered").unwrap_or(0)
        + json_u64(last, "userspace_rate_limited").unwrap_or(0)
        + json_u64(last, "userspace_invalid_schema").unwrap_or(0)
        + json_u64(last, "userspace_unsupported_kind").unwrap_or(0)
        + json_u64(last, "userspace_output_failures").unwrap_or(0);
    let max_observed_rss_kb = health_events
        .iter()
        .filter_map(|event| json_u64(event, "rss_kb"))
        .max()
        .unwrap_or(0);

    Ok(ThroughputSummary {
        health_records: health_events.len() as u64,
        raw_events_read,
        normalized_events_output,
        alerts_output,
        userspace_drops,
        raw_events_per_sec: raw_events_read as f64 / uptime_secs as f64,
        emitted_events_per_sec: normalized_events_output as f64 / uptime_secs as f64,
        userspace_drops_per_sec: userspace_drops as f64 / uptime_secs as f64,
        max_observed_rss_kb,
        final_process_table_size: json_u64(last, "process_table_size").unwrap_or(0),
        final_pending_exec_source_size: json_u64(last, "pending_exec_source_size").unwrap_or(0),
        uptime_secs,
    })
}

fn json_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn write_throughput_result(
    output_dir: &Path,
    duration_secs: u64,
    generator_secs: u64,
    status_code: Option<i32>,
    summary: &ThroughputSummary,
) -> anyhow::Result<std::path::PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_secs();
    let result_path = output_dir.join(format!("throughput-{timestamp}.md"));
    let status_code = status_code
        .map(|code| code.to_string())
        .unwrap_or_else(|| "signal".to_string());
    let contents = format!(
        "# rand-guard throughput run\n\n\
- command: `cargo run -p xtask -- throughput`\n\
- generator: file write loop under `/tmp/rand_guard_throughput`\n\
- network_enabled: false\n\
- requested_duration_secs: {duration_secs}\n\
- requested_generator_secs: {generator_secs}\n\
- process_status_code: {status_code}\n\
- health_records: {}\n\
- uptime_secs: {}\n\
- raw_events_read: {}\n\
- normalized_events_output: {}\n\
- alerts_output: {}\n\
- userspace_drops: {}\n\
- raw_events_per_sec: {:.2}\n\
- emitted_events_per_sec: {:.2}\n\
- userspace_drops_per_sec: {:.2}\n\
- max_observed_rss_kb: {}\n\
- final_process_table_size: {}\n\
- final_pending_exec_source_size: {}\n",
        summary.health_records,
        summary.uptime_secs,
        summary.raw_events_read,
        summary.normalized_events_output,
        summary.alerts_output,
        summary.userspace_drops,
        summary.raw_events_per_sec,
        summary.emitted_events_per_sec,
        summary.userspace_drops_per_sec,
        summary.max_observed_rss_kb,
        summary.final_process_table_size,
        summary.final_pending_exec_source_size,
    );

    std::fs::write(&result_path, contents).context("failed to write throughput result")?;
    Ok(result_path)
}

fn validate_ci_smoke_output(stdout: &[u8]) -> anyhow::Result<()> {
    let stdout = std::str::from_utf8(stdout).context("CI smoke stdout was not valid UTF-8")?;

    let events: Vec<Value> = stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect();

    let start = events
        .iter()
        .find(|event| event["event_type"] == "process_start")
        .context("CI smoke did not emit a process_start JSON event on stdout")?;

    if !start["pid"].is_u64() || !start["timestamp_ns"].is_u64() {
        bail!("CI smoke process_start event was missing numeric pid/timestamp: {start}");
    }
    if start["exe_path"].as_str().is_none_or(str::is_empty) {
        bail!("CI smoke process_start event was missing exe_path: {start}");
    }

    let has_relationship = events
        .iter()
        .any(|event| event["event_type"] == "process_relationship");

    if !has_relationship {
        bail!("CI smoke did not emit a process_relationship event");
    }

    let has_file_write = events
        .iter()
        .any(|event| event["event_type"] == "file_write");

    if !has_file_write {
        bail!("CI smoke did not emit a file_write event");
    }

    Ok(())
}

fn fmt_all(ci: bool) -> anyhow::Result<()> {
    let mut command = Command::new("cargo");
    command.args(["fmt", "--all"]);

    if ci {
        command.args(["--", "--check"]);
    }

    run(&mut command, "cargo fmt")?;

    Ok(())
}

fn check_all() -> anyhow::Result<()> {
    run(
        Command::new("cargo").args(["check", "-p", "edr-user", "-p", "edr-common", "-p", "xtask"]),
        "cargo check userspace",
    )?;
    run(
        Command::new("cargo").args([
            "+nightly",
            "check",
            "-Z",
            "build-std=core",
            "--target",
            "bpfel-unknown-none",
            "-p",
            "edr-ebpf",
        ]),
        "cargo check ebpf",
    )?;

    Ok(())
}

fn clippy_all() -> anyhow::Result<()> {
    run(
        Command::new("cargo").args([
            "clippy",
            "-p",
            "edr-user",
            "-p",
            "edr-common",
            "-p",
            "xtask",
            "--",
            "-D",
            "warnings",
        ]),
        "cargo clippy userspace",
    )?;
    run(
        Command::new("cargo").args([
            "+nightly",
            "clippy",
            "-Z",
            "build-std=core",
            "--target",
            "bpfel-unknown-none",
            "-p",
            "edr-ebpf",
            "--",
            "-D",
            "warnings",
        ]),
        "cargo clippy ebpf",
    )?;

    Ok(())
}

fn test_all() -> anyhow::Result<()> {
    run(
        Command::new("cargo").args(["test", "-p", "edr-user", "-p", "edr-common", "-p", "xtask"]),
        "cargo test userspace",
    )?;

    Ok(())
}

fn run(cmd: &mut Command, name: &str) -> anyhow::Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("failed to spawn {name}"))?;

    if !status.success() {
        bail!("{name} failed with exit code {status}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_throughput_health_summary() {
        let stdout = br#"{"event_type":"health","raw_events_read":100,"normalized_events_output":80,"alerts_output":2,"userspace_filtered":3,"userspace_rate_limited":4,"userspace_invalid_schema":5,"userspace_unsupported_kind":6,"userspace_output_failures":7,"process_table_size":8,"pending_exec_source_size":9,"uptime_secs":10,"rss_kb":1024}
{"event_type":"health","raw_events_read":200,"normalized_events_output":160,"alerts_output":3,"userspace_filtered":4,"userspace_rate_limited":5,"userspace_invalid_schema":6,"userspace_unsupported_kind":7,"userspace_output_failures":8,"process_table_size":10,"pending_exec_source_size":11,"uptime_secs":20,"rss_kb":2048}
"#;

        let summary = parse_throughput_summary(stdout).expect("health summary should parse");

        assert_eq!(summary.health_records, 2);
        assert_eq!(summary.raw_events_read, 200);
        assert_eq!(summary.normalized_events_output, 160);
        assert_eq!(summary.alerts_output, 3);
        assert_eq!(summary.userspace_drops, 30);
        assert_eq!(summary.raw_events_per_sec, 10.0);
        assert_eq!(summary.emitted_events_per_sec, 8.0);
        assert_eq!(summary.userspace_drops_per_sec, 1.5);
        assert_eq!(summary.max_observed_rss_kb, 2048);
        assert_eq!(summary.final_process_table_size, 10);
        assert_eq!(summary.final_pending_exec_source_size, 11);
    }

    #[test]
    fn rejects_throughput_summary_without_health() {
        let err = parse_throughput_summary(b"{}").expect_err("health record should be required");

        assert!(err.to_string().contains("health JSON event"));
    }
}
