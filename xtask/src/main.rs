use anyhow::{Context, bail};
use serde_json::Value;
use std::process::Command;

const USAGE: &str = "usage: cargo xtask <command> [command...]\n\n\
        commands:\n\n\
        f, format       Format all\n\
        c, check        Check all\n\
        l, clippy       Clippy all\n\
        t, test         Test userspace\n\n\
        b, build        Build release all\n\
        r, run          Run\n\n\
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
            "r" | "run" => run_user(false, false)?,
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

fn run_user(debug: bool, ci_smoke: bool) -> anyhow::Result<()> {
    let repo_root = std::env::current_dir().context("failed to get current directory")?;

    let mode = if debug { "debug" } else { "release" };
    let user_bin = repo_root.join(format!("target/{mode}/edr-user"));
    let user_bin_str = user_bin.to_str().context("path is not valid UTF-8")?;
    let ebpf_obj = repo_root.join(format!("target/bpfel-unknown-none/{mode}/edr-ebpf"));
    let ebpf_obj_str = ebpf_obj.to_str().context("path is not valid UTF-8")?;

    let mut command = Command::new("sudo");

    let config_path = if ci_smoke {
        command.env("CI_SMOKE", "1");

        Command::new("timeout")
            .args([
                "6s",
                "bash",
                "-c",
                "sleep 0.2; while true; do /bin/true; sleep 0.1; done",
            ])
            .spawn()?;

        // Spawn a short-lived child that touches a file under /tmp so the
        // file_open tracepoint has a chance to fire.
        Command::new("bash")
            .args(["-c", "sleep 0.3; touch /tmp/edr_ci_smoke_file"])
            .spawn()?;

        let smoke_config = std::env::temp_dir().join("edr_ci_smoke_config.toml");
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
hooks = ["openat"]
watch_paths = ["/tmp"]
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

        let output = command
            .args(["-E", user_bin_str])
            .env("EDR_EBPF_OBJECT", ebpf_obj_str)
            .env("EDR_CONFIG", config_str)
            .output()
            .context("failed to run user loader with sudo directly")?;

        if !output.status.success() {
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

    let has_file_open = events
        .iter()
        .any(|event| event["event_type"] == "file_open");

    if !has_file_open {
        bail!("CI smoke did not emit a file_open event");
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
