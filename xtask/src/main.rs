use anyhow::{Context, bail};
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
            "cs" | "ci-smoke" => run_user(false, true)?,
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

    if ci_smoke {
        command.env("CI_SMOKE", "1");

        Command::new("timeout")
            .args([
                "4s",
                "bash",
                "-c",
                "sleep 1; while true; do /bin/true; sleep 0.1; done",
            ])
            .spawn()?;
    }

    let status = command
        .args(["-E", user_bin_str])
        .env("EDR_EBPF_OBJECT", ebpf_obj_str)
        .status()
        .context("failed to run user loader with sudo directly")?;

    if !status.success() {
        bail!(
            "userspace program failed in {} mode.",
            if ci_smoke { "CI_SMOKE" } else { "normal" }
        );
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
