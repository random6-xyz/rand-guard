use anyhow::{Context, bail};
use std::process::Command;

const USAGE: &str = "usage: cargo xtask <command>\n\n\
        commands:\n\n\
        be, build-ebpf  Format, check, clippy, and build eBPF\n\
        bu, build-user  Format, check, clippy, and build user program\n\
        b, build        Format, check, clippy, and build all\n\
        r, run          Format, check, clippy, build eBPF, and run user program\n\
        d, debug        Format, check, clippy, build eBPF, and run user program in debug mode\n\
        f, format       Format all code\n\
        c, check        Check all code\n\
        l, clippy       Clippy all code\n\
        p, prepare      Format, check, clippy all code\n\
        cs, ci-smoke    Smoke test eBPF\n\
        t, test         Test all code\n\
        h, help         Print command\n";

fn main() -> anyhow::Result<()> {
    let Some(cmd) = std::env::args().nth(1) else {
        bail!(USAGE);
    };

    match cmd.as_str() {
        "be" | "build-ebpf" => {
            fmt_all()?;
            check_all()?;
            clippy_all()?;
            build_ebpf(true)
        }
        "bu" | "build-user" => {
            fmt_all()?;
            check_all()?;
            clippy_all()?;
            build_user(true)
        }
        "b" | "build" => {
            fmt_all()?;
            check_all()?;
            clippy_all()?;
            build_ebpf(true)?;
            build_user(true)
        }
        "r" | "run" => {
            fmt_all()?;
            check_all()?;
            clippy_all()?;
            build_ebpf(true)?;
            build_user(true)?;
            run_user(false)
        }
        "d" | "debug" => {
            fmt_all()?;
            check_all()?;
            clippy_all()?;
            build_ebpf(false)?;
            build_user(false)?;
            run_user(true)
        }
        "f" | "format" => fmt_all(),
        "c" | "check" => check_all(),
        "l" | "clippy" => clippy_all(),
        "p" | "prepare" => {
            fmt_all()?;
            check_all()?;
            clippy_all()
        }
        "cs" | "ci-smoke" => {
            build_ebpf(true)?;
            build_user(true)?;
            ci_smoke()
        }
        "t" | "test" => test_all(),
        "h" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        _ => bail!("unknown command: {cmd}"),
    }
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

fn run_user(debug: bool) -> anyhow::Result<()> {
    let user_bin = if debug {
        "./target/debug/edr-user"
    } else {
        "./target/release/edr-user"
    };

    let ebpf_obj = if debug {
        "target/bpfel-unknown-none/debug/edr-ebpf"
    } else {
        "target/bpfel-unknown-none/release/edr-ebpf"
    };

    let status = Command::new("sudo")
        .args(["-E", user_bin])
        .env("EDR_EBPF_OBJECT", ebpf_obj)
        .status()
        .context("failed to run user loader with sudo directly")?;

    if !status.success() {
        bail!("userspace program failed");
    }

    Ok(())
}

fn fmt_all() -> anyhow::Result<()> {
    run(
        Command::new("cargo").args(["fmt", "--all"]),
        "cargo fmt all",
    )?;

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

fn ci_smoke() -> anyhow::Result<()> {
    let status = Command::new("sudo")
        .args(["-E", "./target/release/edr-user"])
        .env(
            "EDR_EBPF_OBJECT",
            "target/bpfel-unknown-none/release/edr-ebpf",
        )
        .env("CI_SMOKE", "1")
        .status()
        .context("failed to run user loader with sudo directl in ci-smoke mode")?;

    if !status.success() {
        bail!("userspace program failed during ci-smoke");
    }

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
