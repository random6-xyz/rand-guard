mod attach;
mod config;
mod detections;
mod dispatch;
mod logging;
mod normalize;
mod output;
mod privilege;
mod process_table;
mod rules;

use anyhow::Context;
use aya::maps::ring_buf::RingBuf;
use tokio::io::unix::AsyncFd;
use tokio::signal;
use tokio::time::{Duration, sleep};
use tracing::{info, warn};

use crate::dispatch::DispatchContext;
use crate::process_table::ProcessTable;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_path = std::env::var("EDR_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
    let config = config::Config::from_path(&config_path)?;
    logging::init(&config.agent.log_level)?;
    config.validate_current_runtime()?;
    privilege::ensure_sufficient()?;

    let ebpf_path = std::env::var("EDR_EBPF_OBJECT")
        .unwrap_or_else(|_| "crates/ebpf/target/bpfel-unknown-none/debug/edr-ebpf".to_string());
    let ci_smoke = std::env::var("CI_SMOKE").as_deref() == Ok("1");

    let data = std::fs::read(&ebpf_path)?;
    let mut ebpf = aya::Ebpf::load(&data)?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!(error = %e, "failed to initialize eBPF logger");
    }

    let process_hooks: std::collections::HashSet<&str> =
        config.process.hooks.iter().map(|s| s.as_str()).collect();
    let file_hooks: std::collections::HashSet<&str> =
        config.file.hooks.iter().map(|s| s.as_str()).collect();
    let network_hooks: std::collections::HashSet<&str> =
        config.network.hooks.iter().map(|s| s.as_str()).collect();

    if process_hooks.contains("execve") {
        attach::attach_tracepoint(
            &mut ebpf,
            "sched_process_exec",
            "sched",
            "sched_process_exec",
        )?;
        attach::attach_tracepoint(
            &mut ebpf,
            "sys_enter_execve",
            "syscalls",
            "sys_enter_execve",
        )?;
    }

    if process_hooks.contains("fork") {
        attach::attach_tracepoint(
            &mut ebpf,
            "sched_process_fork",
            "sched",
            "sched_process_fork",
        )?;
    }

    if process_hooks.contains("exit") {
        attach::attach_tracepoint(
            &mut ebpf,
            "sched_process_exit",
            "sched",
            "sched_process_exit",
        )?;
    }

    if process_hooks.contains("execveat") {
        attach::attach_tracepoint(
            &mut ebpf,
            "sys_enter_execveat",
            "syscalls",
            "sys_enter_execveat",
        )?;
    }

    if config.events.file && config.file.enabled {
        if file_hooks.contains("openat") {
            attach::attach_tracepoint(
                &mut ebpf,
                "sys_enter_openat",
                "syscalls",
                "sys_enter_openat",
            )?;
        }
        if file_hooks.contains("openat2") {
            attach::attach_tracepoint(
                &mut ebpf,
                "sys_enter_openat2",
                "syscalls",
                "sys_enter_openat2",
            )?;
        }
        if file_hooks.contains("write") {
            attach::attach_tracepoint(&mut ebpf, "sys_enter_write", "syscalls", "sys_enter_write")?;
        }
        if file_hooks.contains("writev") {
            attach::attach_tracepoint(
                &mut ebpf,
                "sys_enter_writev",
                "syscalls",
                "sys_enter_writev",
            )?;
        }
        if file_hooks.contains("pwrite64") {
            attach::attach_tracepoint(
                &mut ebpf,
                "sys_enter_pwrite64",
                "syscalls",
                "sys_enter_pwrite64",
            )?;
        }
        if file_hooks.contains("rename") {
            attach::attach_tracepoint(
                &mut ebpf,
                "sys_enter_rename",
                "syscalls",
                "sys_enter_rename",
            )?;
        }
        if file_hooks.contains("renameat") {
            attach::attach_tracepoint(
                &mut ebpf,
                "sys_enter_renameat",
                "syscalls",
                "sys_enter_renameat",
            )?;
        }
        if file_hooks.contains("renameat2") {
            attach::attach_tracepoint(
                &mut ebpf,
                "sys_enter_renameat2",
                "syscalls",
                "sys_enter_renameat2",
            )?;
        }
        if file_hooks.contains("unlink") {
            attach::attach_tracepoint(
                &mut ebpf,
                "sys_enter_unlink",
                "syscalls",
                "sys_enter_unlink",
            )?;
        }
        if file_hooks.contains("unlinkat") {
            attach::attach_tracepoint(
                &mut ebpf,
                "sys_enter_unlinkat",
                "syscalls",
                "sys_enter_unlinkat",
            )?;
        }
    }

    if config.events.network && config.network.enabled {
        if network_hooks.contains("connect") {
            attach::attach_tracepoint(
                &mut ebpf,
                "sys_enter_connect",
                "syscalls",
                "sys_enter_connect",
            )?;
        }
        if network_hooks.contains("bind") {
            attach::attach_tracepoint(&mut ebpf, "sys_enter_bind", "syscalls", "sys_enter_bind")?;
        }
        if network_hooks.contains("listen") {
            attach::attach_tracepoint(
                &mut ebpf,
                "sys_enter_listen",
                "syscalls",
                "sys_enter_listen",
            )?;
        }
    }

    let ring_buf = RingBuf::try_from(ebpf.map_mut("EVENTS").context("EVENTS map not found")?)?;
    let mut async_ring = AsyncFd::new(ring_buf)?;
    let mut output = output::JsonOutput::stdout();
    let mut table = ProcessTable::new();
    let rule_engine = rules::RuleEngine::new(&config.rules);

    let mut ci_smoke_start_seen = false;
    let mut ci_smoke_rel_or_exit_seen = false;
    let mut ci_smoke_file_open_seen = false;

    info!(
        agent = %config.agent.id,
        mode = ?config.agent.mode,
        hooks = ?config.process.hooks,
        config = %config_path,
        "EDR started and listening for lifecycle events"
    );

    loop {
        tokio::select! {
            ready = async_ring.readable_mut() => {
                let mut guard = ready?;
                let ring_buf = guard.get_inner_mut();
                while let Some(item) = ring_buf.next() {
                    let bytes: &[u8] = &item;

                    let mut dispatch_ctx = DispatchContext {
                        table: &mut table,
                        file_config: Some(&config.file),
                        persistence_detections: &config.detections.persistence,
                        network_detections: &config.detections.network,
                        ci_smoke,
                        ci_smoke_start_seen: &mut ci_smoke_start_seen,
                        ci_smoke_rel_or_exit_seen: &mut ci_smoke_rel_or_exit_seen,
                        ci_smoke_file_open_seen: &mut ci_smoke_file_open_seen,
                    };

                    let normalized = dispatch::dispatch_event(bytes, &mut dispatch_ctx);

                    if let Some(event) = normalized {
                        output.write_normalized(&event)?;
                        for alert in rule_engine.evaluate(&event) {
                            output.write_alert(&alert)?;
                        }
                        if ci_smoke_start_seen && ci_smoke_rel_or_exit_seen && ci_smoke_file_open_seen {
                            return Ok(());
                        }
                    }
                }
                guard.clear_ready();
            },
            _ = sleep(Duration::from_secs(10)), if ci_smoke => {
                if ci_smoke_start_seen && ci_smoke_rel_or_exit_seen && ci_smoke_file_open_seen {
                    return Ok(());
                }
                anyhow::bail!("CI smoke timeout: no ringbuf event received within 10 seconds.");
            },
            _ = signal::ctrl_c() => {
                info!("shutting down");
                break;
            }
        }
    }

    Ok(())
}
