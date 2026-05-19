mod config;
mod detections;
mod logging;
mod normalize;
mod output;
mod privilege;
mod process_table;

use anyhow::Context;
use aya::{maps::ring_buf::RingBuf, programs::TracePoint};
use edr_common::{
    EVENT_SCHEMA_VERSION, EventKind, ExecSyscallEvent, FileOpenAt2Event, FileOpenEvent,
    FilePWrite64Event, FileRenameAt2Event, FileRenameAtEvent, FileRenameEvent, FileUnlinkAtEvent,
    FileUnlinkEvent, FileWriteEvent, FileWriteVEvent, ProcessExecEvent, ProcessExitEvent,
    ProcessForkEvent,
};
use tokio::io::unix::AsyncFd;
use tokio::signal;
use tokio::time::{Duration, sleep};
use tracing::{info, warn};

use crate::normalize::NormalizedEvent;
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

    if process_hooks.contains("execve") {
        attach_tracepoint(
            &mut ebpf,
            "sched_process_exec",
            "sched",
            "sched_process_exec",
        )?;
        attach_tracepoint(
            &mut ebpf,
            "sys_enter_execve",
            "syscalls",
            "sys_enter_execve",
        )?;
    }

    if process_hooks.contains("fork") {
        attach_tracepoint(
            &mut ebpf,
            "sched_process_fork",
            "sched",
            "sched_process_fork",
        )?;
    }

    if process_hooks.contains("exit") {
        attach_tracepoint(
            &mut ebpf,
            "sched_process_exit",
            "sched",
            "sched_process_exit",
        )?;
    }

    if process_hooks.contains("execveat") {
        attach_tracepoint(
            &mut ebpf,
            "sys_enter_execveat",
            "syscalls",
            "sys_enter_execveat",
        )?;
    }

    if config.file.enabled {
        if file_hooks.contains("openat") {
            attach_tracepoint(
                &mut ebpf,
                "sys_enter_openat",
                "syscalls",
                "sys_enter_openat",
            )?;
        }
        if file_hooks.contains("openat2") {
            attach_tracepoint(
                &mut ebpf,
                "sys_enter_openat2",
                "syscalls",
                "sys_enter_openat2",
            )?;
        }
        if file_hooks.contains("write") {
            attach_tracepoint(&mut ebpf, "sys_enter_write", "syscalls", "sys_enter_write")?;
        }
        if file_hooks.contains("writev") {
            attach_tracepoint(
                &mut ebpf,
                "sys_enter_writev",
                "syscalls",
                "sys_enter_writev",
            )?;
        }
        if file_hooks.contains("pwrite64") {
            attach_tracepoint(
                &mut ebpf,
                "sys_enter_pwrite64",
                "syscalls",
                "sys_enter_pwrite64",
            )?;
        }
        if file_hooks.contains("rename") {
            attach_tracepoint(
                &mut ebpf,
                "sys_enter_rename",
                "syscalls",
                "sys_enter_rename",
            )?;
        }
        if file_hooks.contains("renameat") {
            attach_tracepoint(
                &mut ebpf,
                "sys_enter_renameat",
                "syscalls",
                "sys_enter_renameat",
            )?;
        }
        if file_hooks.contains("renameat2") {
            attach_tracepoint(
                &mut ebpf,
                "sys_enter_renameat2",
                "syscalls",
                "sys_enter_renameat2",
            )?;
        }
        if file_hooks.contains("unlink") {
            attach_tracepoint(
                &mut ebpf,
                "sys_enter_unlink",
                "syscalls",
                "sys_enter_unlink",
            )?;
        }
        if file_hooks.contains("unlinkat") {
            attach_tracepoint(
                &mut ebpf,
                "sys_enter_unlinkat",
                "syscalls",
                "sys_enter_unlinkat",
            )?;
        }
    }

    let ring_buf = RingBuf::try_from(ebpf.map_mut("EVENTS").context("EVENTS map not found")?)?;
    let mut async_ring = AsyncFd::new(ring_buf)?;
    let mut output = output::JsonOutput::stdout();
    let mut table = ProcessTable::new();

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
                    if bytes.len() < core::mem::size_of::<edr_common::EventHeader>() {
                        continue;
                    }

                    let header = unsafe {
                        core::ptr::read_unaligned(bytes.as_ptr() as *const edr_common::EventHeader)
                    };

                    if header.version != EVENT_SCHEMA_VERSION {
                        continue;
                    }

                    let normalized = match header.kind {
                        k if k == EventKind::ProcessExec.as_u16() => {
                            if bytes.len() >= core::mem::size_of::<ProcessExecEvent>()
                                && header.size as usize == core::mem::size_of::<ProcessExecEvent>()
                            {
                                let event = unsafe {
                                    core::ptr::read_unaligned(bytes.as_ptr() as *const ProcessExecEvent)
                                };
                                Some(crate::normalize::normalize_exec(&event, &mut table))
                            } else {
                                None
                            }
                        }
                        k if k == EventKind::ProcessFork.as_u16() => {
                            if bytes.len() >= core::mem::size_of::<ProcessForkEvent>()
                                && header.size as usize == core::mem::size_of::<ProcessForkEvent>()
                            {
                                let event = unsafe {
                                    core::ptr::read_unaligned(bytes.as_ptr() as *const ProcessForkEvent)
                                };
                                Some(crate::normalize::normalize_fork(&event, &mut table))
                            } else {
                                None
                            }
                        }
                        k if k == EventKind::ProcessExit.as_u16() => {
                            if bytes.len() >= core::mem::size_of::<ProcessExitEvent>()
                                && header.size as usize == core::mem::size_of::<ProcessExitEvent>()
                            {
                                let event = unsafe {
                                    core::ptr::read_unaligned(bytes.as_ptr() as *const ProcessExitEvent)
                                };
                                Some(crate::normalize::normalize_exit(&event, &mut table))
                            } else {
                                None
                            }
                        }
                        k if k == EventKind::ExecSyscall.as_u16() => {
                            if bytes.len() >= core::mem::size_of::<ExecSyscallEvent>()
                                && header.size as usize == core::mem::size_of::<ExecSyscallEvent>()
                            {
                                let event = unsafe {
                                    core::ptr::read_unaligned(bytes.as_ptr() as *const ExecSyscallEvent)
                                };
                                crate::normalize::normalize_exec_syscall(&event, &mut table);
                            }
                            None
                        }
                        k if k == EventKind::FileOpen.as_u16() => {
                            if bytes.len() >= core::mem::size_of::<FileOpenEvent>()
                                && header.size as usize == core::mem::size_of::<FileOpenEvent>()
                            {
                                let event = unsafe {
                                    core::ptr::read_unaligned(bytes.as_ptr() as *const FileOpenEvent)
                                };
                                crate::normalize::normalize_file_open(&event, &mut table, Some(&config.file), &config.detections.persistence)
                            } else {
                                None
                            }
                        }
                        k if k == EventKind::FileOpenAt2.as_u16() => {
                            if bytes.len() >= core::mem::size_of::<FileOpenAt2Event>()
                                && header.size as usize == core::mem::size_of::<FileOpenAt2Event>()
                            {
                                let event = unsafe {
                                    core::ptr::read_unaligned(bytes.as_ptr() as *const FileOpenAt2Event)
                                };
                                crate::normalize::normalize_file_openat2(&event, &mut table, Some(&config.file), &config.detections.persistence)
                            } else {
                                None
                            }
                        }
                        k if k == EventKind::FileWrite.as_u16() => {
                            if bytes.len() >= core::mem::size_of::<FileWriteEvent>()
                                && header.size as usize == core::mem::size_of::<FileWriteEvent>()
                            {
                                let event = unsafe {
                                    core::ptr::read_unaligned(bytes.as_ptr() as *const FileWriteEvent)
                                };
                                crate::normalize::normalize_file_write(&event, &mut table, Some(&config.file), &config.detections.persistence)
                            } else {
                                None
                            }
                        }
                        k if k == EventKind::FileWriteV.as_u16() => {
                            if bytes.len() >= core::mem::size_of::<FileWriteVEvent>()
                                && header.size as usize == core::mem::size_of::<FileWriteVEvent>()
                            {
                                let event = unsafe {
                                    core::ptr::read_unaligned(bytes.as_ptr() as *const FileWriteVEvent)
                                };
                                crate::normalize::normalize_file_writev(&event, &mut table, Some(&config.file), &config.detections.persistence)
                            } else {
                                None
                            }
                        }
                        k if k == EventKind::FilePWrite64.as_u16() => {
                            if bytes.len() >= core::mem::size_of::<FilePWrite64Event>()
                                && header.size as usize == core::mem::size_of::<FilePWrite64Event>()
                            {
                                let event = unsafe {
                                    core::ptr::read_unaligned(bytes.as_ptr() as *const FilePWrite64Event)
                                };
                                crate::normalize::normalize_file_pwrite64(&event, &mut table, Some(&config.file), &config.detections.persistence)
                            } else {
                                None
                            }
                        }
                        k if k == EventKind::FileRename.as_u16() => {
                            if bytes.len() >= core::mem::size_of::<FileRenameEvent>()
                                && header.size as usize == core::mem::size_of::<FileRenameEvent>()
                            {
                                let event = unsafe {
                                    core::ptr::read_unaligned(bytes.as_ptr() as *const FileRenameEvent)
                                };
                                crate::normalize::normalize_file_rename(&event, &mut table, Some(&config.file), &config.detections.persistence)
                            } else {
                                None
                            }
                        }
                        k if k == EventKind::FileRenameAt.as_u16() => {
                            if bytes.len() >= core::mem::size_of::<FileRenameAtEvent>()
                                && header.size as usize == core::mem::size_of::<FileRenameAtEvent>()
                            {
                                let event = unsafe {
                                    core::ptr::read_unaligned(bytes.as_ptr() as *const FileRenameAtEvent)
                                };
                                crate::normalize::normalize_file_renameat(&event, &mut table, Some(&config.file), &config.detections.persistence)
                            } else {
                                None
                            }
                        }
                        k if k == EventKind::FileRenameAt2.as_u16() => {
                            if bytes.len() >= core::mem::size_of::<FileRenameAt2Event>()
                                && header.size as usize == core::mem::size_of::<FileRenameAt2Event>()
                            {
                                let event = unsafe {
                                    core::ptr::read_unaligned(bytes.as_ptr() as *const FileRenameAt2Event)
                                };
                                crate::normalize::normalize_file_renameat2(&event, &mut table, Some(&config.file), &config.detections.persistence)
                            } else {
                                None
                            }
                        }
                        k if k == EventKind::FileUnlink.as_u16() => {
                            if bytes.len() >= core::mem::size_of::<FileUnlinkEvent>()
                                && header.size as usize == core::mem::size_of::<FileUnlinkEvent>()
                            {
                                let event = unsafe {
                                    core::ptr::read_unaligned(bytes.as_ptr() as *const FileUnlinkEvent)
                                };
                                crate::normalize::normalize_file_unlink(&event, &mut table, Some(&config.file), &config.detections.persistence)
                            } else {
                                None
                            }
                        }
                        k if k == EventKind::FileUnlinkAt.as_u16() => {
                            if bytes.len() >= core::mem::size_of::<FileUnlinkAtEvent>()
                                && header.size as usize == core::mem::size_of::<FileUnlinkAtEvent>()
                            {
                                let event = unsafe {
                                    core::ptr::read_unaligned(bytes.as_ptr() as *const FileUnlinkAtEvent)
                                };
                                crate::normalize::normalize_file_unlinkat(&event, &mut table, Some(&config.file), &config.detections.persistence)
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };

                    if let Some(event) = normalized {
                        output.write_normalized(&event)?;
                        if ci_smoke {
                            match &event {
                                NormalizedEvent::ProcessStart(_) => ci_smoke_start_seen = true,
                                NormalizedEvent::ProcessRelationship(_) |
                                NormalizedEvent::ProcessExit(_) => ci_smoke_rel_or_exit_seen = true,
                                NormalizedEvent::FileOpen(_) => ci_smoke_file_open_seen = true,
                                _ => {}
                            }
                            if ci_smoke_start_seen && ci_smoke_rel_or_exit_seen && ci_smoke_file_open_seen {
                                return Ok(());
                            }
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

fn attach_tracepoint(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    category: &str,
    event: &str,
) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(program_name)
        .with_context(|| format!("program '{}' not found", program_name))?
        .try_into()
        .with_context(|| format!("program '{}' is not a tracepoint", program_name))?;

    program.load()?;
    program.attach(category, event)?;
    info!(program = %program_name, category = %category, event = %event, "tracepoint attached");
    Ok(())
}
