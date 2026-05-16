mod config;
mod logging;
mod privilege;

use anyhow::Context;
use aya::{maps::ring_buf::RingBuf, programs::TracePoint};
use edr_common::{
    EVENT_FLAG_FILENAME_TRUNCATED, EVENT_SCHEMA_VERSION, EventKind, ProcessExecEvent,
};
use tokio::io::unix::AsyncFd;
use tokio::signal;
use tokio::time::{Duration, sleep};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_path =
        std::env::var("EDR_CONFIG").unwrap_or_else(|_| "config.example.toml".to_string());
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

    let program: &mut TracePoint = ebpf
        .program_mut("sched_process_exec")
        .context("program not found")?
        .try_into()?;

    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    let ring_buf = RingBuf::try_from(ebpf.map_mut("EVENTS").context("EVENTS map not found")?)?;
    let mut async_ring = AsyncFd::new(ring_buf)?;

    info!(
        agent = %config.agent.id,
        mode = ?config.agent.mode,
        config = %config_path,
        "EDR started and listening for exec events"
    );

    loop {
        tokio::select! {
            ready = async_ring.readable_mut() => {
                let mut guard = ready?;
                let ring_buf = guard.get_inner_mut();
                while let Some(item) = ring_buf.next() {
                    let bytes: &[u8] = &item;
                    if bytes.len() >= core::mem::size_of::<ProcessExecEvent>() {
                        let event = unsafe {
                            core::ptr::read_unaligned(bytes.as_ptr() as *const ProcessExecEvent)
                        };

                        if event.header.kind == EventKind::ProcessExec.as_u16()
                            && event.header.version == EVENT_SCHEMA_VERSION
                            && event.header.size as usize == core::mem::size_of::<ProcessExecEvent>()
                        {
                            println!("{}", format_process_exec_event_json(&event));

                            if ci_smoke {
                                return Ok(());
                            }
                        }
                    }
                }
                guard.clear_ready();
            },
            _ = sleep(Duration::from_secs(3)), if ci_smoke => {
                anyhow::bail!("CI smoke timeout: no ringbuf event received within 3 seconds.");
            },
            _ = signal::ctrl_c() => {
                info!("shutting down");
                break;
            }
        }
    }

    Ok(())
}

fn format_process_exec_event_json(event: &ProcessExecEvent) -> String {
    let comm = fixed_string(&event.comm, event.comm.len());
    let filename_len = usize::from(event.filename_len).min(event.filename.len());
    let filename = fixed_string(&event.filename, filename_len);

    serde_json::json!({
        "event_type": "process_exec",
        "timestamp_ns": event.header.timestamp_ns,
        "pid": event.header.pid,
        "tid": event.header.tid,
        "ppid": event.header.ppid,
        "uid": event.header.uid,
        "gid": event.header.gid,
        "comm": comm,
        "filename": filename,
        "filename_truncated": event.header.flags & EVENT_FLAG_FILENAME_TRUNCATED != 0,
    })
    .to_string()
}

fn fixed_string(bytes: &[u8], max_len: usize) -> String {
    let len = bytes[..max_len]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(max_len);

    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_process_exec_event_as_json() {
        let mut event = ProcessExecEvent::default();
        event.header.kind = EventKind::ProcessExec.as_u16();
        event.header.version = EVENT_SCHEMA_VERSION;
        event.header.size = ProcessExecEvent::SIZE;
        event.header.flags = EVENT_FLAG_FILENAME_TRUNCATED;
        event.header.timestamp_ns = 123;
        event.header.pid = 100;
        event.header.tid = 101;
        event.header.ppid = 1;
        event.header.uid = 1000;
        event.header.gid = 1000;
        event.comm[..4].copy_from_slice(b"bash");
        event.filename[..13].copy_from_slice(b"/usr/bin/bash");
        event.filename_len = 13;

        let value: serde_json::Value =
            serde_json::from_str(&format_process_exec_event_json(&event))
                .expect("process exec event output should be valid JSON");

        assert_eq!(value["event_type"], "process_exec");
        assert_eq!(value["timestamp_ns"], 123);
        assert_eq!(value["pid"], 100);
        assert_eq!(value["uid"], 1000);
        assert_eq!(value["comm"], "bash");
        assert_eq!(value["filename"], "/usr/bin/bash");
        assert_eq!(value["filename_truncated"], true);
    }
}
