mod config;

use anyhow::Context;
use aya::{maps::ring_buf::RingBuf, programs::TracePoint};
use edr_common::ExecEvent;
use tokio::io::unix::AsyncFd;
use tokio::signal;
use tokio::time::{Duration, sleep};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_path =
        std::env::var("EDR_CONFIG").unwrap_or_else(|_| "config.example.toml".to_string());
    let config = config::Config::from_path(&config_path)?;
    config.validate_current_runtime()?;

    let ebpf_path = std::env::var("EDR_EBPF_OBJECT")
        .unwrap_or_else(|_| "crates/ebpf/target/bpfel-unknown-none/debug/edr-ebpf".to_string());
    let ci_smoke = std::env::var("CI_SMOKE").as_deref() == Ok("1");

    let data = std::fs::read(&ebpf_path)?;
    let mut ebpf = aya::Ebpf::load(&data)?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        eprintln!("failed to initialized eBPF logger: {e}");
    }

    let program: &mut TracePoint = ebpf
        .program_mut("sched_process_exec")
        .context("program not found")?
        .try_into()?;

    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    let ring_buf = RingBuf::try_from(ebpf.map_mut("EVENTS").context("EVENTS map not found")?)?;
    let mut async_ring = AsyncFd::new(ring_buf)?;

    eprintln!(
        "EDR started. agent={} mode={:?} config={} listening for exec events...",
        config.agent.id, config.agent.mode, config_path
    );

    loop {
        tokio::select! {
            ready = async_ring.readable_mut() => {
                let mut guard = ready?;
                let ring_buf = guard.get_inner_mut();
                while let Some(item) = ring_buf.next() {
                    let bytes: &[u8] = &item;
                    if bytes.len() >= core::mem::size_of::<ExecEvent>() {
                        let event = unsafe {
                            core::ptr::read_unaligned(bytes.as_ptr() as *const ExecEvent)
                        };

                        println!("{}", format_exec_event_json(&event));

                        if ci_smoke {
                            return Ok(());
                        }
                    }
                }
            },
            _ = sleep(Duration::from_secs(3)), if ci_smoke => {
                anyhow::bail!("CI smoke timeout: no ringbuf event received within 3 seconds.");
            },
            _ = signal::ctrl_c() => {
                eprintln!("shutting down");
                break;
            }
        }
    }

    Ok(())
}

fn format_exec_event_json(event: &ExecEvent) -> String {
    let comm_len = event
        .comm
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(event.comm.len());
    let comm = String::from_utf8_lossy(&event.comm[..comm_len]);

    serde_json::json!({
        "event_type": "exec",
        "pid": event.pid,
        "tid": event.tid,
        "ppid": event.ppid,
        "uid": event.uid,
        "gid": event.gid,
        "comm": comm,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_exec_event_as_json() {
        let mut event = ExecEvent {
            pid: 100,
            tid: 101,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: [0; 16],
        };
        event.comm[..4].copy_from_slice(b"bash");

        let value: serde_json::Value = serde_json::from_str(&format_exec_event_json(&event))
            .expect("exec event output should be valid JSON");

        assert_eq!(value["event_type"], "exec");
        assert_eq!(value["pid"], 100);
        assert_eq!(value["uid"], 1000);
        assert_eq!(value["comm"], "bash");
    }
}
