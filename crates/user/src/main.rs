use anyhow::Context;
use aya::{maps::ring_buf::RingBuf, programs::TracePoint};
use edr_common::ExecEvent;
use tokio::io::unix::AsyncFd;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ebpf_path = std::env::var("EDR_EBPF_OBJECT")
        .unwrap_or_else(|_| "crates/ebpf/target/bpfel-unknown-none/debug/edr-ebpf".to_string());

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

    println!("EDR started. Listening for exec events...");

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

                        let comm = core::str::from_utf8(&event.comm).unwrap_or("").trim_end_matches('\0');

                        println!(
                            "exec pid={} uid={} comm={}",
                            event.pid,
                            event.uid,
                            comm
                        );
                    }
                }

            }
            _ = signal::ctrl_c() => {
                println!("shutting down");
                break;
            }
        }
    }

    Ok(())
}
