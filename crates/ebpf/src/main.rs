#![no_std]
#![no_main]

use aya_ebpf::{
    cty::c_void,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, r#gen},
    macros::{map, tracepoint},
    maps::ring_buf::RingBuf,
    programs::TracePointContext,
};
use edr_common::ExecEvent;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4096, 0);

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_sched_process_exec(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sched_process_exec(_ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    if let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();

            (*ptr).pid = pid;
            (*ptr).tid = tid;
            (*ptr).ppid = 0;
            (*ptr).uid = uid;
            (*ptr).gid = gid;

            let ret = r#gen::bpf_get_current_comm((*ptr).comm.as_mut_ptr() as *mut c_void, 16);

            if ret < 0 {
                entry.discard(0);
                return Err(ret);
            }
        }

        entry.submit(0);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
