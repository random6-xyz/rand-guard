use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, r#gen},
    macros::tracepoint,
    programs::TracePointContext,
};
use edr_common::{
    EVENT_FLAG_FILENAME_TRUNCATED, EVENT_SCHEMA_VERSION, EventKind, PATH_LEN, ProcessExecEvent,
    ProcessExitEvent, ProcessForkEvent,
};

use crate::EVENTS;
use crate::helpers::read_data_loc_comm;

#[tracepoint(name = "sched_process_exec", category = "sched")]
#[inline(never)]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    try_sched_process_exec(ctx).unwrap_or(1)
}

fn try_sched_process_exec(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    if let Some(mut entry) = EVENTS.reserve::<ProcessExecEvent>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();

            (*ptr).header.kind = EventKind::ProcessExec.as_u16();
            (*ptr).header.version = EVENT_SCHEMA_VERSION;
            (*ptr).header.size = ProcessExecEvent::SIZE;
            (*ptr).header.flags = 0;
            (*ptr).header.timestamp_ns = r#gen::bpf_ktime_get_ns();
            (*ptr).header.pid = pid;
            (*ptr).header.tid = tid;
            (*ptr).header.ppid = 0;
            (*ptr).header.uid = uid;
            (*ptr).header.gid = gid;
            (*ptr).header._pad = 0;
            (*ptr)._pad = [0; 6];

            match bpf_get_current_comm() {
                Ok(comm) => (*ptr).comm = comm,
                Err(ret) => {
                    entry.discard(0);
                    return Err(ret);
                }
            }

            if let Err(ret) = read_sched_exec_filename(&ctx, &mut *ptr) {
                entry.discard(0);
                return Err(ret);
            }
        }

        entry.submit(0);
    }

    Ok(0)
}

unsafe fn read_sched_exec_filename(
    ctx: &TracePointContext,
    event: &mut ProcessExecEvent,
) -> Result<(), i64> {
    let data_loc = unsafe { ctx.read_at::<u32>(8)? };
    let filename_offset = (data_loc & 0xffff) as usize;
    let data_len = data_loc >> 16;

    if filename_offset == 0 || data_len == 0 {
        return Err(-1);
    }

    let mut copied = 0usize;
    let mut saw_null = false;

    for index in 0..PATH_LEN {
        event.filename[index] = 0;
    }

    for index in 0..PATH_LEN {
        if index as u32 >= data_len {
            break;
        }

        let byte = unsafe { ctx.read_at::<u8>(filename_offset + index)? };
        event.filename[index] = byte;

        if byte == 0 {
            saw_null = true;
            break;
        }

        copied = index + 1;
    }

    event.filename_len = copied as u16;

    if !saw_null && data_len as usize >= PATH_LEN {
        event.header.flags |= EVENT_FLAG_FILENAME_TRUNCATED;
    }

    Ok(())
}

#[tracepoint(name = "sched_process_fork", category = "sched")]
#[inline(never)]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    try_sched_process_fork(ctx).unwrap_or(1)
}

fn try_sched_process_fork(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    let parent_pid = unsafe { ctx.read_at::<u32>(12)? };
    let child_pid = unsafe { ctx.read_at::<u32>(20)? };

    if let Some(mut entry) = EVENTS.reserve::<ProcessForkEvent>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();

            (*ptr).header.kind = EventKind::ProcessFork.as_u16();
            (*ptr).header.version = EVENT_SCHEMA_VERSION;
            (*ptr).header.size = ProcessForkEvent::SIZE;
            (*ptr).header.flags = 0;
            (*ptr).header.timestamp_ns = r#gen::bpf_ktime_get_ns();
            (*ptr).header.pid = pid;
            (*ptr).header.tid = tid;
            (*ptr).header.ppid = 0;
            (*ptr).header.uid = uid;
            (*ptr).header.gid = gid;
            (*ptr).header._pad = 0;

            (*ptr).parent_pid = parent_pid;
            if let Err(ret) = read_data_loc_comm(&ctx, 8, &mut (*ptr).parent_comm) {
                entry.discard(0);
                return Err(ret);
            }

            (*ptr).child_pid = child_pid;
            (*ptr).child_tid = child_pid;

            if let Err(ret) = read_data_loc_comm(&ctx, 16, &mut (*ptr).child_comm) {
                entry.discard(0);
                return Err(ret);
            }
        }

        entry.submit(0);
    }

    Ok(0)
}

#[tracepoint(name = "sched_process_exit", category = "sched")]
#[inline(never)]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    try_sched_process_exit(ctx).unwrap_or(1)
}

fn try_sched_process_exit(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    let group_dead = unsafe { ctx.read_at::<u8>(32)? };

    let mut comm = [0u8; 16];
    for (i, item) in comm.iter_mut().enumerate() {
        *item = unsafe { ctx.read_at::<u8>(8 + i)? };
    }

    if let Some(mut entry) = EVENTS.reserve::<ProcessExitEvent>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();

            (*ptr).header.kind = EventKind::ProcessExit.as_u16();
            (*ptr).header.version = EVENT_SCHEMA_VERSION;
            (*ptr).header.size = ProcessExitEvent::SIZE;
            (*ptr).header.flags = 0;
            (*ptr).header.timestamp_ns = r#gen::bpf_ktime_get_ns();
            (*ptr).header.pid = pid;
            (*ptr).header.tid = tid;
            (*ptr).header.ppid = 0;
            (*ptr).header.uid = uid;
            (*ptr).header.gid = gid;
            (*ptr).header._pad = 0;

            (*ptr).group_dead = group_dead;
            (*ptr)._pad = [0; 7];
            (*ptr).comm.copy_from_slice(&comm);
        }

        entry.submit(0);
    }

    Ok(0)
}
