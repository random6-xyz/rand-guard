#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes, r#gen,
    },
    macros::{map, tracepoint},
    maps::ring_buf::RingBuf,
    programs::TracePointContext,
};
use edr_common::{
    EVENT_FLAG_FILENAME_TRUNCATED, EVENT_SCHEMA_VERSION, EventKind, ExecSource, ExecSyscallEvent,
    PATH_LEN, ProcessExecEvent, ProcessExitEvent, ProcessForkEvent,
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(8192, 0);

#[tracepoint]
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
    // sched_process_exec tracepoint layout: __data_loc filename is at offset 8.
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

unsafe fn read_data_loc_comm(
    ctx: &TracePointContext,
    data_loc_offset: usize,
    buf: &mut [u8],
) -> Result<(), i64> {
    let data_loc = unsafe { ctx.read_at::<u32>(data_loc_offset)? };
    let str_offset = (data_loc & 0xffff) as usize;
    let str_len = (data_loc >> 16) as usize;

    if str_offset == 0 {
        return Err(-1);
    }

    for item in buf.iter_mut() {
        *item = 0;
    }

    for (i, item) in buf.iter_mut().enumerate() {
        if i >= str_len {
            break;
        }
        let byte = unsafe { ctx.read_at::<u8>(str_offset + i)? };
        *item = byte;
        if byte == 0 {
            break;
        }
    }

    Ok(())
}

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    try_sched_process_fork(ctx).unwrap_or(1)
}

fn try_sched_process_fork(ctx: TracePointContext) -> Result<u32, i64> {
    let uid_gid = bpf_get_current_uid_gid();
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    if let Some(mut entry) = EVENTS.reserve::<ProcessForkEvent>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();

            // sched_process_fork tracepoint layout:
            //   offset 8:  parent_comm  (__data_loc char[])
            //   offset 12: parent_pid   (pid_t)
            //   offset 16: child_comm   (__data_loc char[])
            //   offset 20: child_pid    (pid_t)
            let parent_pid = ctx.read_at::<u32>(12)?;
            let child_pid = ctx.read_at::<u32>(20)?;

            (*ptr).header.kind = EventKind::ProcessFork.as_u16();
            (*ptr).header.version = EVENT_SCHEMA_VERSION;
            (*ptr).header.size = ProcessForkEvent::SIZE;
            (*ptr).header.flags = 0;
            (*ptr).header.timestamp_ns = r#gen::bpf_ktime_get_ns();
            (*ptr).header.pid = parent_pid;
            (*ptr).header.tid = parent_pid;
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
            // For a fork, child_tid is typically the same as child_pid
            // (thread-group leader). Full clone semantics would require
            // reading task_struct fields, which are unstable across
            // kernel versions, so we use child_pid as a safe proxy.
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

#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    try_sched_process_exit(ctx).unwrap_or(1)
}

fn try_sched_process_exit(ctx: TracePointContext) -> Result<u32, i64> {
    let uid_gid = bpf_get_current_uid_gid();
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    // sched_process_exit tracepoint layout:
    //   offset 8:  comm (char[16])
    //   offset 24: pid (pid_t)
    //   offset 28: prio (int)
    //   offset 32: group_dead (bool)
    let pid = unsafe { ctx.read_at::<u32>(24)? };
    let group_dead = unsafe { ctx.read_at::<u8>(32)? };

    if let Some(mut entry) = EVENTS.reserve::<ProcessExitEvent>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();

            (*ptr).header.kind = EventKind::ProcessExit.as_u16();
            (*ptr).header.version = EVENT_SCHEMA_VERSION;
            (*ptr).header.size = ProcessExitEvent::SIZE;
            (*ptr).header.flags = 0;
            (*ptr).header.timestamp_ns = r#gen::bpf_ktime_get_ns();
            (*ptr).header.pid = pid;
            (*ptr).header.tid = pid;
            (*ptr).header.ppid = 0;
            (*ptr).header.uid = uid;
            (*ptr).header.gid = gid;
            (*ptr).header._pad = 0;

            (*ptr).group_dead = group_dead;
            (*ptr)._pad = [0; 7];

            for i in 0..16usize {
                (*ptr).comm[i] = 0;
            }

            for i in 0..16usize {
                let byte = ctx.read_at::<u8>(8 + i)?;
                (*ptr).comm[i] = byte;
                if byte == 0 {
                    break;
                }
            }
        }

        entry.submit(0);
    }

    Ok(0)
}

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    try_sys_enter_execve(ctx).unwrap_or(1)
}

fn try_sys_enter_execve(ctx: TracePointContext) -> Result<u32, i64> {
    try_sys_enter_exec(ctx, 16, ExecSource::Execve)
}

#[tracepoint]
pub fn sys_enter_execveat(ctx: TracePointContext) -> u32 {
    try_sys_enter_execveat(ctx).unwrap_or(1)
}

fn try_sys_enter_execveat(ctx: TracePointContext) -> Result<u32, i64> {
    try_sys_enter_exec(ctx, 24, ExecSource::Execveat)
}

fn try_sys_enter_exec(
    ctx: TracePointContext,
    filename_ptr_offset: usize,
    source: ExecSource,
) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    let filename_user_ptr = unsafe { ctx.read_at::<u64>(filename_ptr_offset)? } as *const u8;

    if let Some(mut entry) = EVENTS.reserve::<ExecSyscallEvent>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();

            (*ptr).header.kind = EventKind::ExecSyscall.as_u16();
            (*ptr).header.version = EVENT_SCHEMA_VERSION;
            (*ptr).header.size = ExecSyscallEvent::SIZE;
            (*ptr).header.flags = 0;
            (*ptr).header.timestamp_ns = r#gen::bpf_ktime_get_ns();
            (*ptr).header.pid = pid;
            (*ptr).header.tid = tid;
            (*ptr).header.ppid = 0;
            (*ptr).header.uid = uid;
            (*ptr).header.gid = gid;
            (*ptr).header._pad = 0;

            (*ptr).source = source as u8;
            (*ptr)._pad = [0; 5];

            for item in (*ptr).filename.iter_mut() {
                *item = 0;
            }

            if !filename_user_ptr.is_null() {
                let buf = &mut (&mut (*ptr).filename)[..];
                match bpf_probe_read_user_str_bytes(filename_user_ptr, buf) {
                    Ok(bytes) => {
                        (*ptr).filename_len = bytes.len() as u16;
                        if bytes.len() >= PATH_LEN {
                            (*ptr).header.flags |= EVENT_FLAG_FILENAME_TRUNCATED;
                        }
                    }
                    Err(ret) => {
                        entry.discard(0);
                        return Err(ret);
                    }
                }
            } else {
                (*ptr).filename_len = 0;
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
