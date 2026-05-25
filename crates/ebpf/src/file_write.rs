use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, r#gen},
    macros::tracepoint,
    programs::TracePointContext,
};
use edr_common::{
    EVENT_SCHEMA_VERSION, EventKind, FilePWrite64Event, FileWriteEvent, FileWriteVEvent,
};

use crate::EVENTS;

#[tracepoint]
pub fn sys_enter_write(ctx: TracePointContext) -> u32 {
    try_sys_enter_write(ctx).unwrap_or(1)
}

fn try_sys_enter_write(ctx: TracePointContext) -> Result<u32, i64> {
    try_sys_enter_write_family(ctx, 16, 32)
}

#[tracepoint]
pub fn sys_enter_writev(ctx: TracePointContext) -> u32 {
    try_sys_enter_writev(ctx).unwrap_or(1)
}

fn try_sys_enter_writev(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    let fd = unsafe { ctx.read_at::<u32>(16)? } as u64;
    let iovcnt = unsafe { ctx.read_at::<i32>(32)? } as i64;

    if let Some(mut entry) = EVENTS.reserve::<FileWriteVEvent>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();

            (*ptr).header.kind = EventKind::FileWriteV.as_u16();
            (*ptr).header.version = EVENT_SCHEMA_VERSION;
            (*ptr).header.size = FileWriteVEvent::SIZE;
            (*ptr).header.flags = 0;
            (*ptr).header.timestamp_ns = r#gen::bpf_ktime_get_ns();
            (*ptr).header.pid = pid;
            (*ptr).header.tid = tid;
            (*ptr).header.ppid = 0;
            (*ptr).header.uid = uid;
            (*ptr).header.gid = gid;
            (*ptr).header._pad = 0;

            (*ptr).fd = fd;
            (*ptr).iovcnt = iovcnt;
        }

        entry.submit(0);
    }

    Ok(0)
}

#[tracepoint]
pub fn sys_enter_pwrite64(ctx: TracePointContext) -> u32 {
    try_sys_enter_pwrite64(ctx).unwrap_or(1)
}

fn try_sys_enter_pwrite64(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    let fd = unsafe { ctx.read_at::<u32>(16)? } as u64;
    let count = unsafe { ctx.read_at::<u64>(32)? };
    let pos = unsafe { ctx.read_at::<i64>(40)? };

    if let Some(mut entry) = EVENTS.reserve::<FilePWrite64Event>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();

            (*ptr).header.kind = EventKind::FilePWrite64.as_u16();
            (*ptr).header.version = EVENT_SCHEMA_VERSION;
            (*ptr).header.size = FilePWrite64Event::SIZE;
            (*ptr).header.flags = 0;
            (*ptr).header.timestamp_ns = r#gen::bpf_ktime_get_ns();
            (*ptr).header.pid = pid;
            (*ptr).header.tid = tid;
            (*ptr).header.ppid = 0;
            (*ptr).header.uid = uid;
            (*ptr).header.gid = gid;
            (*ptr).header._pad = 0;

            (*ptr).fd = fd;
            (*ptr).count = count;
            (*ptr).pos = pos;
        }

        entry.submit(0);
    }

    Ok(0)
}

fn try_sys_enter_write_family(
    ctx: TracePointContext,
    fd_offset: usize,
    count_offset: usize,
) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    let fd = unsafe { ctx.read_at::<u32>(fd_offset)? } as u64;
    let count = unsafe { ctx.read_at::<u64>(count_offset)? };

    if let Some(mut entry) = EVENTS.reserve::<FileWriteEvent>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();

            (*ptr).header.kind = EventKind::FileWrite.as_u16();
            (*ptr).header.version = EVENT_SCHEMA_VERSION;
            (*ptr).header.size = FileWriteEvent::SIZE;
            (*ptr).header.flags = 0;
            (*ptr).header.timestamp_ns = r#gen::bpf_ktime_get_ns();
            (*ptr).header.pid = pid;
            (*ptr).header.tid = tid;
            (*ptr).header.ppid = 0;
            (*ptr).header.uid = uid;
            (*ptr).header.gid = gid;
            (*ptr).header._pad = 0;

            (*ptr).fd = fd;
            (*ptr).count = count;
        }

        entry.submit(0);
    }

    Ok(0)
}
