use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes, r#gen,
    },
    macros::tracepoint,
    programs::TracePointContext,
};
use edr_common::{
    EVENT_FLAG_FILENAME_TRUNCATED, EVENT_SCHEMA_VERSION, EventKind, FileOpenAt2Event,
    FileOpenEvent, PATH_LEN,
};

use crate::EVENTS;

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    try_sys_enter_openat(ctx).unwrap_or(1)
}

fn try_sys_enter_openat(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    let filename_user_ptr = unsafe { ctx.read_at::<u64>(24)? } as *const u8;
    let flags = unsafe { ctx.read_at::<i32>(32)? } as u32;

    if let Some(mut entry) = EVENTS.reserve::<FileOpenEvent>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();

            (*ptr).header.kind = EventKind::FileOpen.as_u16();
            (*ptr).header.version = EVENT_SCHEMA_VERSION;
            (*ptr).header.size = FileOpenEvent::SIZE;
            (*ptr).header.flags = 0;
            (*ptr).header.timestamp_ns = r#gen::bpf_ktime_get_ns();
            (*ptr).header.pid = pid;
            (*ptr).header.tid = tid;
            (*ptr).header.ppid = 0;
            (*ptr).header.uid = uid;
            (*ptr).header.gid = gid;
            (*ptr).header._pad = 0;

            (*ptr).flags = flags;
            (*ptr)._pad = [0; 2];
            (*ptr).filename_len = 0;

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
            }
        }

        entry.submit(0);
    }

    Ok(0)
}

#[tracepoint]
pub fn sys_enter_openat2(ctx: TracePointContext) -> u32 {
    try_sys_enter_openat2(ctx).unwrap_or(1)
}

fn try_sys_enter_openat2(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    let filename_user_ptr = unsafe { ctx.read_at::<u64>(24)? } as *const u8;
    let how_ptr = unsafe { ctx.read_at::<u64>(32)? } as *const u64;

    let flags = if !how_ptr.is_null() {
        unsafe { bpf_probe_read_user::<u64>(how_ptr) }.unwrap_or(0)
    } else {
        0
    };

    if let Some(mut entry) = EVENTS.reserve::<FileOpenAt2Event>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();

            (*ptr).header.kind = EventKind::FileOpenAt2.as_u16();
            (*ptr).header.version = EVENT_SCHEMA_VERSION;
            (*ptr).header.size = FileOpenAt2Event::SIZE;
            (*ptr).header.flags = 0;
            (*ptr).header.timestamp_ns = r#gen::bpf_ktime_get_ns();
            (*ptr).header.pid = pid;
            (*ptr).header.tid = tid;
            (*ptr).header.ppid = 0;
            (*ptr).header.uid = uid;
            (*ptr).header.gid = gid;
            (*ptr).header._pad = 0;

            (*ptr).flags = flags;
            (*ptr)._pad = [0; 6];
            (*ptr).filename_len = 0;

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
            }
        }

        entry.submit(0);
    }

    Ok(0)
}
