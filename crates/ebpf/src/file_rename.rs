use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_user_str_bytes, r#gen,
    },
    macros::tracepoint,
    programs::TracePointContext,
};
use edr_common::{
    EVENT_FLAG_FILENAME_TRUNCATED, EVENT_SCHEMA_VERSION, EventKind, FileRenameAt2Event,
    FileRenameAtEvent, FileRenameEvent, PATH_LEN,
};

use crate::EVENTS;

#[tracepoint(name = "sys_enter_rename", category = "syscalls")]
#[inline(never)]
pub fn sys_enter_rename(ctx: TracePointContext) -> u32 {
    try_sys_enter_rename(ctx).unwrap_or(1)
}

fn try_sys_enter_rename(ctx: TracePointContext) -> Result<u32, i64> {
    try_sys_enter_rename_family(ctx, 16, 24)
}

#[tracepoint(name = "sys_enter_renameat", category = "syscalls")]
#[inline(never)]
pub fn sys_enter_renameat(ctx: TracePointContext) -> u32 {
    try_sys_enter_renameat(ctx).unwrap_or(1)
}

fn try_sys_enter_renameat(ctx: TracePointContext) -> Result<u32, i64> {
    try_sys_enter_renameat_family(ctx, 24, 40)
}

#[tracepoint(name = "sys_enter_renameat2", category = "syscalls")]
#[inline(never)]
pub fn sys_enter_renameat2(ctx: TracePointContext) -> u32 {
    try_sys_enter_renameat2(ctx).unwrap_or(1)
}

fn try_sys_enter_renameat2(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    let oldname_ptr = unsafe { ctx.read_at::<u64>(24)? } as *const u8;
    let newname_ptr = unsafe { ctx.read_at::<u64>(40)? } as *const u8;
    let flags = unsafe { ctx.read_at::<u32>(48)? };

    if let Some(mut entry) = EVENTS.reserve::<FileRenameAt2Event>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();

            (*ptr).header.kind = EventKind::FileRenameAt2.as_u16();
            (*ptr).header.version = EVENT_SCHEMA_VERSION;
            (*ptr).header.size = FileRenameAt2Event::SIZE;
            (*ptr).header.flags = 0;
            (*ptr).header.timestamp_ns = r#gen::bpf_ktime_get_ns();
            (*ptr).header.pid = pid;
            (*ptr).header.tid = tid;
            (*ptr).header.ppid = 0;
            (*ptr).header.uid = uid;
            (*ptr).header.gid = gid;
            (*ptr).header._pad = 0;

            (*ptr).flags = flags;
            (*ptr)._pad = [0; 4];
            (*ptr).old_filename_len = 0;
            (*ptr).new_filename_len = 0;

            for item in (*ptr).old_filename.iter_mut() {
                *item = 0;
            }
            for item in (*ptr).new_filename.iter_mut() {
                *item = 0;
            }

            if !oldname_ptr.is_null() {
                let buf = &mut (&mut (*ptr).old_filename)[..];
                match bpf_probe_read_user_str_bytes(oldname_ptr, buf) {
                    Ok(bytes) => {
                        (*ptr).old_filename_len = bytes.len() as u16;
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

            if !newname_ptr.is_null() {
                let buf = &mut (&mut (*ptr).new_filename)[..];
                match bpf_probe_read_user_str_bytes(newname_ptr, buf) {
                    Ok(bytes) => {
                        (*ptr).new_filename_len = bytes.len() as u16;
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

fn try_sys_enter_rename_family(
    ctx: TracePointContext,
    oldname_offset: usize,
    newname_offset: usize,
) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    let oldname_ptr = unsafe { ctx.read_at::<u64>(oldname_offset)? } as *const u8;
    let newname_ptr = unsafe { ctx.read_at::<u64>(newname_offset)? } as *const u8;

    if let Some(mut entry) = EVENTS.reserve::<FileRenameEvent>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();

            (*ptr).header.kind = EventKind::FileRename.as_u16();
            (*ptr).header.version = EVENT_SCHEMA_VERSION;
            (*ptr).header.size = FileRenameEvent::SIZE;
            (*ptr).header.flags = 0;
            (*ptr).header.timestamp_ns = r#gen::bpf_ktime_get_ns();
            (*ptr).header.pid = pid;
            (*ptr).header.tid = tid;
            (*ptr).header.ppid = 0;
            (*ptr).header.uid = uid;
            (*ptr).header.gid = gid;
            (*ptr).header._pad = 0;

            (*ptr)._pad = [0; 4];
            (*ptr).old_filename_len = 0;
            (*ptr).new_filename_len = 0;

            for item in (*ptr).old_filename.iter_mut() {
                *item = 0;
            }
            for item in (*ptr).new_filename.iter_mut() {
                *item = 0;
            }

            if !oldname_ptr.is_null() {
                let buf = &mut (&mut (*ptr).old_filename)[..];
                match bpf_probe_read_user_str_bytes(oldname_ptr, buf) {
                    Ok(bytes) => {
                        (*ptr).old_filename_len = bytes.len() as u16;
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

            if !newname_ptr.is_null() {
                let buf = &mut (&mut (*ptr).new_filename)[..];
                match bpf_probe_read_user_str_bytes(newname_ptr, buf) {
                    Ok(bytes) => {
                        (*ptr).new_filename_len = bytes.len() as u16;
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

fn try_sys_enter_renameat_family(
    ctx: TracePointContext,
    oldname_offset: usize,
    newname_offset: usize,
) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    let oldname_ptr = unsafe { ctx.read_at::<u64>(oldname_offset)? } as *const u8;
    let newname_ptr = unsafe { ctx.read_at::<u64>(newname_offset)? } as *const u8;

    if let Some(mut entry) = EVENTS.reserve::<FileRenameAtEvent>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();

            (*ptr).header.kind = EventKind::FileRenameAt.as_u16();
            (*ptr).header.version = EVENT_SCHEMA_VERSION;
            (*ptr).header.size = FileRenameAtEvent::SIZE;
            (*ptr).header.flags = 0;
            (*ptr).header.timestamp_ns = r#gen::bpf_ktime_get_ns();
            (*ptr).header.pid = pid;
            (*ptr).header.tid = tid;
            (*ptr).header.ppid = 0;
            (*ptr).header.uid = uid;
            (*ptr).header.gid = gid;
            (*ptr).header._pad = 0;

            (*ptr)._pad = [0; 4];
            (*ptr).old_filename_len = 0;
            (*ptr).new_filename_len = 0;

            for item in (*ptr).old_filename.iter_mut() {
                *item = 0;
            }
            for item in (*ptr).new_filename.iter_mut() {
                *item = 0;
            }

            if !oldname_ptr.is_null() {
                let buf = &mut (&mut (*ptr).old_filename)[..];
                match bpf_probe_read_user_str_bytes(oldname_ptr, buf) {
                    Ok(bytes) => {
                        (*ptr).old_filename_len = bytes.len() as u16;
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

            if !newname_ptr.is_null() {
                let buf = &mut (&mut (*ptr).new_filename)[..];
                match bpf_probe_read_user_str_bytes(newname_ptr, buf) {
                    Ok(bytes) => {
                        (*ptr).new_filename_len = bytes.len() as u16;
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
