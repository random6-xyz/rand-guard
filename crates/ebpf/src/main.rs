#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes, r#gen,
    },
    macros::{map, tracepoint},
    maps::ring_buf::RingBuf,
    programs::TracePointContext,
};
use edr_common::{
    EVENT_FLAG_FILENAME_TRUNCATED, EVENT_SCHEMA_VERSION, EventKind, ExecSource, ExecSyscallEvent,
    FileOpenAt2Event, FileOpenEvent, FilePWrite64Event, FileRenameAt2Event, FileRenameAtEvent,
    FileRenameEvent, FileUnlinkAtEvent, FileUnlinkEvent, FileWriteEvent, FileWriteVEvent, PATH_LEN,
    ProcessExecEvent, ProcessExitEvent, ProcessForkEvent,
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(65536, 0);

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
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    // Read tracepoint data BEFORE reserving ring buffer.
    // Using `?` after reserve would leak the reference on failure.
    let parent_pid = unsafe { ctx.read_at::<u32>(12)? };
    let child_pid = unsafe { ctx.read_at::<u32>(20)? };

    if let Some(mut entry) = EVENTS.reserve::<ProcessForkEvent>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();

            // sched_process_fork tracepoint layout:
            //   offset 8:  parent_comm  (__data_loc char[])
            //   offset 12: parent_pid   (pid_t)
            //   offset 16: child_comm   (__data_loc char[])
            //   offset 20: child_pid    (pid_t)

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
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    // sched_process_exit tracepoint layout:
    //   offset 8:  comm (char[16])
    //   offset 24: pid (pid_t)
    //   offset 28: prio (int)
    //   offset 32: group_dead (bool)
    // Read tracepoint data BEFORE reserving ring buffer.
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

    // sys_enter_openat tracepoint layout:
    //   offset 16: dfd (int)
    //   offset 24: filename (const char *)
    //   offset 32: flags (int)
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

    // sys_enter_openat2 tracepoint layout:
    //   offset 24: filename (const char *)
    //   offset 32: how (struct open_how *)
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

#[tracepoint]
pub fn sys_enter_write(ctx: TracePointContext) -> u32 {
    try_sys_enter_write(ctx).unwrap_or(1)
}

fn try_sys_enter_write(ctx: TracePointContext) -> Result<u32, i64> {
    try_sys_enter_write_family(ctx, 16, 32, false, false)
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

    // sys_enter_writev tracepoint layout:
    //   offset 16: fd (unsigned int)
    //   offset 24: vec (const struct iovec *)
    //   offset 32: vlen (int)
    let fd = unsafe { ctx.read_at::<u32>(16)? } as u64;
    let iovcnt = unsafe { ctx.read_at::<i32>(32)? } as u64;

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

    // sys_enter_pwrite64 tracepoint layout:
    //   offset 16: fd (unsigned int)
    //   offset 24: buf (const char *)
    //   offset 32: count (size_t)
    //   offset 40: pos (loff_t)
    let fd = unsafe { ctx.read_at::<u32>(16)? } as u64;
    let count = unsafe { ctx.read_at::<u64>(32)? };
    let pos = unsafe { ctx.read_at::<u64>(40)? };

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
    _is_pwrite: bool,
    _is_writev: bool,
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

#[tracepoint]
pub fn sys_enter_rename(ctx: TracePointContext) -> u32 {
    try_sys_enter_rename(ctx).unwrap_or(1)
}

fn try_sys_enter_rename(ctx: TracePointContext) -> Result<u32, i64> {
    try_sys_enter_rename_family(ctx, 16, 24, false, false)
}

#[tracepoint]
pub fn sys_enter_renameat(ctx: TracePointContext) -> u32 {
    try_sys_enter_renameat(ctx).unwrap_or(1)
}

fn try_sys_enter_renameat(ctx: TracePointContext) -> Result<u32, i64> {
    try_sys_enter_renameat_family(ctx, 24, 40)
}

#[tracepoint]
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

    // sys_enter_renameat2 tracepoint layout:
    //   offset 24: oldname (const char *)
    //   offset 40: newname (const char *)
    //   offset 48: flags (unsigned int)
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
    _has_fd: bool,
    _is_at2: bool,
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

#[tracepoint]
pub fn sys_enter_unlink(ctx: TracePointContext) -> u32 {
    try_sys_enter_unlink(ctx).unwrap_or(1)
}

fn try_sys_enter_unlink(ctx: TracePointContext) -> Result<u32, i64> {
    try_sys_enter_unlink_family(ctx, 16, false)
}

#[tracepoint]
pub fn sys_enter_unlinkat(ctx: TracePointContext) -> u32 {
    try_sys_enter_unlinkat(ctx).unwrap_or(1)
}

fn try_sys_enter_unlinkat(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    // sys_enter_unlinkat tracepoint layout:
    //   offset 24: pathname (const char *)
    //   offset 32: flag (int)
    let pathname_ptr = unsafe { ctx.read_at::<u64>(24)? } as *const u8;
    let flags = unsafe { ctx.read_at::<i32>(32)? } as u32;

    if let Some(mut entry) = EVENTS.reserve::<FileUnlinkAtEvent>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();

            (*ptr).header.kind = EventKind::FileUnlinkAt.as_u16();
            (*ptr).header.version = EVENT_SCHEMA_VERSION;
            (*ptr).header.size = FileUnlinkAtEvent::SIZE;
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

            if !pathname_ptr.is_null() {
                let buf = &mut (&mut (*ptr).filename)[..];
                match bpf_probe_read_user_str_bytes(pathname_ptr, buf) {
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

fn try_sys_enter_unlink_family(
    ctx: TracePointContext,
    pathname_offset: usize,
    _has_flags: bool,
) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    let pathname_ptr = unsafe { ctx.read_at::<u64>(pathname_offset)? } as *const u8;

    if let Some(mut entry) = EVENTS.reserve::<FileUnlinkEvent>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();

            (*ptr).header.kind = EventKind::FileUnlink.as_u16();
            (*ptr).header.version = EVENT_SCHEMA_VERSION;
            (*ptr).header.size = FileUnlinkEvent::SIZE;
            (*ptr).header.flags = 0;
            (*ptr).header.timestamp_ns = r#gen::bpf_ktime_get_ns();
            (*ptr).header.pid = pid;
            (*ptr).header.tid = tid;
            (*ptr).header.ppid = 0;
            (*ptr).header.uid = uid;
            (*ptr).header.gid = gid;
            (*ptr).header._pad = 0;

            (*ptr)._pad = [0; 6];
            (*ptr).filename_len = 0;

            for item in (*ptr).filename.iter_mut() {
                *item = 0;
            }

            if !pathname_ptr.is_null() {
                let buf = &mut (&mut (*ptr).filename)[..];
                match bpf_probe_read_user_str_bytes(pathname_ptr, buf) {
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
