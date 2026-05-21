use edr_common::{
    EVENT_FLAG_FILENAME_TRUNCATED, ExecSyscallEvent, FileOpenAt2Event, FileOpenEvent,
    FilePWrite64Event, FileRenameAt2Event, FileRenameAtEvent, FileRenameEvent, FileUnlinkAtEvent,
    FileUnlinkEvent, FileWriteEvent, FileWriteVEvent, NetworkBindEvent, NetworkConnectEvent,
    NetworkFamily, NetworkListenEvent, ProcessExecEvent, ProcessExitEvent, ProcessForkEvent,
};

use crate::config::{FileConfig, PersistenceRule};

use crate::process_table::{ProcessTable, fixed_string};

/// Normalized userspace event emitted after raw ring-buffer records have
/// been decoded and enriched by the process table.
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum NormalizedEvent {
    ProcessStart(ProcessStart),
    ProcessExit(ProcessExit),
    ProcessRelationship(ProcessRelationship),
    FileOpen(FileOpen),
    FileOpenAt2(FileOpenAt2),
    FileWrite(FileWrite),
    FileWriteV(FileWriteV),
    FilePWrite64(FilePWrite64),
    FileRename(FileRename),
    FileRenameAt(FileRenameAt),
    FileRenameAt2(FileRenameAt2),
    FileUnlink(FileUnlink),
    FileUnlinkAt(FileUnlinkAt),
    NetworkConnect(NetworkConnect),
    NetworkBind(NetworkBind),
    NetworkListen(NetworkListen),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessStart {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    /// `Some("execve")` or `Some("execveat")` when correlated from a raw
    /// syscall event that preceded this `sched_process_exec`.
    pub source: Option<String>,
    pub timestamp_ns: u64,
    pub filename_truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessExit {
    pub pid: u32,
    pub tid: u32,
    pub comm: String,
    pub group_dead: bool,
    pub uid: u32,
    pub gid: u32,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessRelationship {
    pub parent_pid: u32,
    pub parent_comm: String,
    pub child_pid: u32,
    pub child_tid: u32,
    pub child_comm: String,
    pub uid: u32,
    pub gid: u32,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileOpen {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub filename: String,
    pub flags: u32,
    pub filename_truncated: bool,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileOpenAt2 {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub filename: String,
    pub flags: u64,
    pub filename_truncated: bool,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileWrite {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub fd: u64,
    pub count: u64,
    pub resolved_path: String,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileWriteV {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub fd: u64,
    pub iovcnt: i64,
    pub resolved_path: String,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilePWrite64 {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub fd: u64,
    pub count: u64,
    pub pos: i64,
    pub resolved_path: String,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRename {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub old_filename: String,
    pub new_filename: String,
    pub filename_truncated: bool,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRenameAt {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub old_filename: String,
    pub new_filename: String,
    pub filename_truncated: bool,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRenameAt2 {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub old_filename: String,
    pub new_filename: String,
    pub flags: u32,
    pub filename_truncated: bool,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileUnlink {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub filename: String,
    pub filename_truncated: bool,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileUnlinkAt {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub filename: String,
    pub flags: u32,
    pub filename_truncated: bool,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkConnect {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub family: String,
    pub socket_fd: i32,
    pub remote_addr: String,
    pub remote_port: u16,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkBind {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub family: String,
    pub socket_fd: i32,
    pub local_addr: String,
    pub local_port: u16,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkListen {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub family: String,
    pub socket_fd: i32,
    pub local_addr: String,
    pub local_port: u16,
    pub backlog: i32,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

/// Convert a raw `sched_process_exec` record into a normalized `ProcessStart`.
pub fn normalize_exec(event: &ProcessExecEvent, table: &mut ProcessTable) -> NormalizedEvent {
    let record = table.update_from_exec(event);
    let filename_truncated = event.header.flags & EVENT_FLAG_FILENAME_TRUNCATED != 0;

    NormalizedEvent::ProcessStart(ProcessStart {
        pid: record.pid,
        tid: record.tid,
        ppid: record.ppid,
        uid: record.uid,
        gid: record.gid,
        comm: record.comm,
        exe_path: record.exe_path,
        source: record.pending_source,
        timestamp_ns: event.header.timestamp_ns,
        filename_truncated,
    })
}

/// Convert a raw `sched_process_fork` record into a normalized
/// `ProcessRelationship` and update the process table with the child.
pub fn normalize_fork(event: &ProcessForkEvent, table: &mut ProcessTable) -> NormalizedEvent {
    let record = table.insert_from_fork(event);
    let parent_comm = fixed_string(&event.parent_comm, event.parent_comm.len());

    NormalizedEvent::ProcessRelationship(ProcessRelationship {
        parent_pid: event.parent_pid,
        parent_comm,
        child_pid: record.pid,
        child_tid: record.tid,
        child_comm: record.comm,
        uid: event.header.uid,
        gid: event.header.gid,
        timestamp_ns: event.header.timestamp_ns,
    })
}

/// Convert a raw `sched_process_exit` record into a normalized `ProcessExit`.
///
/// If the `(pid, tid)` is known in the process table the enriched record is
/// used; otherwise the raw fields are emitted directly.
pub fn normalize_exit(event: &ProcessExitEvent, table: &mut ProcessTable) -> NormalizedEvent {
    let comm = fixed_string(&event.comm, event.comm.len());
    let group_dead = event.group_dead != 0;

    if let Some(record) = table.mark_exit(event) {
        NormalizedEvent::ProcessExit(ProcessExit {
            pid: record.pid,
            tid: record.tid,
            comm: record.comm,
            group_dead,
            uid: record.uid,
            gid: record.gid,
            timestamp_ns: event.header.timestamp_ns,
        })
    } else {
        NormalizedEvent::ProcessExit(ProcessExit {
            pid: event.header.pid,
            tid: event.header.tid,
            comm,
            group_dead,
            uid: event.header.uid,
            gid: event.header.gid,
            timestamp_ns: event.header.timestamp_ns,
        })
    }
}

/// Update the process table with a pending syscall source (`execve` or
/// `execveat`).  No normalized event is emitted for raw syscall records.
pub fn normalize_exec_syscall(event: &ExecSyscallEvent, table: &mut ProcessTable) {
    table.set_pending_source(event);
}

/// Resolve a file descriptor to a path via `/proc/<pid>/fd/<fd>`.
fn resolve_fd_path(pid: u32, fd: u64) -> String {
    let path = format!("/proc/{pid}/fd/{fd}");
    std::fs::read_link(&path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Check whether a filename passes the configured watch/exclude filters.
///
/// * If `watch_paths` or `watch_patterns` are non-empty, the filename must
///   match at least one prefix **or** one pattern.
/// * If `exclude_paths` are non-empty, the filename must not match any
///   exclude prefix.
fn passes_file_filter(filename: &str, config: &FileConfig) -> bool {
    let has_watch = !config.watch_paths.is_empty() || !config.watch_patterns.is_empty();
    if has_watch {
        let matches_prefix = config.watch_paths.iter().any(|p| filename.starts_with(p));
        let matches_pattern = config.watch_patterns.iter().any(|pat| {
            if let Some(suffix) = pat.strip_prefix("*.") {
                filename.ends_with(&format!(".{suffix}"))
            } else {
                filename.contains(pat.as_str())
            }
        });
        if !matches_prefix && !matches_pattern {
            return false;
        }
    }

    if config.exclude_paths.iter().any(|p| filename.starts_with(p)) {
        return false;
    }

    true
}

fn passes_file_filter_opt(filename: &str, file_config: Option<&FileConfig>) -> bool {
    let Some(config) = file_config else {
        return true;
    };
    passes_file_filter(filename, config)
}

fn enrich_from_table(
    header: &edr_common::EventHeader,
    table: &ProcessTable,
) -> (String, String, u32) {
    if let Some(record) = table.get(&(header.pid, header.tid)) {
        (record.comm.clone(), record.exe_path.clone(), record.ppid)
    } else {
        (String::new(), String::new(), 0)
    }
}

fn enrich_from_table_or_comm(
    header: &edr_common::EventHeader,
    table: &ProcessTable,
    raw_comm: &[u8],
) -> (String, String, u32) {
    if let Some(record) = table.get(&(header.pid, header.tid)) {
        (record.comm.clone(), record.exe_path.clone(), record.ppid)
    } else {
        (fixed_string(raw_comm, raw_comm.len()), String::new(), 0)
    }
}

fn network_family(family: u16) -> String {
    match family {
        f if f == NetworkFamily::Ipv4 as u16 => "ipv4".to_string(),
        f if f == NetworkFamily::Ipv6 as u16 => "ipv6".to_string(),
        _ => "unknown".to_string(),
    }
}

fn network_addr(family: u16, ipv4_addr: u32, ipv6_addr: &[u8; 16]) -> String {
    if family == NetworkFamily::Ipv4 as u16 {
        let octets = ipv4_addr.to_be_bytes();
        format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
    } else if family == NetworkFamily::Ipv6 as u16 {
        std::net::Ipv6Addr::from(*ipv6_addr).to_string()
    } else {
        String::new()
    }
}

fn detect_for_path(
    path: &str,
    operation: &str,
    detections: &[PersistenceRule],
) -> (bool, Option<String>) {
    if let Some(name) = crate::detections::check_persistence(path, operation, detections) {
        (true, Some(name))
    } else {
        (false, None)
    }
}

fn detect_for_paths(
    paths: &[&str],
    operation: &str,
    detections: &[PersistenceRule],
) -> (bool, Option<String>) {
    for path in paths {
        if let Some(name) = crate::detections::check_persistence(path, operation, detections) {
            return (true, Some(name));
        }
    }
    (false, None)
}

/// Convert a raw `sys_enter_openat` record into a normalized `FileOpen`.
pub fn normalize_file_open(
    event: &FileOpenEvent,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[PersistenceRule],
) -> Option<NormalizedEvent> {
    let filename = fixed_string(&event.filename, event.filename.len());
    if !passes_file_filter_opt(&filename, file_config) {
        return None;
    }

    let filename_truncated = event.header.flags & EVENT_FLAG_FILENAME_TRUNCATED != 0;
    let (comm, exe_path, ppid) = enrich_from_table(&event.header, table);
    let (alert, detection_type) = detect_for_path(&filename, "file_open", detections);

    Some(NormalizedEvent::FileOpen(FileOpen {
        pid: event.header.pid,
        tid: event.header.tid,
        ppid,
        uid: event.header.uid,
        gid: event.header.gid,
        comm,
        exe_path,
        filename,
        flags: event.flags,
        filename_truncated,
        alert,
        detection_type,
        timestamp_ns: event.header.timestamp_ns,
    }))
}

/// Convert a raw `sys_enter_openat2` record into a normalized `FileOpenAt2`.
pub fn normalize_file_openat2(
    event: &FileOpenAt2Event,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[PersistenceRule],
) -> Option<NormalizedEvent> {
    let filename = fixed_string(&event.filename, event.filename.len());
    if !passes_file_filter_opt(&filename, file_config) {
        return None;
    }

    let filename_truncated = event.header.flags & EVENT_FLAG_FILENAME_TRUNCATED != 0;
    let (comm, exe_path, ppid) = enrich_from_table(&event.header, table);
    let (alert, detection_type) = detect_for_path(&filename, "file_open", detections);

    Some(NormalizedEvent::FileOpenAt2(FileOpenAt2 {
        pid: event.header.pid,
        tid: event.header.tid,
        ppid,
        uid: event.header.uid,
        gid: event.header.gid,
        comm,
        exe_path,
        filename,
        flags: event.flags,
        filename_truncated,
        alert,
        detection_type,
        timestamp_ns: event.header.timestamp_ns,
    }))
}

/// Convert a raw `sys_enter_write` record into a normalized `FileWrite`.
pub fn normalize_file_write(
    event: &FileWriteEvent,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[PersistenceRule],
) -> Option<NormalizedEvent> {
    let resolved_path = resolve_fd_path(event.header.pid, event.fd);
    if !passes_file_filter_opt(&resolved_path, file_config) {
        return None;
    }

    let (comm, exe_path, ppid) = enrich_from_table(&event.header, table);
    let (alert, detection_type) = detect_for_path(&resolved_path, "file_write", detections);

    Some(NormalizedEvent::FileWrite(FileWrite {
        pid: event.header.pid,
        tid: event.header.tid,
        ppid,
        uid: event.header.uid,
        gid: event.header.gid,
        comm,
        exe_path,
        fd: event.fd,
        count: event.count,
        resolved_path,
        alert,
        detection_type,
        timestamp_ns: event.header.timestamp_ns,
    }))
}

/// Convert a raw `sys_enter_writev` record into a normalized `FileWriteV`.
pub fn normalize_file_writev(
    event: &FileWriteVEvent,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[PersistenceRule],
) -> Option<NormalizedEvent> {
    let resolved_path = resolve_fd_path(event.header.pid, event.fd);
    if !passes_file_filter_opt(&resolved_path, file_config) {
        return None;
    }

    let (comm, exe_path, ppid) = enrich_from_table(&event.header, table);
    let (alert, detection_type) = detect_for_path(&resolved_path, "file_write", detections);

    Some(NormalizedEvent::FileWriteV(FileWriteV {
        pid: event.header.pid,
        tid: event.header.tid,
        ppid,
        uid: event.header.uid,
        gid: event.header.gid,
        comm,
        exe_path,
        fd: event.fd,
        iovcnt: event.iovcnt,
        resolved_path,
        alert,
        detection_type,
        timestamp_ns: event.header.timestamp_ns,
    }))
}

/// Convert a raw `sys_enter_pwrite64` record into a normalized `FilePWrite64`.
pub fn normalize_file_pwrite64(
    event: &FilePWrite64Event,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[PersistenceRule],
) -> Option<NormalizedEvent> {
    let resolved_path = resolve_fd_path(event.header.pid, event.fd);
    if !passes_file_filter_opt(&resolved_path, file_config) {
        return None;
    }

    let (comm, exe_path, ppid) = enrich_from_table(&event.header, table);
    let (alert, detection_type) = detect_for_path(&resolved_path, "file_write", detections);

    Some(NormalizedEvent::FilePWrite64(FilePWrite64 {
        pid: event.header.pid,
        tid: event.header.tid,
        ppid,
        uid: event.header.uid,
        gid: event.header.gid,
        comm,
        exe_path,
        fd: event.fd,
        count: event.count,
        pos: event.pos,
        resolved_path,
        alert,
        detection_type,
        timestamp_ns: event.header.timestamp_ns,
    }))
}

/// Convert a raw `sys_enter_rename` record into a normalized `FileRename`.
pub fn normalize_file_rename(
    event: &FileRenameEvent,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[PersistenceRule],
) -> Option<NormalizedEvent> {
    let old_filename = fixed_string(&event.old_filename, event.old_filename.len());
    let new_filename = fixed_string(&event.new_filename, event.new_filename.len());
    if !passes_file_filter_opt(&old_filename, file_config)
        && !passes_file_filter_opt(&new_filename, file_config)
    {
        return None;
    }

    let filename_truncated = event.header.flags & EVENT_FLAG_FILENAME_TRUNCATED != 0;
    let (comm, exe_path, ppid) = enrich_from_table(&event.header, table);
    let (alert, detection_type) =
        detect_for_paths(&[&old_filename, &new_filename], "file_rename", detections);

    Some(NormalizedEvent::FileRename(FileRename {
        pid: event.header.pid,
        tid: event.header.tid,
        ppid,
        uid: event.header.uid,
        gid: event.header.gid,
        comm,
        exe_path,
        old_filename,
        new_filename,
        filename_truncated,
        alert,
        detection_type,
        timestamp_ns: event.header.timestamp_ns,
    }))
}

/// Convert a raw `sys_enter_renameat` record into a normalized `FileRenameAt`.
pub fn normalize_file_renameat(
    event: &FileRenameAtEvent,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[PersistenceRule],
) -> Option<NormalizedEvent> {
    let old_filename = fixed_string(&event.old_filename, event.old_filename.len());
    let new_filename = fixed_string(&event.new_filename, event.new_filename.len());
    if !passes_file_filter_opt(&old_filename, file_config)
        && !passes_file_filter_opt(&new_filename, file_config)
    {
        return None;
    }

    let filename_truncated = event.header.flags & EVENT_FLAG_FILENAME_TRUNCATED != 0;
    let (comm, exe_path, ppid) = enrich_from_table(&event.header, table);
    let (alert, detection_type) =
        detect_for_paths(&[&old_filename, &new_filename], "file_rename", detections);

    Some(NormalizedEvent::FileRenameAt(FileRenameAt {
        pid: event.header.pid,
        tid: event.header.tid,
        ppid,
        uid: event.header.uid,
        gid: event.header.gid,
        comm,
        exe_path,
        old_filename,
        new_filename,
        filename_truncated,
        alert,
        detection_type,
        timestamp_ns: event.header.timestamp_ns,
    }))
}

/// Convert a raw `sys_enter_renameat2` record into a normalized `FileRenameAt2`.
pub fn normalize_file_renameat2(
    event: &FileRenameAt2Event,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[PersistenceRule],
) -> Option<NormalizedEvent> {
    let old_filename = fixed_string(&event.old_filename, event.old_filename.len());
    let new_filename = fixed_string(&event.new_filename, event.new_filename.len());
    if !passes_file_filter_opt(&old_filename, file_config)
        && !passes_file_filter_opt(&new_filename, file_config)
    {
        return None;
    }

    let filename_truncated = event.header.flags & EVENT_FLAG_FILENAME_TRUNCATED != 0;
    let (comm, exe_path, ppid) = enrich_from_table(&event.header, table);
    let (alert, detection_type) =
        detect_for_paths(&[&old_filename, &new_filename], "file_rename", detections);

    Some(NormalizedEvent::FileRenameAt2(FileRenameAt2 {
        pid: event.header.pid,
        tid: event.header.tid,
        ppid,
        uid: event.header.uid,
        gid: event.header.gid,
        comm,
        exe_path,
        old_filename,
        new_filename,
        flags: event.flags,
        filename_truncated,
        alert,
        detection_type,
        timestamp_ns: event.header.timestamp_ns,
    }))
}

/// Convert a raw `sys_enter_unlink` record into a normalized `FileUnlink`.
pub fn normalize_file_unlink(
    event: &FileUnlinkEvent,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[PersistenceRule],
) -> Option<NormalizedEvent> {
    let filename = fixed_string(&event.filename, event.filename.len());
    if !passes_file_filter_opt(&filename, file_config) {
        return None;
    }

    let filename_truncated = event.header.flags & EVENT_FLAG_FILENAME_TRUNCATED != 0;
    let (comm, exe_path, ppid) = enrich_from_table(&event.header, table);
    let (alert, detection_type) = detect_for_path(&filename, "file_unlink", detections);

    Some(NormalizedEvent::FileUnlink(FileUnlink {
        pid: event.header.pid,
        tid: event.header.tid,
        ppid,
        uid: event.header.uid,
        gid: event.header.gid,
        comm,
        exe_path,
        filename,
        filename_truncated,
        alert,
        detection_type,
        timestamp_ns: event.header.timestamp_ns,
    }))
}

/// Convert a raw `sys_enter_unlinkat` record into a normalized `FileUnlinkAt`.
pub fn normalize_file_unlinkat(
    event: &FileUnlinkAtEvent,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[PersistenceRule],
) -> Option<NormalizedEvent> {
    let filename = fixed_string(&event.filename, event.filename.len());
    if !passes_file_filter_opt(&filename, file_config) {
        return None;
    }

    let filename_truncated = event.header.flags & EVENT_FLAG_FILENAME_TRUNCATED != 0;
    let (comm, exe_path, ppid) = enrich_from_table(&event.header, table);
    let (alert, detection_type) = detect_for_path(&filename, "file_unlink", detections);

    Some(NormalizedEvent::FileUnlinkAt(FileUnlinkAt {
        pid: event.header.pid,
        tid: event.header.tid,
        ppid,
        uid: event.header.uid,
        gid: event.header.gid,
        comm,
        exe_path,
        filename,
        flags: event.flags,
        filename_truncated,
        alert,
        detection_type,
        timestamp_ns: event.header.timestamp_ns,
    }))
}

/// Convert a raw `sys_enter_connect` record into a normalized network event.
pub fn normalize_network_connect(
    event: &NetworkConnectEvent,
    table: &mut ProcessTable,
) -> Option<NormalizedEvent> {
    let (comm, exe_path, ppid) = enrich_from_table_or_comm(&event.header, table, &event.comm);

    Some(NormalizedEvent::NetworkConnect(NetworkConnect {
        pid: event.header.pid,
        tid: event.header.tid,
        ppid,
        uid: event.header.uid,
        gid: event.header.gid,
        comm,
        exe_path,
        family: network_family(event.family),
        socket_fd: event.socket_fd,
        remote_addr: network_addr(event.family, event.ipv4_addr, &event.ipv6_addr),
        remote_port: event.port,
        alert: false,
        detection_type: None,
        timestamp_ns: event.header.timestamp_ns,
    }))
}

/// Convert a raw `sys_enter_bind` record into a normalized network event.
pub fn normalize_network_bind(
    event: &NetworkBindEvent,
    table: &mut ProcessTable,
) -> Option<NormalizedEvent> {
    let (comm, exe_path, ppid) = enrich_from_table_or_comm(&event.header, table, &event.comm);

    Some(NormalizedEvent::NetworkBind(NetworkBind {
        pid: event.header.pid,
        tid: event.header.tid,
        ppid,
        uid: event.header.uid,
        gid: event.header.gid,
        comm,
        exe_path,
        family: network_family(event.family),
        socket_fd: event.socket_fd,
        local_addr: network_addr(event.family, event.ipv4_addr, &event.ipv6_addr),
        local_port: event.port,
        alert: false,
        detection_type: None,
        timestamp_ns: event.header.timestamp_ns,
    }))
}

/// Convert a raw `sys_enter_listen` record into a normalized network event.
pub fn normalize_network_listen(
    event: &NetworkListenEvent,
    table: &mut ProcessTable,
) -> Option<NormalizedEvent> {
    let (comm, exe_path, ppid) = enrich_from_table_or_comm(&event.header, table, &event.comm);

    Some(NormalizedEvent::NetworkListen(NetworkListen {
        pid: event.header.pid,
        tid: event.header.tid,
        ppid,
        uid: event.header.uid,
        gid: event.header.gid,
        comm,
        exe_path,
        family: network_family(event.family),
        socket_fd: event.socket_fd,
        local_addr: network_addr(event.family, event.ipv4_addr, &event.ipv6_addr),
        local_port: event.port,
        backlog: event.backlog,
        alert: false,
        detection_type: None,
        timestamp_ns: event.header.timestamp_ns,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use edr_common::{
        EVENT_SCHEMA_VERSION, EventKind, ExecSource, ExecSyscallEvent, NetworkConnectEvent,
        NetworkFamily, ProcessExecEvent, ProcessExitEvent, ProcessForkEvent,
    };

    fn make_exec_event(
        pid: u32,
        tid: u32,
        ppid: u32,
        filename: &str,
        comm: &str,
    ) -> ProcessExecEvent {
        let mut event = ProcessExecEvent::default();
        event.header.kind = EventKind::ProcessExec.as_u16();
        event.header.version = EVENT_SCHEMA_VERSION;
        event.header.size = ProcessExecEvent::SIZE;
        event.header.timestamp_ns = 1000;
        event.header.pid = pid;
        event.header.tid = tid;
        event.header.ppid = ppid;
        event.header.uid = 1000;
        event.header.gid = 1000;
        event.comm[..comm.len()].copy_from_slice(comm.as_bytes());
        event.filename[..filename.len()].copy_from_slice(filename.as_bytes());
        event.filename_len = filename.len() as u16;
        event
    }

    fn make_fork_event(
        parent_pid: u32,
        child_pid: u32,
        child_tid: u32,
        parent_comm: &str,
        child_comm: &str,
    ) -> ProcessForkEvent {
        let mut event = ProcessForkEvent::default();
        event.header.kind = EventKind::ProcessFork.as_u16();
        event.header.version = EVENT_SCHEMA_VERSION;
        event.header.size = ProcessForkEvent::SIZE;
        event.header.timestamp_ns = 2000;
        event.header.uid = 1000;
        event.header.gid = 1000;
        event.parent_pid = parent_pid;
        event.parent_comm[..parent_comm.len()].copy_from_slice(parent_comm.as_bytes());
        event.child_pid = child_pid;
        event.child_tid = child_tid;
        event.child_comm[..child_comm.len()].copy_from_slice(child_comm.as_bytes());
        event
    }

    fn make_exit_event(pid: u32, tid: u32, comm: &str) -> ProcessExitEvent {
        let mut event = ProcessExitEvent::default();
        event.header.kind = EventKind::ProcessExit.as_u16();
        event.header.version = EVENT_SCHEMA_VERSION;
        event.header.size = ProcessExitEvent::SIZE;
        event.header.timestamp_ns = 3000;
        event.header.pid = pid;
        event.header.tid = tid;
        event.header.uid = 1000;
        event.header.gid = 1000;
        event.comm[..comm.len()].copy_from_slice(comm.as_bytes());
        event
    }

    fn make_exec_syscall_event(pid: u32, tid: u32, source: ExecSource) -> ExecSyscallEvent {
        let mut event = ExecSyscallEvent::default();
        event.header.kind = EventKind::ExecSyscall.as_u16();
        event.header.version = EVENT_SCHEMA_VERSION;
        event.header.size = ExecSyscallEvent::SIZE;
        event.header.timestamp_ns = 500;
        event.header.pid = pid;
        event.header.tid = tid;
        event.source = source as u8;
        event
    }

    fn file_config() -> FileConfig {
        FileConfig {
            enabled: true,
            hooks: vec!["openat".to_string()],
            watch_paths: vec!["/etc".to_string()],
            watch_patterns: vec!["*.service".to_string()],
            exclude_paths: vec!["/etc/ignore".to_string()],
        }
    }

    fn make_file_open_event(filename: &str) -> FileOpenEvent {
        let mut event = FileOpenEvent::default();
        event.header.kind = EventKind::FileOpen.as_u16();
        event.header.version = EVENT_SCHEMA_VERSION;
        event.header.size = FileOpenEvent::SIZE;
        event.header.timestamp_ns = 4000;
        event.header.pid = 42;
        event.header.tid = 42;
        event.header.uid = 1000;
        event.header.gid = 1000;
        event.filename[..filename.len()].copy_from_slice(filename.as_bytes());
        event.filename_len = filename.len() as u16;
        event
    }

    fn make_network_connect_event(pid: u32, tid: u32, comm: &str) -> NetworkConnectEvent {
        let mut event = NetworkConnectEvent::default();
        event.header.kind = EventKind::NetworkConnect.as_u16();
        event.header.version = EVENT_SCHEMA_VERSION;
        event.header.size = NetworkConnectEvent::SIZE;
        event.header.timestamp_ns = 6000;
        event.header.pid = pid;
        event.header.tid = tid;
        event.header.uid = 1000;
        event.header.gid = 1000;
        event.comm[..comm.len()].copy_from_slice(comm.as_bytes());
        event.family = NetworkFamily::Ipv4 as u16;
        event.socket_fd = 3;
        event.port = 4444;
        event.ipv4_addr = u32::from_be_bytes([127, 0, 0, 1]);
        event
    }

    #[test]
    fn exec_normalizes_to_process_start() {
        let mut table = ProcessTable::new();
        let event = make_exec_event(42, 42, 0, "/bin/sh", "sh");
        let normalized = normalize_exec(&event, &mut table);

        match normalized {
            NormalizedEvent::ProcessStart(start) => {
                assert_eq!(start.pid, 42);
                assert_eq!(start.ppid, 0);
                assert_eq!(start.comm, "sh");
                assert_eq!(start.exe_path, "/bin/sh");
                assert!(start.source.is_none());
            }
            other => panic!("expected ProcessStart, got {:?}", other),
        }
    }

    #[test]
    fn file_filter_matches_watch_and_exclude_rules() {
        let config = file_config();

        assert!(passes_file_filter("/etc/passwd", &config));
        assert!(passes_file_filter("/tmp/demo.service", &config));
        assert!(!passes_file_filter("/tmp/fooservice", &config));
        assert!(!passes_file_filter("/var/tmp/demo.txt", &config));
        assert!(!passes_file_filter("/etc/ignore/secret", &config));
    }

    #[test]
    fn file_open_normalization_applies_filter_and_detection() {
        let mut table = ProcessTable::new();
        table.update_from_exec(&make_exec_event(
            42,
            42,
            7,
            "/usr/bin/systemctl",
            "systemctl",
        ));
        let rules = vec![PersistenceRule {
            name: "systemd_service_modified".to_string(),
            paths: vec!["/etc/systemd/system/".to_string()],
            patterns: vec!["*.service".to_string()],
            operations: vec!["file_open".to_string()],
        }];

        let event = make_file_open_event("/etc/systemd/system/demo.service");
        let normalized = normalize_file_open(&event, &mut table, Some(&file_config()), &rules)
            .expect("matching file open should be emitted");

        match normalized {
            NormalizedEvent::FileOpen(file) => {
                assert_eq!(file.ppid, 7);
                assert_eq!(file.comm, "systemctl");
                assert!(file.alert);
                assert_eq!(
                    file.detection_type,
                    Some("systemd_service_modified".to_string())
                );
            }
            other => panic!("expected FileOpen, got {:?}", other),
        }

        let ignored = make_file_open_event("/var/tmp/demo.txt");
        assert!(normalize_file_open(&ignored, &mut table, Some(&file_config()), &rules).is_none());
    }

    #[test]
    fn network_connect_normalizes_with_enriched_process() {
        let mut table = ProcessTable::new();
        table.update_from_exec(&make_exec_event(42, 42, 7, "/usr/bin/curl", "curl"));
        let event = make_network_connect_event(42, 42, "rawcurl");

        let normalized = normalize_network_connect(&event, &mut table)
            .expect("network connect should be emitted");

        match normalized {
            NormalizedEvent::NetworkConnect(net) => {
                assert_eq!(net.ppid, 7);
                assert_eq!(net.comm, "curl");
                assert_eq!(net.exe_path, "/usr/bin/curl");
                assert_eq!(net.family, "ipv4");
                assert_eq!(net.remote_addr, "127.0.0.1");
                assert_eq!(net.remote_port, 4444);
                assert!(!net.alert);
            }
            other => panic!("expected NetworkConnect, got {:?}", other),
        }
    }

    #[test]
    fn network_connect_uses_raw_comm_when_process_unknown() {
        let mut table = ProcessTable::new();
        let event = make_network_connect_event(999, 999, "nc");

        let normalized = normalize_network_connect(&event, &mut table)
            .expect("network connect should be emitted");

        match normalized {
            NormalizedEvent::NetworkConnect(net) => {
                assert_eq!(net.ppid, 0);
                assert_eq!(net.comm, "nc");
                assert_eq!(net.exe_path, "");
            }
            other => panic!("expected NetworkConnect, got {:?}", other),
        }
    }

    #[test]
    fn exec_preserves_ppid_from_prior_fork() {
        let mut table = ProcessTable::new();
        let fork = make_fork_event(1, 42, 42, "bash", "sh");
        table.insert_from_fork(&fork);

        let exec = make_exec_event(42, 42, 0, "/bin/sh", "sh");
        let normalized = normalize_exec(&exec, &mut table);

        match normalized {
            NormalizedEvent::ProcessStart(start) => {
                assert_eq!(start.ppid, 1);
            }
            other => panic!("expected ProcessStart, got {:?}", other),
        }
    }

    #[test]
    fn exec_includes_pending_source() {
        let mut table = ProcessTable::new();
        table.update_from_exec(&make_exec_event(42, 42, 0, "/bin/sh", "sh"));
        normalize_exec_syscall(
            &make_exec_syscall_event(42, 42, ExecSource::Execveat),
            &mut table,
        );

        let exec = make_exec_event(42, 42, 0, "/bin/bash", "bash");
        let normalized = normalize_exec(&exec, &mut table);

        match normalized {
            NormalizedEvent::ProcessStart(start) => {
                assert_eq!(start.source, Some("execveat".to_string()));
            }
            other => panic!("expected ProcessStart, got {:?}", other),
        }
    }

    #[test]
    fn fork_normalizes_to_relationship() {
        let mut table = ProcessTable::new();
        let fork = make_fork_event(1, 100, 100, "bash", "cat");
        let normalized = normalize_fork(&fork, &mut table);

        match normalized {
            NormalizedEvent::ProcessRelationship(rel) => {
                assert_eq!(rel.parent_pid, 1);
                assert_eq!(rel.parent_comm, "bash");
                assert_eq!(rel.child_pid, 100);
                assert_eq!(rel.child_tid, 100);
                assert_eq!(rel.child_comm, "cat");
            }
            other => panic!("expected ProcessRelationship, got {:?}", other),
        }
    }

    #[test]
    fn exit_normalizes_with_enriched_fields_when_known() {
        let mut table = ProcessTable::new();
        table.update_from_exec(&make_exec_event(42, 42, 0, "/bin/sh", "sh"));

        let exit = make_exit_event(42, 42, "sh");
        let normalized = normalize_exit(&exit, &mut table);

        match normalized {
            NormalizedEvent::ProcessExit(ex) => {
                assert_eq!(ex.pid, 42);
                assert_eq!(ex.comm, "sh");
                assert!(!ex.group_dead);
            }
            other => panic!("expected ProcessExit, got {:?}", other),
        }
    }

    #[test]
    fn exit_normalizes_with_raw_fields_when_unknown() {
        let mut table = ProcessTable::new();
        let exit = make_exit_event(999, 999, "unknown");
        let normalized = normalize_exit(&exit, &mut table);

        match normalized {
            NormalizedEvent::ProcessExit(ex) => {
                assert_eq!(ex.pid, 999);
                assert_eq!(ex.comm, "unknown");
            }
            other => panic!("expected ProcessExit, got {:?}", other),
        }
    }

    #[test]
    fn exec_syscall_sets_pending_source_without_emitting_event() {
        let mut table = ProcessTable::new();
        table.update_from_exec(&make_exec_event(42, 42, 0, "/bin/sh", "sh"));

        normalize_exec_syscall(
            &make_exec_syscall_event(42, 42, ExecSource::Execve),
            &mut table,
        );

        assert_eq!(
            table.get(&(42, 42)).unwrap().pending_source,
            Some("execve".to_string())
        );
    }

    #[test]
    fn exec_after_fork_preserves_ppid_and_first_seen() {
        let mut table = ProcessTable::new();
        let fork = make_fork_event(1, 42, 42, "bash", "sh");
        normalize_fork(&fork, &mut table);

        let mut exec = make_exec_event(42, 42, 0, "/bin/sh", "sh");
        exec.header.timestamp_ns = 5000;
        let normalized = normalize_exec(&exec, &mut table);

        match normalized {
            NormalizedEvent::ProcessStart(start) => {
                assert_eq!(start.ppid, 1);
                assert_eq!(start.timestamp_ns, 5000);
            }
            other => panic!("expected ProcessStart, got {:?}", other),
        }
    }

    #[test]
    fn fork_without_parent_context_still_emits_relationship() {
        let mut table = ProcessTable::new();
        let fork = make_fork_event(1, 100, 100, "bash", "cat");
        let normalized = normalize_fork(&fork, &mut table);

        match normalized {
            NormalizedEvent::ProcessRelationship(rel) => {
                assert_eq!(rel.parent_pid, 1);
                assert_eq!(rel.child_pid, 100);
            }
            other => panic!("expected ProcessRelationship, got {:?}", other),
        }
    }
}
