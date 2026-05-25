use edr_common::{
    EVENT_FLAG_FILENAME_TRUNCATED, FileOpenAt2Event, FileOpenEvent, FilePWrite64Event,
    FileRenameAt2Event, FileRenameAtEvent, FileRenameEvent, FileUnlinkAtEvent, FileUnlinkEvent,
    FileWriteEvent, FileWriteVEvent,
};

use crate::config::FileConfig;
use crate::normalize::helpers::{detect_for_path, detect_for_paths, enrich_from_table};
use crate::normalize::types::*;
use crate::process_table::{ProcessTable, fixed_string};

fn resolve_fd_path(pid: u32, fd: u64) -> String {
    let path = format!("/proc/{pid}/fd/{fd}");
    std::fs::read_link(&path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

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

pub fn normalize_file_open(
    event: &FileOpenEvent,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[crate::config::PersistenceRule],
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

pub fn normalize_file_openat2(
    event: &FileOpenAt2Event,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[crate::config::PersistenceRule],
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

pub fn normalize_file_write(
    event: &FileWriteEvent,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[crate::config::PersistenceRule],
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

pub fn normalize_file_writev(
    event: &FileWriteVEvent,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[crate::config::PersistenceRule],
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

pub fn normalize_file_pwrite64(
    event: &FilePWrite64Event,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[crate::config::PersistenceRule],
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

pub fn normalize_file_rename(
    event: &FileRenameEvent,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[crate::config::PersistenceRule],
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

pub fn normalize_file_renameat(
    event: &FileRenameAtEvent,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[crate::config::PersistenceRule],
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

pub fn normalize_file_renameat2(
    event: &FileRenameAt2Event,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[crate::config::PersistenceRule],
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

pub fn normalize_file_unlink(
    event: &FileUnlinkEvent,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[crate::config::PersistenceRule],
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

pub fn normalize_file_unlinkat(
    event: &FileUnlinkAtEvent,
    table: &mut ProcessTable,
    file_config: Option<&FileConfig>,
    detections: &[crate::config::PersistenceRule],
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
