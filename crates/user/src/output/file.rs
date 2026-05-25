use crate::normalize::{
    FileOpen, FileOpenAt2, FilePWrite64, FileRename, FileRenameAt, FileRenameAt2, FileUnlink,
    FileUnlinkAt, FileWrite, FileWriteV,
};

pub fn format_file_open_json(file: &FileOpen) -> String {
    serde_json::json!({
        "event_type": "file_open",
        "timestamp_ns": file.timestamp_ns,
        "pid": file.pid,
        "tid": file.tid,
        "ppid": file.ppid,
        "uid": file.uid,
        "gid": file.gid,
        "comm": file.comm,
        "exe_path": file.exe_path,
        "filename": file.filename,
        "flags": file.flags,
        "filename_truncated": file.filename_truncated,
        "alert": file.alert,
        "detection_type": file.detection_type,
    })
    .to_string()
}

pub fn format_file_openat2_json(file: &FileOpenAt2) -> String {
    serde_json::json!({
        "event_type": "file_openat2",
        "timestamp_ns": file.timestamp_ns,
        "pid": file.pid,
        "tid": file.tid,
        "ppid": file.ppid,
        "uid": file.uid,
        "gid": file.gid,
        "comm": file.comm,
        "exe_path": file.exe_path,
        "filename": file.filename,
        "flags": file.flags,
        "filename_truncated": file.filename_truncated,
        "alert": file.alert,
        "detection_type": file.detection_type,
    })
    .to_string()
}

pub fn format_file_write_json(file: &FileWrite) -> String {
    serde_json::json!({
        "event_type": "file_write",
        "timestamp_ns": file.timestamp_ns,
        "pid": file.pid,
        "tid": file.tid,
        "ppid": file.ppid,
        "uid": file.uid,
        "gid": file.gid,
        "comm": file.comm,
        "exe_path": file.exe_path,
        "fd": file.fd,
        "count": file.count,
        "resolved_path": file.resolved_path,
        "alert": file.alert,
        "detection_type": file.detection_type,
    })
    .to_string()
}

pub fn format_file_writev_json(file: &FileWriteV) -> String {
    serde_json::json!({
        "event_type": "file_writev",
        "timestamp_ns": file.timestamp_ns,
        "pid": file.pid,
        "tid": file.tid,
        "ppid": file.ppid,
        "uid": file.uid,
        "gid": file.gid,
        "comm": file.comm,
        "exe_path": file.exe_path,
        "fd": file.fd,
        "iovcnt": file.iovcnt,
        "resolved_path": file.resolved_path,
        "alert": file.alert,
        "detection_type": file.detection_type,
    })
    .to_string()
}

pub fn format_file_pwrite64_json(file: &FilePWrite64) -> String {
    serde_json::json!({
        "event_type": "file_pwrite64",
        "timestamp_ns": file.timestamp_ns,
        "pid": file.pid,
        "tid": file.tid,
        "ppid": file.ppid,
        "uid": file.uid,
        "gid": file.gid,
        "comm": file.comm,
        "exe_path": file.exe_path,
        "fd": file.fd,
        "count": file.count,
        "pos": file.pos,
        "resolved_path": file.resolved_path,
        "alert": file.alert,
        "detection_type": file.detection_type,
    })
    .to_string()
}

pub fn format_file_rename_json(file: &FileRename) -> String {
    serde_json::json!({
        "event_type": "file_rename",
        "timestamp_ns": file.timestamp_ns,
        "pid": file.pid,
        "tid": file.tid,
        "ppid": file.ppid,
        "uid": file.uid,
        "gid": file.gid,
        "comm": file.comm,
        "exe_path": file.exe_path,
        "old_filename": file.old_filename,
        "new_filename": file.new_filename,
        "filename_truncated": file.filename_truncated,
        "alert": file.alert,
        "detection_type": file.detection_type,
    })
    .to_string()
}

pub fn format_file_renameat_json(file: &FileRenameAt) -> String {
    serde_json::json!({
        "event_type": "file_renameat",
        "timestamp_ns": file.timestamp_ns,
        "pid": file.pid,
        "tid": file.tid,
        "ppid": file.ppid,
        "uid": file.uid,
        "gid": file.gid,
        "comm": file.comm,
        "exe_path": file.exe_path,
        "old_filename": file.old_filename,
        "new_filename": file.new_filename,
        "filename_truncated": file.filename_truncated,
        "alert": file.alert,
        "detection_type": file.detection_type,
    })
    .to_string()
}

pub fn format_file_renameat2_json(file: &FileRenameAt2) -> String {
    serde_json::json!({
        "event_type": "file_renameat2",
        "timestamp_ns": file.timestamp_ns,
        "pid": file.pid,
        "tid": file.tid,
        "ppid": file.ppid,
        "uid": file.uid,
        "gid": file.gid,
        "comm": file.comm,
        "exe_path": file.exe_path,
        "old_filename": file.old_filename,
        "new_filename": file.new_filename,
        "flags": file.flags,
        "filename_truncated": file.filename_truncated,
        "alert": file.alert,
        "detection_type": file.detection_type,
    })
    .to_string()
}

pub fn format_file_unlink_json(file: &FileUnlink) -> String {
    serde_json::json!({
        "event_type": "file_unlink",
        "timestamp_ns": file.timestamp_ns,
        "pid": file.pid,
        "tid": file.tid,
        "ppid": file.ppid,
        "uid": file.uid,
        "gid": file.gid,
        "comm": file.comm,
        "exe_path": file.exe_path,
        "filename": file.filename,
        "filename_truncated": file.filename_truncated,
        "alert": file.alert,
        "detection_type": file.detection_type,
    })
    .to_string()
}

pub fn format_file_unlinkat_json(file: &FileUnlinkAt) -> String {
    serde_json::json!({
        "event_type": "file_unlinkat",
        "timestamp_ns": file.timestamp_ns,
        "pid": file.pid,
        "tid": file.tid,
        "ppid": file.ppid,
        "uid": file.uid,
        "gid": file.gid,
        "comm": file.comm,
        "exe_path": file.exe_path,
        "filename": file.filename,
        "flags": file.flags,
        "filename_truncated": file.filename_truncated,
        "alert": file.alert,
        "detection_type": file.detection_type,
    })
    .to_string()
}
