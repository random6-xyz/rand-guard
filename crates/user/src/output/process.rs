use crate::normalize::{ProcessExit, ProcessRelationship, ProcessStart};

pub fn format_process_start_json(start: &ProcessStart) -> String {
    serde_json::json!({
        "event_type": "process_start",
        "timestamp_ns": start.timestamp_ns,
        "pid": start.pid,
        "tid": start.tid,
        "ppid": start.ppid,
        "uid": start.uid,
        "gid": start.gid,
        "comm": start.comm,
        "exe_path": start.exe_path,
        "source": start.source,
        "filename_truncated": start.filename_truncated,
    })
    .to_string()
}

pub fn format_process_exit_json(exit: &ProcessExit) -> String {
    serde_json::json!({
        "event_type": "process_exit",
        "timestamp_ns": exit.timestamp_ns,
        "pid": exit.pid,
        "tid": exit.tid,
        "comm": exit.comm,
        "group_dead": exit.group_dead,
        "uid": exit.uid,
        "gid": exit.gid,
    })
    .to_string()
}

pub fn format_process_relationship_json(rel: &ProcessRelationship) -> String {
    serde_json::json!({
        "event_type": "process_relationship",
        "timestamp_ns": rel.timestamp_ns,
        "parent_pid": rel.parent_pid,
        "parent_comm": rel.parent_comm,
        "child_pid": rel.child_pid,
        "child_tid": rel.child_tid,
        "child_comm": rel.child_comm,
        "uid": rel.uid,
        "gid": rel.gid,
    })
    .to_string()
}
