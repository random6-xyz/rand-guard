use std::io::{self, Write};

use anyhow::Context;

use crate::normalize::{
    FileOpen, FileOpenAt2, FilePWrite64, FileRename, FileRenameAt, FileRenameAt2, FileUnlink,
    FileUnlinkAt, FileWrite, FileWriteV, NormalizedEvent, ProcessExit, ProcessRelationship,
    ProcessStart,
};

pub struct JsonOutput<W> {
    writer: W,
}

impl JsonOutput<io::Stdout> {
    pub fn stdout() -> Self {
        Self::new(io::stdout())
    }
}

impl<W: Write> JsonOutput<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    pub fn write_normalized(&mut self, event: &NormalizedEvent) -> anyhow::Result<()> {
        writeln!(self.writer, "{}", format_normalized_event_json(event))
            .context("failed to write normalized event JSON")
    }

    #[cfg(test)]
    fn into_inner(self) -> W {
        self.writer
    }
}

pub fn format_normalized_event_json(event: &NormalizedEvent) -> String {
    match event {
        NormalizedEvent::ProcessStart(start) => format_process_start_json(start),
        NormalizedEvent::ProcessExit(exit) => format_process_exit_json(exit),
        NormalizedEvent::ProcessRelationship(rel) => format_process_relationship_json(rel),
        NormalizedEvent::FileOpen(file) => format_file_open_json(file),
        NormalizedEvent::FileOpenAt2(file) => format_file_openat2_json(file),
        NormalizedEvent::FileWrite(file) => format_file_write_json(file),
        NormalizedEvent::FileWriteV(file) => format_file_writev_json(file),
        NormalizedEvent::FilePWrite64(file) => format_file_pwrite64_json(file),
        NormalizedEvent::FileRename(file) => format_file_rename_json(file),
        NormalizedEvent::FileRenameAt(file) => format_file_renameat_json(file),
        NormalizedEvent::FileRenameAt2(file) => format_file_renameat2_json(file),
        NormalizedEvent::FileUnlink(file) => format_file_unlink_json(file),
        NormalizedEvent::FileUnlinkAt(file) => format_file_unlinkat_json(file),
    }
}

fn format_process_start_json(start: &ProcessStart) -> String {
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

fn format_process_exit_json(exit: &ProcessExit) -> String {
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

fn format_process_relationship_json(rel: &ProcessRelationship) -> String {
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

fn format_file_open_json(file: &FileOpen) -> String {
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
    })
    .to_string()
}

fn format_file_openat2_json(file: &FileOpenAt2) -> String {
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
    })
    .to_string()
}

fn format_file_write_json(file: &FileWrite) -> String {
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
    })
    .to_string()
}

fn format_file_writev_json(file: &FileWriteV) -> String {
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
    })
    .to_string()
}

fn format_file_pwrite64_json(file: &FilePWrite64) -> String {
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
    })
    .to_string()
}

fn format_file_rename_json(file: &FileRename) -> String {
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
    })
    .to_string()
}

fn format_file_renameat_json(file: &FileRenameAt) -> String {
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
    })
    .to_string()
}

fn format_file_renameat2_json(file: &FileRenameAt2) -> String {
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
    })
    .to_string()
}

fn format_file_unlink_json(file: &FileUnlink) -> String {
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
    })
    .to_string()
}

fn format_file_unlinkat_json(file: &FileUnlinkAt) -> String {
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
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_process_start_as_json() {
        let event = sample_process_start();

        let value: serde_json::Value = serde_json::from_str(&format_normalized_event_json(
            &NormalizedEvent::ProcessStart(event.clone()),
        ))
        .expect("process start event output should be valid JSON");

        assert_eq!(value["event_type"], "process_start");
        assert_eq!(value["timestamp_ns"], 123);
        assert_eq!(value["pid"], 100);
        assert_eq!(value["tid"], 101);
        assert_eq!(value["ppid"], 1);
        assert_eq!(value["uid"], 1000);
        assert_eq!(value["gid"], 1000);
        assert_eq!(value["comm"], "bash");
        assert_eq!(value["exe_path"], "/usr/bin/bash");
        assert_eq!(value["source"], "execve");
        assert_eq!(value["filename_truncated"], true);
    }

    #[test]
    fn writes_json_line_to_writer() {
        let event = sample_process_start();
        let mut output = JsonOutput::new(Vec::new());

        output
            .write_normalized(&NormalizedEvent::ProcessStart(event))
            .expect("JSON event write should succeed");

        let line = String::from_utf8(output.into_inner()).expect("JSON output should be UTF-8");
        assert!(line.ends_with('\n'));

        let value: serde_json::Value = serde_json::from_str(line.trim_end())
            .expect("written process start event should be valid JSON");
        assert_eq!(value["event_type"], "process_start");
        assert_eq!(value["exe_path"], "/usr/bin/bash");
    }

    #[test]
    fn formats_process_exit_as_json() {
        let event = ProcessExit {
            pid: 42,
            tid: 42,
            comm: "sh".to_string(),
            group_dead: true,
            uid: 1000,
            gid: 1000,
            timestamp_ns: 3000,
        };

        let value: serde_json::Value = serde_json::from_str(&format_normalized_event_json(
            &NormalizedEvent::ProcessExit(event),
        ))
        .expect("process exit event output should be valid JSON");

        assert_eq!(value["event_type"], "process_exit");
        assert_eq!(value["pid"], 42);
        assert_eq!(value["comm"], "sh");
        assert_eq!(value["group_dead"], true);
    }

    #[test]
    fn formats_process_relationship_as_json() {
        let event = ProcessRelationship {
            parent_pid: 1,
            parent_comm: "bash".to_string(),
            child_pid: 100,
            child_tid: 100,
            child_comm: "cat".to_string(),
            uid: 1000,
            gid: 1000,
            timestamp_ns: 2000,
        };

        let value: serde_json::Value = serde_json::from_str(&format_normalized_event_json(
            &NormalizedEvent::ProcessRelationship(event),
        ))
        .expect("process relationship event output should be valid JSON");

        assert_eq!(value["event_type"], "process_relationship");
        assert_eq!(value["parent_pid"], 1);
        assert_eq!(value["parent_comm"], "bash");
        assert_eq!(value["child_pid"], 100);
        assert_eq!(value["child_tid"], 100);
        assert_eq!(value["child_comm"], "cat");
    }

    #[test]
    fn source_field_is_null_when_none() {
        let mut event = sample_process_start();
        event.source = None;

        let value: serde_json::Value = serde_json::from_str(&format_normalized_event_json(
            &NormalizedEvent::ProcessStart(event),
        ))
        .expect("process start event output should be valid JSON");

        assert!(value["source"].is_null());
    }

    #[test]
    fn formats_process_exit_with_group_dead_false() {
        let event = ProcessExit {
            pid: 42,
            tid: 42,
            comm: "sh".to_string(),
            group_dead: false,
            uid: 1000,
            gid: 1000,
            timestamp_ns: 3000,
        };

        let value: serde_json::Value = serde_json::from_str(&format_normalized_event_json(
            &NormalizedEvent::ProcessExit(event),
        ))
        .expect("process exit event output should be valid JSON");

        assert_eq!(value["event_type"], "process_exit");
        assert_eq!(value["group_dead"], false);
    }

    fn sample_process_start() -> ProcessStart {
        ProcessStart {
            pid: 100,
            tid: 101,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "bash".to_string(),
            exe_path: "/usr/bin/bash".to_string(),
            source: Some("execve".to_string()),
            timestamp_ns: 123,
            filename_truncated: true,
        }
    }
}
