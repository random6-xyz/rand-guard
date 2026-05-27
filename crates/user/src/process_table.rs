use std::collections::HashMap;

use edr_common::{
    ExecSource, ExecSyscallEvent, ProcessExecEvent, ProcessExitEvent, ProcessForkEvent,
};

/// In-memory enrichment record for a single `(pid, tid)` observed by eBPF.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessRecord {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub exit_timestamp: Option<u64>,
    pub exited: bool,
    /// Temporarily stores the raw syscall source (`execve`/`execveat`) so
    /// that the following `sched_process_exec` normalized event can include it.
    pub pending_source: Option<String>,
}

/// Simple userspace process table keyed by `(pid, tid)`.
pub struct ProcessTable {
    records: HashMap<(u32, u32), ProcessRecord>,
    pending_exec_sources: HashMap<(u32, u32), String>,
}

impl ProcessTable {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            pending_exec_sources: HashMap::new(),
        }
    }

    /// Insert or update a record from a `sched_process_exec` event.
    ///
    /// If the `(pid, tid)` is already known (e.g. from a prior fork), the
    /// existing `ppid` and `first_seen` are preserved.  The `pending_source`
    /// field is consumed and cleared.
    pub fn update_from_exec(&mut self, event: &ProcessExecEvent) -> ProcessRecord {
        let key = (event.header.pid, event.header.tid);
        let comm = fixed_string(&event.comm, event.comm.len());
        let filename = fixed_string(&event.filename, event.filename.len());

        let mut record = if let Some(mut existing) = self.records.remove(&key) {
            if existing.pending_source.is_none() {
                existing.pending_source = self.pending_exec_sources.remove(&key);
            }
            ProcessRecord {
                pid: event.header.pid,
                tid: event.header.tid,
                ppid: existing.ppid,
                uid: event.header.uid,
                gid: event.header.gid,
                comm,
                exe_path: filename,
                first_seen: existing.first_seen,
                last_seen: event.header.timestamp_ns,
                exit_timestamp: None,
                exited: false,
                pending_source: existing.pending_source,
            }
        } else {
            let pending_source = self.pending_exec_sources.remove(&key);
            ProcessRecord {
                pid: event.header.pid,
                tid: event.header.tid,
                ppid: event.header.ppid,
                uid: event.header.uid,
                gid: event.header.gid,
                comm,
                exe_path: filename,
                first_seen: event.header.timestamp_ns,
                last_seen: event.header.timestamp_ns,
                exit_timestamp: None,
                exited: false,
                pending_source,
            }
        };

        // Consume pending_source so it does not leak to future events.
        let result = record.clone();
        let _source = record.pending_source.take();
        self.records.insert(key, record);
        result
    }

    /// Insert a child record from a `sched_process_fork` event.
    ///
    /// The child is keyed by `(child_pid, child_tid)` and its `ppid` is set
    /// to `parent_pid`.
    pub fn insert_from_fork(&mut self, event: &ProcessForkEvent) -> ProcessRecord {
        let key = (event.child_pid, event.child_tid);
        let child_comm = fixed_string(&event.child_comm, event.child_comm.len());

        let record = ProcessRecord {
            pid: event.child_pid,
            tid: event.child_tid,
            ppid: event.parent_pid,
            uid: event.header.uid,
            gid: event.header.gid,
            comm: child_comm,
            exe_path: String::new(),
            first_seen: event.header.timestamp_ns,
            last_seen: event.header.timestamp_ns,
            exit_timestamp: None,
            exited: false,
            pending_source: None,
        };

        self.records.insert(key, record.clone());
        record
    }

    /// Mark a process as exited from a `sched_process_exit` event.
    ///
    /// Returns the record if it was known, or `None` for unknown processes.
    pub fn mark_exit(&mut self, event: &ProcessExitEvent) -> Option<ProcessRecord> {
        let key = (event.header.pid, event.header.tid);
        self.pending_exec_sources.remove(&key);
        if let Some(mut record) = self.records.remove(&key) {
            record.last_seen = event.header.timestamp_ns;
            record.exit_timestamp = Some(event.header.timestamp_ns);
            record.exited = true;
            Some(record)
        } else {
            None
        }
    }

    /// Store the raw syscall source (`execve`/`execveat`) on an existing
    /// record so that the next `sched_process_exec` can emit it.
    pub fn set_pending_source(&mut self, event: &ExecSyscallEvent) {
        let key = (event.header.pid, event.header.tid);
        let source = match event.source {
            s if s == ExecSource::Execve as u8 => "execve",
            s if s == ExecSource::Execveat as u8 => "execveat",
            _ => "unknown",
        };

        if let Some(record) = self.records.get_mut(&key) {
            record.pending_source = Some(source.to_string());
        } else {
            self.pending_exec_sources.insert(key, source.to_string());
        }
    }

    #[allow(dead_code)]
    pub fn get(&self, key: &(u32, u32)) -> Option<&ProcessRecord> {
        self.records.get(key)
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn pending_exec_source_count(&self) -> usize {
        self.pending_exec_sources.len()
    }
}

pub(crate) fn fixed_string(bytes: &[u8], max_len: usize) -> String {
    let len = bytes[..max_len]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(max_len);
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use edr_common::{
        EVENT_SCHEMA_VERSION, EventKind, ExecSource, ExecSyscallEvent, ProcessExecEvent,
        ProcessExitEvent, ProcessForkEvent,
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

    #[test]
    fn inserts_exec_record_with_zero_ppid_when_unknown() {
        let mut table = ProcessTable::new();
        let event = make_exec_event(42, 42, 0, "/bin/sh", "sh");
        let record = table.update_from_exec(&event);
        assert_eq!(record.pid, 42);
        assert_eq!(record.ppid, 0);
        assert_eq!(record.exe_path, "/bin/sh");
        assert_eq!(record.comm, "sh");
    }

    #[test]
    fn preserves_ppid_from_existing_fork_record_on_exec() {
        let mut table = ProcessTable::new();
        let fork = make_fork_event(1, 42, 42, "bash", "sh");
        table.insert_from_fork(&fork);

        let exec = make_exec_event(42, 42, 0, "/bin/sh", "sh");
        let record = table.update_from_exec(&exec);
        assert_eq!(record.ppid, 1);
        assert_eq!(record.exe_path, "/bin/sh");
    }

    #[test]
    fn fork_creates_child_record() {
        let mut table = ProcessTable::new();
        let fork = make_fork_event(1, 100, 100, "bash", "cat");
        let record = table.insert_from_fork(&fork);
        assert_eq!(record.pid, 100);
        assert_eq!(record.tid, 100);
        assert_eq!(record.ppid, 1);
        assert_eq!(record.comm, "cat");
        assert!(table.get(&(100, 100)).is_some());
    }

    #[test]
    fn exit_marks_existing_record() {
        let mut table = ProcessTable::new();
        let exec = make_exec_event(42, 42, 0, "/bin/sh", "sh");
        table.update_from_exec(&exec);

        let exit = make_exit_event(42, 42, "sh");
        let record = table.mark_exit(&exit).expect("record should be known");
        assert!(record.exited);
        assert_eq!(record.exit_timestamp, Some(3000));
    }

    #[test]
    fn exit_returns_none_for_unknown_process() {
        let mut table = ProcessTable::new();
        let exit = make_exit_event(999, 999, "unknown");
        assert!(table.mark_exit(&exit).is_none());
    }

    #[test]
    fn pending_source_correlates_to_exec() {
        let mut table = ProcessTable::new();
        let exec = make_exec_event(42, 42, 0, "/bin/sh", "sh");
        table.update_from_exec(&exec);

        let syscall = make_exec_syscall_event(42, 42, ExecSource::Execveat);
        table.set_pending_source(&syscall);

        let exec2 = make_exec_event(42, 42, 0, "/bin/bash", "bash");
        let record = table.update_from_exec(&exec2);
        assert_eq!(record.pending_source, Some("execveat".to_string()));
        // After consumption the stored record should have None
        assert!(table.get(&(42, 42)).unwrap().pending_source.is_none());
    }

    #[test]
    fn pending_source_correlates_when_exec_record_does_not_exist_yet() {
        let mut table = ProcessTable::new();
        let syscall = make_exec_syscall_event(42, 42, ExecSource::Execveat);
        table.set_pending_source(&syscall);

        let exec = make_exec_event(42, 42, 0, "/bin/bash", "bash");
        let record = table.update_from_exec(&exec);

        assert_eq!(record.pending_source, Some("execveat".to_string()));
        assert!(table.get(&(42, 42)).unwrap().pending_source.is_none());
    }

    #[test]
    fn exec_preserves_first_seen_from_fork() {
        let mut table = ProcessTable::new();
        let fork = make_fork_event(1, 42, 42, "bash", "sh");
        table.insert_from_fork(&fork);

        let mut exec = make_exec_event(42, 42, 0, "/bin/sh", "sh");
        exec.header.timestamp_ns = 5000;
        let record = table.update_from_exec(&exec);
        assert_eq!(record.first_seen, 2000); // from fork
        assert_eq!(record.last_seen, 5000);
    }

    #[test]
    fn multiple_children_from_same_parent() {
        let mut table = ProcessTable::new();
        let fork1 = make_fork_event(1, 10, 10, "bash", "sh");
        let fork2 = make_fork_event(1, 11, 11, "bash", "cat");
        table.insert_from_fork(&fork1);
        table.insert_from_fork(&fork2);

        assert_eq!(table.get(&(10, 10)).unwrap().comm, "sh");
        assert_eq!(table.get(&(11, 11)).unwrap().comm, "cat");
    }

    #[test]
    fn full_lifecycle_fork_exec_exit() {
        let mut table = ProcessTable::new();
        let fork = make_fork_event(1, 42, 42, "bash", "sh");
        table.insert_from_fork(&fork);

        let exec = make_exec_event(42, 42, 0, "/bin/sh", "sh");
        table.update_from_exec(&exec);

        let exit = make_exit_event(42, 42, "sh");
        let record = table.mark_exit(&exit).expect("record should exist");
        assert!(record.exited);
        assert_eq!(record.exe_path, "/bin/sh");
        assert_eq!(record.ppid, 1);
    }
}
