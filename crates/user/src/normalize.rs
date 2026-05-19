use edr_common::{
    EVENT_FLAG_FILENAME_TRUNCATED, ExecSyscallEvent, ProcessExecEvent, ProcessExitEvent,
    ProcessForkEvent,
};

use crate::process_table::{ProcessTable, fixed_string};

/// Normalized userspace event emitted after raw ring-buffer records have
/// been decoded and enriched by the process table.
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum NormalizedEvent {
    ProcessStart(ProcessStart),
    ProcessExit(ProcessExit),
    ProcessRelationship(ProcessRelationship),
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
