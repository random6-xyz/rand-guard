use edr_common::{
    EVENT_FLAG_FILENAME_TRUNCATED, ProcessExecEvent, ProcessExitEvent, ProcessForkEvent,
};

use crate::normalize::types::{NormalizedEvent, ProcessExit, ProcessRelationship, ProcessStart};
use crate::process_table::ProcessTable;

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

pub fn normalize_fork(event: &ProcessForkEvent, table: &mut ProcessTable) -> NormalizedEvent {
    let record = table.insert_from_fork(event);
    let parent_comm =
        crate::process_table::fixed_string(&event.parent_comm, event.parent_comm.len());

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

pub fn normalize_exit(event: &ProcessExitEvent, table: &mut ProcessTable) -> NormalizedEvent {
    let comm = crate::process_table::fixed_string(&event.comm, event.comm.len());
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

pub fn normalize_exec_syscall(event: &edr_common::ExecSyscallEvent, table: &mut ProcessTable) {
    table.set_pending_source(event);
}
