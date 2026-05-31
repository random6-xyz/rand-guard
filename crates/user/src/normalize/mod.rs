mod file;
mod helpers;
mod network;
mod process;
mod types;

pub use file::{
    normalize_file_open, normalize_file_openat2, normalize_file_pwrite64, normalize_file_rename,
    normalize_file_renameat, normalize_file_renameat2, normalize_file_unlink,
    normalize_file_unlinkat, normalize_file_write, normalize_file_writev,
};
pub use network::{normalize_network_bind, normalize_network_connect, normalize_network_listen};
pub use process::{normalize_exec, normalize_exec_syscall, normalize_exit, normalize_fork};
pub use types::*;

#[cfg(test)]
mod tests {
    use edr_common::{
        EVENT_SCHEMA_VERSION, EventKind, ExecSource, ExecSyscallEvent, FileOpenEvent,
        NetworkConnectEvent, NetworkFamily, ProcessExecEvent, ProcessExitEvent, ProcessForkEvent,
    };

    use super::*;
    use crate::config::{FileConfig, NetworkDetectionRule, NetworkDirection, PersistenceRule};
    use crate::process_table::ProcessTable;

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

        let normalized = normalize_network_connect(&event, &mut table, &[])
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

        let normalized = normalize_network_connect(&event, &mut table, &[])
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
    fn network_connect_applies_suspicious_port_detection() {
        let mut table = ProcessTable::new();
        let event = make_network_connect_event(999, 999, "nc");
        let rules = vec![NetworkDetectionRule {
            name: "suspicious_outbound_port".to_string(),
            directions: vec![NetworkDirection::Outbound],
            ports: vec![4444],
            process_names: vec![],
        }];

        let normalized = normalize_network_connect(&event, &mut table, &rules)
            .expect("network connect should be emitted");

        match normalized {
            NormalizedEvent::NetworkConnect(net) => {
                assert!(net.alert);
                assert_eq!(
                    net.detection_type,
                    Some("suspicious_outbound_port".to_string())
                );
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
