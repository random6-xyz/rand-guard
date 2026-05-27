mod alert;
mod dispatcher;
mod file;
mod health;
mod network;
mod process;
mod writer;

#[allow(unused_imports)]
pub use alert::format_alert_json;
#[allow(unused_imports)]
pub use dispatcher::format_normalized_event_json;
#[allow(unused_imports)]
pub use file::{
    format_file_open_json, format_file_openat2_json, format_file_pwrite64_json,
    format_file_rename_json, format_file_renameat_json, format_file_renameat2_json,
    format_file_unlink_json, format_file_unlinkat_json, format_file_write_json,
    format_file_writev_json,
};
#[allow(unused_imports)]
pub use health::{HealthRecord, format_health_json, read_rss_kb};
#[allow(unused_imports)]
pub use network::{
    format_network_bind_json, format_network_connect_json, format_network_listen_json,
};
#[allow(unused_imports)]
pub use process::{
    format_process_exit_json, format_process_relationship_json, format_process_start_json,
};
pub use writer::JsonOutput;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::{
        FileOpen, FileOpenAt2, FilePWrite64, FileRename, FileRenameAt, FileRenameAt2, FileUnlink,
        FileUnlinkAt, FileWrite, FileWriteV, NetworkBind, NetworkConnect, NetworkListen,
        NormalizedEvent, ProcessExit, ProcessRelationship, ProcessStart,
    };
    use crate::rules::Alert;

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

    #[test]
    fn formats_file_events_as_json() {
        let cases = vec![
            (
                NormalizedEvent::FileOpen(FileOpen {
                    pid: 10,
                    tid: 11,
                    ppid: 1,
                    uid: 1000,
                    gid: 1000,
                    comm: "touch".to_string(),
                    exe_path: "/usr/bin/touch".to_string(),
                    filename: "/etc/demo.service".to_string(),
                    flags: 64,
                    filename_truncated: false,
                    alert: true,
                    detection_type: Some("systemd_service_modified".to_string()),
                    timestamp_ns: 100,
                }),
                "file_open",
                "filename",
                "/etc/demo.service",
            ),
            (
                NormalizedEvent::FileOpenAt2(FileOpenAt2 {
                    pid: 10,
                    tid: 11,
                    ppid: 1,
                    uid: 1000,
                    gid: 1000,
                    comm: "touch".to_string(),
                    exe_path: "/usr/bin/touch".to_string(),
                    filename: "/etc/demo.service".to_string(),
                    flags: 64,
                    filename_truncated: false,
                    alert: false,
                    detection_type: None,
                    timestamp_ns: 101,
                }),
                "file_openat2",
                "filename",
                "/etc/demo.service",
            ),
            (
                NormalizedEvent::FileWrite(FileWrite {
                    pid: 10,
                    tid: 11,
                    ppid: 1,
                    uid: 1000,
                    gid: 1000,
                    comm: "tee".to_string(),
                    exe_path: "/usr/bin/tee".to_string(),
                    fd: 3,
                    count: 12,
                    resolved_path: "/etc/crontab".to_string(),
                    alert: true,
                    detection_type: Some("cron_modified".to_string()),
                    timestamp_ns: 102,
                }),
                "file_write",
                "resolved_path",
                "/etc/crontab",
            ),
            (
                NormalizedEvent::FileWriteV(FileWriteV {
                    pid: 10,
                    tid: 11,
                    ppid: 1,
                    uid: 1000,
                    gid: 1000,
                    comm: "tee".to_string(),
                    exe_path: "/usr/bin/tee".to_string(),
                    fd: 3,
                    iovcnt: 2,
                    resolved_path: "/etc/crontab".to_string(),
                    alert: false,
                    detection_type: None,
                    timestamp_ns: 103,
                }),
                "file_writev",
                "resolved_path",
                "/etc/crontab",
            ),
            (
                NormalizedEvent::FilePWrite64(FilePWrite64 {
                    pid: 10,
                    tid: 11,
                    ppid: 1,
                    uid: 1000,
                    gid: 1000,
                    comm: "tee".to_string(),
                    exe_path: "/usr/bin/tee".to_string(),
                    fd: 3,
                    count: 12,
                    pos: 4,
                    resolved_path: "/etc/crontab".to_string(),
                    alert: false,
                    detection_type: None,
                    timestamp_ns: 104,
                }),
                "file_pwrite64",
                "resolved_path",
                "/etc/crontab",
            ),
            (
                NormalizedEvent::FileRename(FileRename {
                    pid: 10,
                    tid: 11,
                    ppid: 1,
                    uid: 1000,
                    gid: 1000,
                    comm: "mv".to_string(),
                    exe_path: "/usr/bin/mv".to_string(),
                    old_filename: "/tmp/a".to_string(),
                    new_filename: "/etc/a".to_string(),
                    filename_truncated: false,
                    alert: false,
                    detection_type: None,
                    timestamp_ns: 105,
                }),
                "file_rename",
                "new_filename",
                "/etc/a",
            ),
            (
                NormalizedEvent::FileRenameAt(FileRenameAt {
                    pid: 10,
                    tid: 11,
                    ppid: 1,
                    uid: 1000,
                    gid: 1000,
                    comm: "mv".to_string(),
                    exe_path: "/usr/bin/mv".to_string(),
                    old_filename: "/tmp/a".to_string(),
                    new_filename: "/etc/a".to_string(),
                    filename_truncated: false,
                    alert: false,
                    detection_type: None,
                    timestamp_ns: 106,
                }),
                "file_renameat",
                "new_filename",
                "/etc/a",
            ),
            (
                NormalizedEvent::FileRenameAt2(FileRenameAt2 {
                    pid: 10,
                    tid: 11,
                    ppid: 1,
                    uid: 1000,
                    gid: 1000,
                    comm: "mv".to_string(),
                    exe_path: "/usr/bin/mv".to_string(),
                    old_filename: "/tmp/a".to_string(),
                    new_filename: "/etc/a".to_string(),
                    flags: 1,
                    filename_truncated: false,
                    alert: false,
                    detection_type: None,
                    timestamp_ns: 107,
                }),
                "file_renameat2",
                "new_filename",
                "/etc/a",
            ),
            (
                NormalizedEvent::FileUnlink(FileUnlink {
                    pid: 10,
                    tid: 11,
                    ppid: 1,
                    uid: 1000,
                    gid: 1000,
                    comm: "rm".to_string(),
                    exe_path: "/usr/bin/rm".to_string(),
                    filename: "/etc/a".to_string(),
                    filename_truncated: false,
                    alert: false,
                    detection_type: None,
                    timestamp_ns: 108,
                }),
                "file_unlink",
                "filename",
                "/etc/a",
            ),
            (
                NormalizedEvent::FileUnlinkAt(FileUnlinkAt {
                    pid: 10,
                    tid: 11,
                    ppid: 1,
                    uid: 1000,
                    gid: 1000,
                    comm: "rm".to_string(),
                    exe_path: "/usr/bin/rm".to_string(),
                    filename: "/etc/a".to_string(),
                    flags: 0,
                    filename_truncated: false,
                    alert: false,
                    detection_type: None,
                    timestamp_ns: 109,
                }),
                "file_unlinkat",
                "filename",
                "/etc/a",
            ),
        ];

        for (event, event_type, field, expected) in cases {
            let value: serde_json::Value =
                serde_json::from_str(&format_normalized_event_json(&event))
                    .expect("file event output should be valid JSON");

            assert_eq!(value["event_type"], event_type);
            assert_eq!(value[field], expected);
        }
    }

    #[test]
    fn formats_network_events_as_json() {
        let connect = NormalizedEvent::NetworkConnect(NetworkConnect {
            pid: 10,
            tid: 11,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "nc".to_string(),
            exe_path: "/usr/bin/nc".to_string(),
            family: "ipv4".to_string(),
            socket_fd: 3,
            remote_addr: "127.0.0.1".to_string(),
            remote_port: 4444,
            alert: true,
            detection_type: Some("suspicious_outbound_port".to_string()),
            timestamp_ns: 200,
        });
        let value: serde_json::Value =
            serde_json::from_str(&format_normalized_event_json(&connect))
                .expect("network connect output should be valid JSON");
        assert_eq!(value["event_type"], "network_connect");
        assert_eq!(value["remote_addr"], "127.0.0.1");
        assert_eq!(value["remote_port"], 4444);
        assert_eq!(value["alert"], true);

        let bind = NormalizedEvent::NetworkBind(NetworkBind {
            pid: 10,
            tid: 11,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "nc".to_string(),
            exe_path: "/usr/bin/nc".to_string(),
            family: "ipv4".to_string(),
            socket_fd: 3,
            local_addr: "0.0.0.0".to_string(),
            local_port: 4444,
            alert: false,
            detection_type: None,
            timestamp_ns: 201,
        });
        let value: serde_json::Value = serde_json::from_str(&format_normalized_event_json(&bind))
            .expect("network bind output should be valid JSON");
        assert_eq!(value["event_type"], "network_bind");
        assert_eq!(value["local_port"], 4444);

        let listen = NormalizedEvent::NetworkListen(NetworkListen {
            pid: 10,
            tid: 11,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "nc".to_string(),
            exe_path: "/usr/bin/nc".to_string(),
            family: "unknown".to_string(),
            socket_fd: 3,
            local_addr: "".to_string(),
            local_port: 0,
            backlog: 128,
            alert: false,
            detection_type: None,
            timestamp_ns: 202,
        });
        let value: serde_json::Value = serde_json::from_str(&format_normalized_event_json(&listen))
            .expect("network listen output should be valid JSON");
        assert_eq!(value["event_type"], "network_listen");
        assert_eq!(value["backlog"], 128);
    }

    #[test]
    fn formats_alert_as_stable_json() {
        let alert = Alert {
            timestamp_ns: 123,
            rule_id: "FILE-001".to_string(),
            rule_name: "Sensitive file touched".to_string(),
            rule_type: "file".to_string(),
            severity: "high".to_string(),
            action: "alert".to_string(),
            source_event_type: "file_write".to_string(),
            pid: Some(100),
            tid: Some(100),
            ppid: Some(1),
            uid: Some(0),
            gid: Some(0),
            comm: Some("bash".to_string()),
            exe_path: Some("/usr/bin/bash".to_string()),
            process_name: Some("bash".to_string()),
            parent_name: None,
            path: Some("/etc/shadow".to_string()),
            operation: Some("file_write".to_string()),
            direction: None,
            port: None,
            addr: None,
            family: None,
        };

        let value: serde_json::Value = serde_json::from_str(&format_alert_json(&alert))
            .expect("alert output should be valid JSON");

        assert_eq!(value["event_type"], "alert");
        assert_eq!(value["rule_id"], "FILE-001");
        assert_eq!(value["source_event_type"], "file_write");
        assert_eq!(value["path"], "/etc/shadow");
        assert_eq!(value["operation"], "file_write");
        assert!(value["direction"].is_null());
    }

    #[test]
    fn writes_alert_line_to_writer() {
        let alert = Alert {
            timestamp_ns: 123,
            rule_id: "NET-001".to_string(),
            rule_name: "Suspicious outbound port".to_string(),
            rule_type: "network".to_string(),
            severity: "medium".to_string(),
            action: "alert".to_string(),
            source_event_type: "network_connect".to_string(),
            pid: Some(100),
            tid: Some(100),
            ppid: Some(1),
            uid: Some(1000),
            gid: Some(1000),
            comm: Some("nc".to_string()),
            exe_path: Some("/usr/bin/nc".to_string()),
            process_name: Some("nc".to_string()),
            parent_name: None,
            path: None,
            operation: None,
            direction: Some("outbound".to_string()),
            port: Some(4444),
            addr: Some("127.0.0.1".to_string()),
            family: Some("ipv4".to_string()),
        };
        let mut output = JsonOutput::new(Vec::new());

        output
            .write_alert(&alert)
            .expect("alert write should succeed");

        let line = String::from_utf8(output.into_inner()).expect("JSON output should be UTF-8");
        assert!(line.ends_with('\n'));
        let value: serde_json::Value =
            serde_json::from_str(line.trim_end()).expect("written alert should be valid JSON");
        assert_eq!(value["event_type"], "alert");
        assert_eq!(value["port"], 4444);
    }

    #[test]
    fn formats_health_record_as_json() {
        let record = HealthRecord {
            raw_events_read: 100,
            normalized_events_output: 80,
            alerts_output: 3,
            userspace_filtered: 15,
            userspace_rate_limited: 2,
            invalid_schema: 0,
            process_table_size: 42,
            pending_exec_source_size: 1,
            uptime_secs: 60,
            rss_kb: Some(8192),
        };

        let value: serde_json::Value = serde_json::from_str(&format_health_json(&record))
            .expect("health record output should be valid JSON");

        assert_eq!(value["event_type"], "health");
        assert_eq!(value["raw_events_read"], 100);
        assert_eq!(value["normalized_events_output"], 80);
        assert_eq!(value["alerts_output"], 3);
        assert_eq!(value["userspace_filtered"], 15);
        assert_eq!(value["userspace_rate_limited"], 2);
        assert_eq!(value["invalid_schema"], 0);
        assert_eq!(value["process_table_size"], 42);
        assert_eq!(value["pending_exec_source_size"], 1);
        assert_eq!(value["uptime_secs"], 60);
        assert_eq!(value["rss_kb"], 8192);
    }

    #[test]
    fn formats_health_record_with_null_rss() {
        let record = HealthRecord {
            raw_events_read: 0,
            normalized_events_output: 0,
            alerts_output: 0,
            userspace_filtered: 0,
            userspace_rate_limited: 0,
            invalid_schema: 0,
            process_table_size: 0,
            pending_exec_source_size: 0,
            uptime_secs: 0,
            rss_kb: None,
        };

        let value: serde_json::Value = serde_json::from_str(&format_health_json(&record))
            .expect("health record with null rss should be valid JSON");

        assert!(value["rss_kb"].is_null());
    }

    #[test]
    fn writes_health_record_line_to_writer() {
        let record = HealthRecord {
            raw_events_read: 0,
            normalized_events_output: 0,
            alerts_output: 0,
            userspace_filtered: 0,
            userspace_rate_limited: 0,
            invalid_schema: 0,
            process_table_size: 0,
            pending_exec_source_size: 0,
            uptime_secs: 0,
            rss_kb: None,
        };
        let mut output = JsonOutput::new(Vec::new());

        output
            .write_health(&record)
            .expect("health write should succeed");

        let line = String::from_utf8(output.into_inner()).expect("JSON output should be UTF-8");
        assert!(line.ends_with('\n'));

        let value: serde_json::Value = serde_json::from_str(line.trim_end())
            .expect("written health record should be valid JSON");
        assert_eq!(value["event_type"], "health");
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
