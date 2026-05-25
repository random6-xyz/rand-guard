use std::collections::HashMap;

use crate::normalize::{
    FilePWrite64, FileRename, FileRenameAt, FileRenameAt2, FileWrite, FileWriteV, NetworkConnect,
    NormalizedEvent, ProcessStart,
};
use crate::rules::Alert;

const SCENARIO_WINDOW_NS: u64 = 10_000_000_000;
const REVERSE_SHELL_PORTS: &[u16] = &[4444, 1337, 31337, 9001, 5555];
const REVERSE_SHELL_PROCESS_NAMES: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "mksh", "busybox", "nc", "ncat", "socat", "python",
    "python3", "perl", "php", "ruby",
];
const DROP_EXEC_PATH_PREFIXES: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"];

pub struct ScenarioEngine {
    recent_processes: HashMap<(u32, u32), ProcessSnapshot>,
    recent_file_writes: HashMap<String, FileSnapshot>,
}

impl ScenarioEngine {
    pub fn new() -> Self {
        Self {
            recent_processes: HashMap::new(),
            recent_file_writes: HashMap::new(),
        }
    }

    pub fn evaluate(&mut self, event: &NormalizedEvent) -> Vec<Alert> {
        let timestamp_ns = event_timestamp_ns(event);
        self.prune(timestamp_ns);

        match event {
            NormalizedEvent::ProcessStart(start) => {
                let alerts = self.evaluate_drop_execute(start);
                self.recent_processes.remove(&(start.pid, start.tid));
                if is_reverse_shell_process(&start.comm) {
                    self.recent_processes
                        .insert((start.pid, start.tid), ProcessSnapshot::from(start));
                }
                alerts
            }
            NormalizedEvent::ProcessExit(exit) => {
                self.recent_processes.remove(&(exit.pid, exit.tid));
                Vec::new()
            }
            NormalizedEvent::FileWrite(file) => {
                self.record_file_write(FileSnapshot::from_write(file))
            }
            NormalizedEvent::FileWriteV(file) => {
                self.record_file_write(FileSnapshot::from_writev(file))
            }
            NormalizedEvent::FilePWrite64(file) => {
                self.record_file_write(FileSnapshot::from_pwrite64(file))
            }
            NormalizedEvent::FileRename(file) => {
                self.record_file_write(FileSnapshot::from_rename(file))
            }
            NormalizedEvent::FileRenameAt(file) => {
                self.record_file_write(FileSnapshot::from_renameat(file))
            }
            NormalizedEvent::FileRenameAt2(file) => {
                self.record_file_write(FileSnapshot::from_renameat2(file))
            }
            NormalizedEvent::FileUnlink(file) => self.remove_file_write(&file.filename),
            NormalizedEvent::FileUnlinkAt(file) => self.remove_file_write(&file.filename),
            NormalizedEvent::NetworkConnect(connect) => self.evaluate_reverse_shell(connect),
            _ => Vec::new(),
        }
    }

    fn evaluate_reverse_shell(&self, connect: &NetworkConnect) -> Vec<Alert> {
        if !REVERSE_SHELL_PORTS.contains(&connect.remote_port) {
            return Vec::new();
        }

        let Some(process) = self.recent_processes.get(&(connect.pid, connect.tid)) else {
            return Vec::new();
        };

        if !within_window(process.timestamp_ns, connect.timestamp_ns) {
            return Vec::new();
        }

        vec![reverse_shell_alert(process, connect)]
    }

    fn prune(&mut self, now_ns: u64) {
        self.recent_processes
            .retain(|_, process| within_window(process.timestamp_ns, now_ns));
        self.recent_file_writes
            .retain(|_, file| within_window(file.timestamp_ns, now_ns));
    }

    fn record_file_write(&mut self, file: Option<FileSnapshot>) -> Vec<Alert> {
        if let Some(file) = file {
            self.recent_file_writes.insert(file.path.clone(), file);
        }
        Vec::new()
    }

    fn remove_file_write(&mut self, path: &str) -> Vec<Alert> {
        self.recent_file_writes.remove(path);
        Vec::new()
    }

    fn evaluate_drop_execute(&self, start: &ProcessStart) -> Vec<Alert> {
        if start.exe_path.is_empty() || !is_drop_execute_path(&start.exe_path) {
            return Vec::new();
        }

        let Some(file) = self.recent_file_writes.get(&start.exe_path) else {
            return Vec::new();
        };

        if !within_window(file.timestamp_ns, start.timestamp_ns) {
            return Vec::new();
        }

        vec![drop_execute_alert(file, start)]
    }
}

#[derive(Clone, Debug)]
struct ProcessSnapshot {
    timestamp_ns: u64,
    ppid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    exe_path: String,
}

impl From<&ProcessStart> for ProcessSnapshot {
    fn from(start: &ProcessStart) -> Self {
        Self {
            timestamp_ns: start.timestamp_ns,
            ppid: start.ppid,
            uid: start.uid,
            gid: start.gid,
            comm: start.comm.clone(),
            exe_path: start.exe_path.clone(),
        }
    }
}

#[derive(Clone, Debug)]
struct FileSnapshot {
    timestamp_ns: u64,
    path: String,
    operation: &'static str,
}

impl FileSnapshot {
    fn from_write(file: &FileWrite) -> Option<Self> {
        Self::new(file.timestamp_ns, &file.resolved_path, "file_write")
    }

    fn from_writev(file: &FileWriteV) -> Option<Self> {
        Self::new(file.timestamp_ns, &file.resolved_path, "file_write")
    }

    fn from_pwrite64(file: &FilePWrite64) -> Option<Self> {
        Self::new(file.timestamp_ns, &file.resolved_path, "file_write")
    }

    fn from_rename(file: &FileRename) -> Option<Self> {
        Self::new(file.timestamp_ns, &file.new_filename, "file_rename")
    }

    fn from_renameat(file: &FileRenameAt) -> Option<Self> {
        Self::new(file.timestamp_ns, &file.new_filename, "file_rename")
    }

    fn from_renameat2(file: &FileRenameAt2) -> Option<Self> {
        Self::new(file.timestamp_ns, &file.new_filename, "file_rename")
    }

    fn new(timestamp_ns: u64, path: &str, operation: &'static str) -> Option<Self> {
        if path.is_empty() || !is_drop_execute_path(path) {
            return None;
        }

        Some(Self {
            timestamp_ns,
            path: path.to_string(),
            operation,
        })
    }
}

fn event_timestamp_ns(event: &NormalizedEvent) -> u64 {
    match event {
        NormalizedEvent::ProcessStart(event) => event.timestamp_ns,
        NormalizedEvent::ProcessExit(event) => event.timestamp_ns,
        NormalizedEvent::ProcessRelationship(event) => event.timestamp_ns,
        NormalizedEvent::FileOpen(event) => event.timestamp_ns,
        NormalizedEvent::FileOpenAt2(event) => event.timestamp_ns,
        NormalizedEvent::FileWrite(event) => event.timestamp_ns,
        NormalizedEvent::FileWriteV(event) => event.timestamp_ns,
        NormalizedEvent::FilePWrite64(event) => event.timestamp_ns,
        NormalizedEvent::FileRename(event) => event.timestamp_ns,
        NormalizedEvent::FileRenameAt(event) => event.timestamp_ns,
        NormalizedEvent::FileRenameAt2(event) => event.timestamp_ns,
        NormalizedEvent::FileUnlink(event) => event.timestamp_ns,
        NormalizedEvent::FileUnlinkAt(event) => event.timestamp_ns,
        NormalizedEvent::NetworkConnect(event) => event.timestamp_ns,
        NormalizedEvent::NetworkBind(event) => event.timestamp_ns,
        NormalizedEvent::NetworkListen(event) => event.timestamp_ns,
    }
}

fn is_reverse_shell_process(comm: &str) -> bool {
    REVERSE_SHELL_PROCESS_NAMES.contains(&comm)
}

fn within_window(start_ns: u64, now_ns: u64) -> bool {
    now_ns >= start_ns && now_ns - start_ns <= SCENARIO_WINDOW_NS
}

fn is_drop_execute_path(path: &str) -> bool {
    DROP_EXEC_PATH_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

fn reverse_shell_alert(process: &ProcessSnapshot, connect: &NetworkConnect) -> Alert {
    Alert {
        timestamp_ns: connect.timestamp_ns,
        rule_id: "BUILTIN-SCENARIO-REVERSE-SHELL-001".to_string(),
        rule_name: "Reverse shell behavior".to_string(),
        rule_type: "scenario".to_string(),
        severity: "high".to_string(),
        action: "alert".to_string(),
        source_event_type: "network_connect".to_string(),
        pid: Some(connect.pid),
        tid: Some(connect.tid),
        ppid: Some(process.ppid),
        uid: Some(process.uid),
        gid: Some(process.gid),
        comm: Some(process.comm.clone()),
        exe_path: Some(process.exe_path.clone()),
        process_name: Some(process.comm.clone()),
        parent_name: None,
        path: None,
        operation: None,
        direction: Some("outbound".to_string()),
        port: Some(connect.remote_port),
        addr: Some(connect.remote_addr.clone()),
        family: Some(connect.family.clone()),
    }
}

fn drop_execute_alert(file: &FileSnapshot, start: &ProcessStart) -> Alert {
    Alert {
        timestamp_ns: start.timestamp_ns,
        rule_id: "BUILTIN-SCENARIO-DROP-EXEC-001".to_string(),
        rule_name: "Suspicious binary drop and execute".to_string(),
        rule_type: "scenario".to_string(),
        severity: "high".to_string(),
        action: "alert".to_string(),
        source_event_type: "process_start".to_string(),
        pid: Some(start.pid),
        tid: Some(start.tid),
        ppid: Some(start.ppid),
        uid: Some(start.uid),
        gid: Some(start.gid),
        comm: Some(start.comm.clone()),
        exe_path: Some(start.exe_path.clone()),
        process_name: Some(start.comm.clone()),
        parent_name: None,
        path: Some(file.path.clone()),
        operation: Some(file.operation.to_string()),
        direction: None,
        port: None,
        addr: None,
        family: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::{FileUnlink, ProcessExit};

    fn process_start(comm: &str, timestamp_ns: u64) -> NormalizedEvent {
        process_start_with_exe(comm, &format!("/usr/bin/{comm}"), timestamp_ns)
    }

    fn process_start_with_exe(comm: &str, exe_path: &str, timestamp_ns: u64) -> NormalizedEvent {
        NormalizedEvent::ProcessStart(ProcessStart {
            pid: 10,
            tid: 10,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: comm.to_string(),
            exe_path: exe_path.to_string(),
            source: Some("execve".to_string()),
            timestamp_ns,
            filename_truncated: false,
        })
    }

    fn file_write(path: &str, timestamp_ns: u64) -> NormalizedEvent {
        NormalizedEvent::FileWrite(FileWrite {
            pid: 20,
            tid: 20,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "cp".to_string(),
            exe_path: "/usr/bin/cp".to_string(),
            fd: 3,
            count: 100,
            resolved_path: path.to_string(),
            alert: false,
            detection_type: None,
            timestamp_ns,
        })
    }

    fn file_rename(new_path: &str, timestamp_ns: u64) -> NormalizedEvent {
        NormalizedEvent::FileRename(FileRename {
            pid: 20,
            tid: 20,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "mv".to_string(),
            exe_path: "/usr/bin/mv".to_string(),
            old_filename: "/home/alice/demo".to_string(),
            new_filename: new_path.to_string(),
            filename_truncated: false,
            alert: false,
            detection_type: None,
            timestamp_ns,
        })
    }

    fn file_unlink(path: &str, timestamp_ns: u64) -> NormalizedEvent {
        NormalizedEvent::FileUnlink(FileUnlink {
            pid: 20,
            tid: 20,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "rm".to_string(),
            exe_path: "/usr/bin/rm".to_string(),
            filename: path.to_string(),
            filename_truncated: false,
            alert: false,
            detection_type: None,
            timestamp_ns,
        })
    }

    fn process_exit(comm: &str, timestamp_ns: u64) -> NormalizedEvent {
        NormalizedEvent::ProcessExit(ProcessExit {
            pid: 10,
            tid: 10,
            comm: comm.to_string(),
            group_dead: true,
            uid: 1000,
            gid: 1000,
            timestamp_ns,
        })
    }

    fn network_connect(port: u16, timestamp_ns: u64) -> NormalizedEvent {
        NormalizedEvent::NetworkConnect(NetworkConnect {
            pid: 10,
            tid: 10,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "sh".to_string(),
            exe_path: "/usr/bin/sh".to_string(),
            family: "ipv4".to_string(),
            socket_fd: 3,
            remote_addr: "127.0.0.1".to_string(),
            remote_port: port,
            alert: false,
            detection_type: None,
            timestamp_ns,
        })
    }

    #[test]
    fn reverse_shell_alerts_on_shell_connect_to_suspicious_port() {
        let mut engine = ScenarioEngine::new();

        assert!(engine.evaluate(&process_start("sh", 1_000)).is_empty());
        let alerts = engine.evaluate(&network_connect(4444, 2_000));

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "BUILTIN-SCENARIO-REVERSE-SHELL-001");
        assert_eq!(alerts[0].process_name, Some("sh".to_string()));
        assert_eq!(alerts[0].port, Some(4444));
        assert_eq!(alerts[0].addr, Some("127.0.0.1".to_string()));
    }

    #[test]
    fn reverse_shell_ignores_benign_port() {
        let mut engine = ScenarioEngine::new();

        engine.evaluate(&process_start("sh", 1_000));
        let alerts = engine.evaluate(&network_connect(443, 2_000));

        assert!(alerts.is_empty());
    }

    #[test]
    fn reverse_shell_ignores_events_outside_window() {
        let mut engine = ScenarioEngine::new();

        engine.evaluate(&process_start("sh", 1_000));
        let alerts = engine.evaluate(&network_connect(4444, 11_000_001_001));

        assert!(alerts.is_empty());
    }

    #[test]
    fn reverse_shell_ignores_non_candidate_process() {
        let mut engine = ScenarioEngine::new();

        engine.evaluate(&process_start("curl", 1_000));
        let alerts = engine.evaluate(&network_connect(4444, 2_000));

        assert!(alerts.is_empty());
    }

    #[test]
    fn reverse_shell_replaces_candidate_after_non_candidate_exec() {
        let mut engine = ScenarioEngine::new();

        engine.evaluate(&process_start("sh", 1_000));
        engine.evaluate(&process_start("curl", 1_500));
        let alerts = engine.evaluate(&network_connect(4444, 2_000));

        assert!(alerts.is_empty());
    }

    #[test]
    fn reverse_shell_removes_candidate_on_exit() {
        let mut engine = ScenarioEngine::new();

        engine.evaluate(&process_start("sh", 1_000));
        engine.evaluate(&process_exit("sh", 1_500));
        let alerts = engine.evaluate(&network_connect(4444, 2_000));

        assert!(alerts.is_empty());
    }

    #[test]
    fn drop_execute_alerts_on_written_temp_path_execution() {
        let mut engine = ScenarioEngine::new();

        assert!(
            engine
                .evaluate(&file_write("/tmp/rg-demo", 1_000))
                .is_empty()
        );
        let alerts = engine.evaluate(&process_start_with_exe("rg-demo", "/tmp/rg-demo", 2_000));

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "BUILTIN-SCENARIO-DROP-EXEC-001");
        assert_eq!(alerts[0].path, Some("/tmp/rg-demo".to_string()));
        assert_eq!(alerts[0].operation, Some("file_write".to_string()));
        assert_eq!(alerts[0].process_name, Some("rg-demo".to_string()));
    }

    #[test]
    fn drop_execute_alerts_on_renamed_temp_path_execution() {
        let mut engine = ScenarioEngine::new();

        engine.evaluate(&file_rename("/dev/shm/rg-demo", 1_000));
        let alerts = engine.evaluate(&process_start_with_exe(
            "rg-demo",
            "/dev/shm/rg-demo",
            2_000,
        ));

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].operation, Some("file_rename".to_string()));
    }

    #[test]
    fn drop_execute_ignores_non_staging_paths() {
        let mut engine = ScenarioEngine::new();

        engine.evaluate(&file_write("/home/alice/rg-demo", 1_000));
        let alerts = engine.evaluate(&process_start_with_exe(
            "rg-demo",
            "/home/alice/rg-demo",
            2_000,
        ));

        assert!(alerts.is_empty());
    }

    #[test]
    fn drop_execute_ignores_events_outside_window() {
        let mut engine = ScenarioEngine::new();

        engine.evaluate(&file_write("/tmp/rg-demo", 1_000));
        let alerts = engine.evaluate(&process_start_with_exe(
            "rg-demo",
            "/tmp/rg-demo",
            11_000_001_001,
        ));

        assert!(alerts.is_empty());
    }

    #[test]
    fn drop_execute_unlink_removes_stale_write_snapshot() {
        let mut engine = ScenarioEngine::new();

        engine.evaluate(&file_write("/tmp/rg-demo", 1_000));
        engine.evaluate(&file_unlink("/tmp/rg-demo", 1_500));
        let alerts = engine.evaluate(&process_start_with_exe("rg-demo", "/tmp/rg-demo", 2_000));

        assert!(alerts.is_empty());
    }
}
