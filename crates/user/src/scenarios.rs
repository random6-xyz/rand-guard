use std::collections::HashMap;

use crate::normalize::{NetworkConnect, NormalizedEvent, ProcessStart};
use crate::rules::Alert;

const SCENARIO_WINDOW_NS: u64 = 10_000_000_000;
const REVERSE_SHELL_PORTS: &[u16] = &[4444, 1337, 31337, 9001, 5555];
const REVERSE_SHELL_PROCESS_NAMES: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "mksh", "busybox", "nc", "ncat", "socat", "python",
    "python3", "perl", "php", "ruby",
];

pub struct ScenarioEngine {
    recent_processes: HashMap<(u32, u32), ProcessSnapshot>,
}

impl ScenarioEngine {
    pub fn new() -> Self {
        Self {
            recent_processes: HashMap::new(),
        }
    }

    pub fn evaluate(&mut self, event: &NormalizedEvent) -> Vec<Alert> {
        let timestamp_ns = event_timestamp_ns(event);
        self.prune(timestamp_ns);

        match event {
            NormalizedEvent::ProcessStart(start) => {
                if is_reverse_shell_process(&start.comm) {
                    self.recent_processes
                        .insert((start.pid, start.tid), ProcessSnapshot::from(start));
                }
                Vec::new()
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn process_start(comm: &str, timestamp_ns: u64) -> NormalizedEvent {
        NormalizedEvent::ProcessStart(ProcessStart {
            pid: 10,
            tid: 10,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: comm.to_string(),
            exe_path: format!("/usr/bin/{comm}"),
            source: Some("execve".to_string()),
            timestamp_ns,
            filename_truncated: false,
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
}
