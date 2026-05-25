use crate::config::{NetworkDirection, RuleAction, RuleConfig, RuleType, Severity};
use crate::normalize::{
    FileOpen, FileOpenAt2, FilePWrite64, FileRename, FileRenameAt, FileRenameAt2, FileUnlink,
    FileUnlinkAt, FileWrite, FileWriteV, NetworkBind, NetworkConnect, NetworkListen,
    NormalizedEvent, ProcessRelationship, ProcessStart,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alert {
    pub timestamp_ns: u64,
    pub rule_id: String,
    pub rule_name: String,
    pub rule_type: String,
    pub severity: String,
    pub action: String,
    pub source_event_type: String,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub comm: Option<String>,
    pub exe_path: Option<String>,
    pub process_name: Option<String>,
    pub parent_name: Option<String>,
    pub path: Option<String>,
    pub operation: Option<String>,
    pub direction: Option<String>,
    pub port: Option<u16>,
    pub addr: Option<String>,
    pub family: Option<String>,
}

pub struct RuleEngine {
    rules: Vec<RuleConfig>,
}

impl RuleEngine {
    pub fn new(config_rules: &[RuleConfig]) -> Self {
        let mut rules = builtin_rules();
        rules.extend(config_rules.iter().cloned());
        Self { rules }
    }

    pub fn evaluate(&self, event: &NormalizedEvent) -> Vec<Alert> {
        self.rules
            .iter()
            .filter(|rule| rule.enabled)
            .filter_map(|rule| evaluate_rule(rule, event))
            .collect()
    }
}

pub fn builtin_rules() -> Vec<RuleConfig> {
    vec![
        RuleConfig {
            id: "BUILTIN-FILE-SYSTEMD-001".to_string(),
            name: "Systemd service modified".to_string(),
            enabled: true,
            rule_type: RuleType::File,
            severity: Severity::High,
            action: RuleAction::Alert,
            parent_names: vec![],
            process_names: vec![],
            paths: vec![
                "/etc/systemd/system/".to_string(),
                "/usr/lib/systemd/system/".to_string(),
                "/run/systemd/system/".to_string(),
            ],
            patterns: vec!["*.service".to_string()],
            operations: file_operations(),
            direction: None,
            ports: vec![],
        },
        RuleConfig {
            id: "BUILTIN-FILE-CRON-001".to_string(),
            name: "Cron configuration modified".to_string(),
            enabled: true,
            rule_type: RuleType::File,
            severity: Severity::High,
            action: RuleAction::Alert,
            parent_names: vec![],
            process_names: vec![],
            paths: vec![
                "/etc/cron.d/".to_string(),
                "/etc/cron.daily/".to_string(),
                "/etc/crontab".to_string(),
            ],
            patterns: vec![],
            operations: file_operations(),
            direction: None,
            ports: vec![],
        },
        RuleConfig {
            id: "BUILTIN-NET-OUTBOUND-001".to_string(),
            name: "Suspicious outbound port".to_string(),
            enabled: true,
            rule_type: RuleType::Network,
            severity: Severity::Medium,
            action: RuleAction::Alert,
            parent_names: vec![],
            process_names: vec![],
            paths: vec![],
            patterns: vec![],
            operations: vec![],
            direction: Some(NetworkDirection::Outbound),
            ports: vec![4444, 1337, 31337],
        },
    ]
}

fn file_operations() -> Vec<String> {
    ["file_open", "file_write", "file_rename", "file_unlink"]
        .iter()
        .map(|op| op.to_string())
        .collect()
}

fn evaluate_rule(rule: &RuleConfig, event: &NormalizedEvent) -> Option<Alert> {
    match rule.rule_type {
        RuleType::Process => evaluate_process_rule(rule, event),
        RuleType::File => evaluate_file_rule(rule, event),
        RuleType::Network => evaluate_network_rule(rule, event),
    }
}

fn evaluate_process_rule(rule: &RuleConfig, event: &NormalizedEvent) -> Option<Alert> {
    match event {
        NormalizedEvent::ProcessStart(start) => {
            if !rule.parent_names.is_empty() {
                return None;
            }
            if !matches_name(&rule.process_names, &start.comm) {
                return None;
            }
            Some(process_start_alert(rule, start))
        }
        NormalizedEvent::ProcessRelationship(rel) => {
            if !matches_name(&rule.process_names, &rel.child_comm) {
                return None;
            }
            if !matches_name(&rule.parent_names, &rel.parent_comm) {
                return None;
            }
            Some(process_relationship_alert(rule, rel))
        }
        _ => None,
    }
}

fn evaluate_file_rule(rule: &RuleConfig, event: &NormalizedEvent) -> Option<Alert> {
    let fields = match event {
        NormalizedEvent::FileOpen(file) => FileFields::from_open(file),
        NormalizedEvent::FileOpenAt2(file) => FileFields::from_openat2(file),
        NormalizedEvent::FileWrite(file) => FileFields::from_write(file),
        NormalizedEvent::FileWriteV(file) => FileFields::from_writev(file),
        NormalizedEvent::FilePWrite64(file) => FileFields::from_pwrite64(file),
        NormalizedEvent::FileRename(file) => FileFields::from_rename(file),
        NormalizedEvent::FileRenameAt(file) => FileFields::from_renameat(file),
        NormalizedEvent::FileRenameAt2(file) => FileFields::from_renameat2(file),
        NormalizedEvent::FileUnlink(file) => FileFields::from_unlink(file),
        NormalizedEvent::FileUnlinkAt(file) => FileFields::from_unlinkat(file),
        _ => return None,
    };

    if !matches_operation(&rule.operations, fields.operation) {
        return None;
    }
    let matched_path = fields
        .paths
        .iter()
        .find(|path| matches_path_rule(path, &rule.paths, &rule.patterns))?;

    Some(file_alert(rule, &fields, matched_path))
}

fn evaluate_network_rule(rule: &RuleConfig, event: &NormalizedEvent) -> Option<Alert> {
    let fields = match event {
        NormalizedEvent::NetworkConnect(net) => NetworkFields::from_connect(net),
        NormalizedEvent::NetworkBind(net) => NetworkFields::from_bind(net),
        NormalizedEvent::NetworkListen(net) => NetworkFields::from_listen(net),
        _ => return None,
    };

    if rule.direction != Some(fields.direction) || !rule.ports.contains(&fields.port) {
        return None;
    }
    if !matches_name(&rule.process_names, fields.comm) {
        return None;
    }

    Some(network_alert(rule, &fields))
}

fn matches_name(names: &[String], value: &str) -> bool {
    names.is_empty() || names.iter().any(|name| name == value)
}

fn matches_operation(operations: &[String], operation: &str) -> bool {
    operations
        .iter()
        .any(|op| op == "*" || canonical_operation(op) == operation)
}

fn canonical_operation(operation: &str) -> &str {
    match operation {
        "open" | "file_open" => "file_open",
        "write" | "file_write" => "file_write",
        "rename" | "file_rename" => "file_rename",
        "unlink" | "file_unlink" => "file_unlink",
        other => other,
    }
}

fn matches_path_rule(path: &str, paths: &[String], patterns: &[String]) -> bool {
    let has_paths = !paths.is_empty();
    let has_patterns = !patterns.is_empty();
    let matches_path = paths.iter().any(|prefix| path.starts_with(prefix));
    let matches_pattern = patterns
        .iter()
        .any(|pattern| matches_pattern(path, pattern));

    if has_paths && has_patterns {
        matches_path && matches_pattern
    } else if has_paths {
        matches_path
    } else if has_patterns {
        matches_pattern
    } else {
        false
    }
}

fn matches_pattern(path: &str, pattern: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        path.ends_with(&format!(".{suffix}"))
    } else {
        path.contains(pattern)
    }
}

fn base_alert(rule: &RuleConfig, timestamp_ns: u64, source_event_type: &str) -> Alert {
    Alert {
        timestamp_ns,
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        rule_type: rule_type_name(&rule.rule_type).to_string(),
        severity: severity_name(&rule.severity).to_string(),
        action: action_name(&rule.action).to_string(),
        source_event_type: source_event_type.to_string(),
        pid: None,
        tid: None,
        ppid: None,
        uid: None,
        gid: None,
        comm: None,
        exe_path: None,
        process_name: None,
        parent_name: None,
        path: None,
        operation: None,
        direction: None,
        port: None,
        addr: None,
        family: None,
    }
}

fn process_start_alert(rule: &RuleConfig, start: &ProcessStart) -> Alert {
    let mut alert = base_alert(rule, start.timestamp_ns, "process_start");
    alert.pid = Some(start.pid);
    alert.tid = Some(start.tid);
    alert.ppid = Some(start.ppid);
    alert.uid = Some(start.uid);
    alert.gid = Some(start.gid);
    alert.comm = Some(start.comm.clone());
    alert.exe_path = Some(start.exe_path.clone());
    alert.process_name = Some(start.comm.clone());
    alert
}

fn process_relationship_alert(rule: &RuleConfig, rel: &ProcessRelationship) -> Alert {
    let mut alert = base_alert(rule, rel.timestamp_ns, "process_relationship");
    alert.pid = Some(rel.child_pid);
    alert.tid = Some(rel.child_tid);
    alert.ppid = Some(rel.parent_pid);
    alert.uid = Some(rel.uid);
    alert.gid = Some(rel.gid);
    alert.comm = Some(rel.child_comm.clone());
    alert.process_name = Some(rel.child_comm.clone());
    alert.parent_name = Some(rel.parent_comm.clone());
    alert
}

fn file_alert(rule: &RuleConfig, fields: &FileFields<'_>, path: &str) -> Alert {
    let mut alert = base_alert(rule, fields.timestamp_ns, fields.source_event_type);
    alert.pid = Some(fields.pid);
    alert.tid = Some(fields.tid);
    alert.ppid = Some(fields.ppid);
    alert.uid = Some(fields.uid);
    alert.gid = Some(fields.gid);
    alert.comm = Some(fields.comm.to_string());
    alert.exe_path = Some(fields.exe_path.to_string());
    alert.path = Some(path.to_string());
    alert.operation = Some(fields.operation.to_string());
    alert
}

fn network_alert(rule: &RuleConfig, fields: &NetworkFields<'_>) -> Alert {
    let mut alert = base_alert(rule, fields.timestamp_ns, fields.source_event_type);
    alert.pid = Some(fields.pid);
    alert.tid = Some(fields.tid);
    alert.ppid = Some(fields.ppid);
    alert.uid = Some(fields.uid);
    alert.gid = Some(fields.gid);
    alert.comm = Some(fields.comm.to_string());
    alert.exe_path = Some(fields.exe_path.to_string());
    alert.direction = Some(direction_name(fields.direction).to_string());
    alert.port = Some(fields.port);
    alert.addr = Some(fields.addr.to_string());
    alert.family = Some(fields.family.to_string());
    alert
}

fn rule_type_name(rule_type: &RuleType) -> &'static str {
    match rule_type {
        RuleType::Process => "process",
        RuleType::File => "file",
        RuleType::Network => "network",
    }
}

fn severity_name(severity: &Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn action_name(action: &RuleAction) -> &'static str {
    match action {
        RuleAction::Alert => "alert",
    }
}

fn direction_name(direction: NetworkDirection) -> &'static str {
    match direction {
        NetworkDirection::Inbound => "inbound",
        NetworkDirection::Outbound => "outbound",
    }
}

struct FileFields<'a> {
    source_event_type: &'static str,
    timestamp_ns: u64,
    pid: u32,
    tid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,
    comm: &'a str,
    exe_path: &'a str,
    operation: &'static str,
    paths: Vec<&'a str>,
}

impl<'a> FileFields<'a> {
    fn from_open(file: &'a FileOpen) -> Self {
        Self::new(
            "file_open",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_open",
            vec![&file.filename],
        )
    }

    fn from_openat2(file: &'a FileOpenAt2) -> Self {
        Self::new(
            "file_openat2",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_open",
            vec![&file.filename],
        )
    }

    fn from_write(file: &'a FileWrite) -> Self {
        Self::new(
            "file_write",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_write",
            vec![&file.resolved_path],
        )
    }

    fn from_writev(file: &'a FileWriteV) -> Self {
        Self::new(
            "file_writev",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_write",
            vec![&file.resolved_path],
        )
    }

    fn from_pwrite64(file: &'a FilePWrite64) -> Self {
        Self::new(
            "file_pwrite64",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_write",
            vec![&file.resolved_path],
        )
    }

    fn from_rename(file: &'a FileRename) -> Self {
        Self::new(
            "file_rename",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_rename",
            vec![&file.old_filename, &file.new_filename],
        )
    }

    fn from_renameat(file: &'a FileRenameAt) -> Self {
        Self::new(
            "file_renameat",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_rename",
            vec![&file.old_filename, &file.new_filename],
        )
    }

    fn from_renameat2(file: &'a FileRenameAt2) -> Self {
        Self::new(
            "file_renameat2",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_rename",
            vec![&file.old_filename, &file.new_filename],
        )
    }

    fn from_unlink(file: &'a FileUnlink) -> Self {
        Self::new(
            "file_unlink",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_unlink",
            vec![&file.filename],
        )
    }

    fn from_unlinkat(file: &'a FileUnlinkAt) -> Self {
        Self::new(
            "file_unlinkat",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_unlink",
            vec![&file.filename],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        source_event_type: &'static str,
        timestamp_ns: u64,
        pid: u32,
        tid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        comm: &'a str,
        exe_path: &'a str,
        operation: &'static str,
        paths: Vec<&'a str>,
    ) -> Self {
        Self {
            source_event_type,
            timestamp_ns,
            pid,
            tid,
            ppid,
            uid,
            gid,
            comm,
            exe_path,
            operation,
            paths,
        }
    }
}

struct NetworkFields<'a> {
    source_event_type: &'static str,
    timestamp_ns: u64,
    pid: u32,
    tid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,
    comm: &'a str,
    exe_path: &'a str,
    family: &'a str,
    direction: NetworkDirection,
    port: u16,
    addr: &'a str,
}

impl<'a> NetworkFields<'a> {
    fn from_connect(net: &'a NetworkConnect) -> Self {
        Self::new(
            "network_connect",
            net.timestamp_ns,
            net.pid,
            net.tid,
            net.ppid,
            net.uid,
            net.gid,
            &net.comm,
            &net.exe_path,
            &net.family,
            NetworkDirection::Outbound,
            net.remote_port,
            &net.remote_addr,
        )
    }

    fn from_bind(net: &'a NetworkBind) -> Self {
        Self::new(
            "network_bind",
            net.timestamp_ns,
            net.pid,
            net.tid,
            net.ppid,
            net.uid,
            net.gid,
            &net.comm,
            &net.exe_path,
            &net.family,
            NetworkDirection::Inbound,
            net.local_port,
            &net.local_addr,
        )
    }

    fn from_listen(net: &'a NetworkListen) -> Self {
        Self::new(
            "network_listen",
            net.timestamp_ns,
            net.pid,
            net.tid,
            net.ppid,
            net.uid,
            net.gid,
            &net.comm,
            &net.exe_path,
            &net.family,
            NetworkDirection::Inbound,
            net.local_port,
            &net.local_addr,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        source_event_type: &'static str,
        timestamp_ns: u64,
        pid: u32,
        tid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        comm: &'a str,
        exe_path: &'a str,
        family: &'a str,
        direction: NetworkDirection,
        port: u16,
        addr: &'a str,
    ) -> Self {
        Self {
            source_event_type,
            timestamp_ns,
            pid,
            tid,
            ppid,
            uid,
            gid,
            comm,
            exe_path,
            family,
            direction,
            port,
            addr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::{FileRename, NetworkConnect, ProcessStart};

    fn file_rule() -> RuleConfig {
        RuleConfig {
            id: "FILE-001".to_string(),
            name: "Sensitive file touched".to_string(),
            enabled: true,
            rule_type: RuleType::File,
            severity: Severity::High,
            action: RuleAction::Alert,
            parent_names: vec![],
            process_names: vec![],
            paths: vec!["/etc/passwd".to_string()],
            patterns: vec![],
            operations: vec!["file_rename".to_string()],
            direction: None,
            ports: vec![],
        }
    }

    #[test]
    fn process_rule_matches_process_start_name() {
        let engine = RuleEngine::new(&[RuleConfig {
            id: "PROC-001".to_string(),
            name: "Shell started".to_string(),
            enabled: true,
            rule_type: RuleType::Process,
            severity: Severity::Medium,
            action: RuleAction::Alert,
            parent_names: vec![],
            process_names: vec!["bash".to_string()],
            paths: vec![],
            patterns: vec![],
            operations: vec![],
            direction: None,
            ports: vec![],
        }]);
        let event = NormalizedEvent::ProcessStart(ProcessStart {
            pid: 10,
            tid: 10,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "bash".to_string(),
            exe_path: "/usr/bin/bash".to_string(),
            source: Some("execve".to_string()),
            timestamp_ns: 123,
            filename_truncated: false,
        });

        let alerts = engine.evaluate(&event);

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "PROC-001");
        assert_eq!(alerts[0].process_name, Some("bash".to_string()));
    }

    #[test]
    fn process_parent_rule_matches_relationship() {
        let engine = RuleEngine::new(&[RuleConfig {
            id: "PROC-002".to_string(),
            name: "Web shell spawn".to_string(),
            enabled: true,
            rule_type: RuleType::Process,
            severity: Severity::High,
            action: RuleAction::Alert,
            parent_names: vec!["nginx".to_string()],
            process_names: vec!["sh".to_string()],
            paths: vec![],
            patterns: vec![],
            operations: vec![],
            direction: None,
            ports: vec![],
        }]);
        let event = NormalizedEvent::ProcessRelationship(ProcessRelationship {
            parent_pid: 1,
            parent_comm: "nginx".to_string(),
            child_pid: 10,
            child_tid: 10,
            child_comm: "sh".to_string(),
            uid: 33,
            gid: 33,
            timestamp_ns: 123,
        });

        let alerts = engine.evaluate(&event);

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].parent_name, Some("nginx".to_string()));
    }

    #[test]
    fn file_rule_matches_either_rename_path() {
        let engine = RuleEngine::new(&[file_rule()]);
        let event = NormalizedEvent::FileRename(FileRename {
            pid: 10,
            tid: 10,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: "mv".to_string(),
            exe_path: "/usr/bin/mv".to_string(),
            old_filename: "/tmp/passwd".to_string(),
            new_filename: "/etc/passwd".to_string(),
            filename_truncated: false,
            alert: false,
            detection_type: None,
            timestamp_ns: 123,
        });

        let alerts = engine.evaluate(&event);

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].path, Some("/etc/passwd".to_string()));
        assert_eq!(alerts[0].operation, Some("file_rename".to_string()));
    }

    #[test]
    fn network_rule_matches_outbound_port() {
        let engine = RuleEngine::new(&[RuleConfig {
            id: "NET-001".to_string(),
            name: "Suspicious outbound port".to_string(),
            enabled: true,
            rule_type: RuleType::Network,
            severity: Severity::Medium,
            action: RuleAction::Alert,
            parent_names: vec![],
            process_names: vec!["nc".to_string()],
            paths: vec![],
            patterns: vec![],
            operations: vec![],
            direction: Some(NetworkDirection::Outbound),
            ports: vec![4444],
        }]);
        let event = NormalizedEvent::NetworkConnect(NetworkConnect {
            pid: 10,
            tid: 10,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "nc".to_string(),
            exe_path: "/usr/bin/nc".to_string(),
            family: "ipv4".to_string(),
            socket_fd: 3,
            remote_addr: "127.0.0.1".to_string(),
            remote_port: 4444,
            alert: false,
            detection_type: None,
            timestamp_ns: 123,
        });

        let alerts = engine.evaluate(&event);

        assert_eq!(alerts.len(), 2);
        assert!(alerts.iter().any(|alert| alert.rule_id == "NET-001"));
        assert!(
            alerts
                .iter()
                .any(|alert| alert.rule_id == "BUILTIN-NET-OUTBOUND-001")
        );
    }

    #[test]
    fn disabled_rules_are_ignored() {
        let mut rule = file_rule();
        rule.enabled = false;
        let engine = RuleEngine::new(&[rule]);
        let event = NormalizedEvent::FileRename(FileRename {
            pid: 10,
            tid: 10,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: "mv".to_string(),
            exe_path: "/usr/bin/mv".to_string(),
            old_filename: "/tmp/passwd".to_string(),
            new_filename: "/etc/passwd".to_string(),
            filename_truncated: false,
            alert: false,
            detection_type: None,
            timestamp_ns: 123,
        });

        assert!(engine.evaluate(&event).is_empty());
    }
}
