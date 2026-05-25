use crate::config::{NetworkDirection, RuleAction, RuleConfig, RuleType, Severity};
use crate::normalize::{ProcessRelationship, ProcessStart};
use crate::rules::matchers::{FileFields, NetworkFields};

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

pub fn base_alert(rule: &RuleConfig, timestamp_ns: u64, source_event_type: &str) -> Alert {
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

pub fn process_start_alert(rule: &RuleConfig, start: &ProcessStart) -> Alert {
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

pub fn process_relationship_alert(rule: &RuleConfig, rel: &ProcessRelationship) -> Alert {
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

pub fn file_alert(rule: &RuleConfig, fields: &FileFields<'_>, path: &str) -> Alert {
    let mut alert = base_alert(rule, fields.timestamp_ns, fields.source_event_type);
    alert.pid = Some(fields.pid);
    alert.tid = Some(fields.tid);
    alert.ppid = Some(fields.ppid);
    alert.uid = Some(fields.uid);
    alert.gid = Some(fields.gid);
    alert.comm = Some(fields.comm.to_string());
    alert.exe_path = Some(fields.exe_path.to_string());
    alert.process_name = Some(fields.comm.to_string());
    alert.path = Some(path.to_string());
    alert.operation = Some(fields.operation.to_string());
    alert
}

pub fn network_alert(rule: &RuleConfig, fields: &NetworkFields<'_>) -> Alert {
    let mut alert = base_alert(rule, fields.timestamp_ns, fields.source_event_type);
    alert.pid = Some(fields.pid);
    alert.tid = Some(fields.tid);
    alert.ppid = Some(fields.ppid);
    alert.uid = Some(fields.uid);
    alert.gid = Some(fields.gid);
    alert.comm = Some(fields.comm.to_string());
    alert.exe_path = Some(fields.exe_path.to_string());
    alert.process_name = Some(fields.comm.to_string());
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
