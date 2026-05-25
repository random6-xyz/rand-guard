use crate::rules::Alert;

pub fn format_alert_json(alert: &Alert) -> String {
    serde_json::json!({
        "event_type": "alert",
        "timestamp_ns": alert.timestamp_ns,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "rule_type": alert.rule_type,
        "severity": alert.severity,
        "action": alert.action,
        "source_event_type": alert.source_event_type,
        "pid": alert.pid,
        "tid": alert.tid,
        "ppid": alert.ppid,
        "uid": alert.uid,
        "gid": alert.gid,
        "comm": alert.comm,
        "exe_path": alert.exe_path,
        "process_name": alert.process_name,
        "parent_name": alert.parent_name,
        "path": alert.path,
        "operation": alert.operation,
        "direction": alert.direction,
        "port": alert.port,
        "addr": alert.addr,
        "family": alert.family,
    })
    .to_string()
}
