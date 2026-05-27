#[derive(Clone, Debug)]
pub struct HealthRecord {
    pub raw_events_read: u64,
    pub normalized_events_output: u64,
    pub alerts_output: u64,
    pub userspace_filtered: u64,
    pub userspace_rate_limited: u64,
    pub invalid_schema: u64,
    pub process_table_size: usize,
    pub pending_exec_source_size: usize,
    pub uptime_secs: u64,
}

pub fn format_health_json(record: &HealthRecord) -> String {
    serde_json::json!({
        "event_type": "health",
        "raw_events_read": record.raw_events_read,
        "normalized_events_output": record.normalized_events_output,
        "alerts_output": record.alerts_output,
        "userspace_filtered": record.userspace_filtered,
        "userspace_rate_limited": record.userspace_rate_limited,
        "invalid_schema": record.invalid_schema,
        "process_table_size": record.process_table_size,
        "pending_exec_source_size": record.pending_exec_source_size,
        "uptime_secs": record.uptime_secs,
    })
    .to_string()
}
