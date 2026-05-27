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
    pub rss_kb: Option<u64>,
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
        "rss_kb": record.rss_kb,
    })
    .to_string()
}

pub fn read_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    parse_rss_kb(&status)
}

fn parse_rss_kb(status: &str) -> Option<u64> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let trimmed = rest.trim();
            if let Some(kb_str) = trimmed.strip_suffix("kB") {
                return kb_str.trim().parse().ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rss_from_proc_status() {
        let sample = "\
Name:\tedr-user
Umask:\t0022
State:\tS (sleeping)
VmPeak:\t   12345 kB
VmSize:\t   11000 kB
VmRSS:\t    8192 kB
VmData:\t    4096 kB
";
        assert_eq!(parse_rss_kb(sample), Some(8192));
    }

    #[test]
    fn returns_none_when_rss_missing() {
        let sample = "Name:\tedr-user\nState:\tS (sleeping)\n";
        assert_eq!(parse_rss_kb(sample), None);
    }
}
