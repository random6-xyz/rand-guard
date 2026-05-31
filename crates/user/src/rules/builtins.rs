use crate::config::{NetworkDirection, RuleAction, RuleConfig, RuleType, Severity};

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

pub fn file_operations() -> Vec<String> {
    ["file_write", "file_rename", "file_unlink"]
        .iter()
        .map(|op| op.to_string())
        .collect()
}
