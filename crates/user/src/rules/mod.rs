mod alerts;
mod builtins;
mod engine;
mod matchers;

pub use alerts::Alert;
#[allow(unused_imports)]
pub use builtins::builtin_rules;
pub use engine::RuleEngine;
#[allow(unused_imports)]
pub use matchers::{FileFields, NetworkFields, matches_path_rule, matches_pattern};

#[cfg(test)]
mod tests {
    use crate::config::{NetworkDirection, RuleAction, RuleConfig, RuleType, Severity};
    use crate::normalize::{
        FileOpen, FileRename, FileWrite, NetworkConnect, NormalizedEvent, ProcessRelationship,
        ProcessStart,
    };
    use crate::rules::RuleEngine;
    use crate::rules::builtins::builtin_rules;
    use crate::rules::matchers::{matches_path_rule, matches_pattern};

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

    #[test]
    fn process_rule_with_parent_names_skips_process_start() {
        let engine = RuleEngine::new(&[RuleConfig {
            id: "PROC-002".to_string(),
            name: "Shell spawned by web server".to_string(),
            enabled: true,
            rule_type: RuleType::Process,
            severity: Severity::High,
            action: RuleAction::Alert,
            parent_names: vec!["nginx".to_string()],
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

        assert!(engine.evaluate(&event).is_empty());
    }

    #[test]
    fn file_alert_includes_process_name() {
        let mut rule = file_rule();
        rule.paths = vec!["/etc/shadow".to_string()];
        rule.operations = vec!["file_write".to_string()];
        let engine = RuleEngine::new(&[rule]);
        let event = NormalizedEvent::FileWrite(FileWrite {
            pid: 10,
            tid: 10,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: "tee".to_string(),
            exe_path: "/usr/bin/tee".to_string(),
            fd: 3,
            count: 100,
            resolved_path: "/etc/shadow".to_string(),
            alert: false,
            detection_type: None,
            timestamp_ns: 123,
        });

        let alerts = engine.evaluate(&event);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].process_name, Some("tee".to_string()));
        assert_eq!(alerts[0].comm, Some("tee".to_string()));
    }

    #[test]
    fn network_alert_includes_process_name() {
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
        let user_alert = alerts.iter().find(|a| a.rule_id == "NET-001").unwrap();
        assert_eq!(user_alert.process_name, Some("nc".to_string()));
    }

    #[test]
    fn matches_pattern_suffix_only() {
        assert!(matches_pattern("/etc/systemd/ssh.service", "*.service"));
        assert!(matches_pattern("backup.service", "*.service"));
        assert!(!matches_pattern("/etc/shadow", "*.service"));
    }

    #[test]
    fn matches_pattern_exact_fallback() {
        assert!(matches_pattern("/etc/crontab", "/etc/crontab"));
        assert!(!matches_pattern("/etc/crontab.bak", "/etc/crontab"));
        assert!(!matches_pattern("/v/etc/passwd", "etc"));
    }

    #[test]
    fn matches_path_rule_exact_file() {
        assert!(matches_path_rule(
            "/etc/crontab",
            &["/etc/crontab".to_string()],
            &[]
        ));
        assert!(!matches_path_rule(
            "/etc/crontab.bak",
            &["/etc/crontab".to_string()],
            &[]
        ));
        assert!(matches_path_rule(
            "/etc/crontab/back",
            &["/etc/crontab".to_string()],
            &[]
        ));
    }

    #[test]
    fn matches_path_rule_directory_prefix() {
        assert!(matches_path_rule(
            "/etc/systemd/system/ssh.service",
            &["/etc/systemd/system/".to_string()],
            &[]
        ));
        assert!(!matches_path_rule(
            "/etc/systemd_other",
            &["/etc/systemd/system/".to_string()],
            &[]
        ));
    }

    #[test]
    fn builtin_rules_validate() {
        use crate::config::validate_rule;
        for rule in builtin_rules() {
            validate_rule(&rule)
                .unwrap_or_else(|e| panic!("built-in rule '{}' should validate: {e}", rule.id));
        }
    }

    #[test]
    fn builtin_cron_rule_matches_exact_path() {
        let rules = builtin_rules();
        let _cron_rule = rules
            .iter()
            .find(|r| r.id == "BUILTIN-FILE-CRON-001")
            .unwrap();
        let engine = RuleEngine::new(&[]);
        let event = NormalizedEvent::FileWrite(FileWrite {
            pid: 10,
            tid: 10,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: "crontab".to_string(),
            exe_path: "/usr/bin/crontab".to_string(),
            fd: 3,
            count: 100,
            resolved_path: "/etc/crontab".to_string(),
            alert: false,
            detection_type: None,
            timestamp_ns: 123,
        });

        let alerts = engine.evaluate(&event);
        assert!(alerts.iter().any(|a| a.rule_id == "BUILTIN-FILE-CRON-001"));
    }

    #[test]
    fn builtin_cron_rule_does_not_match_crontab_bak() {
        let engine = RuleEngine::new(&[]);
        let event = NormalizedEvent::FileWrite(FileWrite {
            pid: 10,
            tid: 10,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: "crontab".to_string(),
            exe_path: "/usr/bin/crontab".to_string(),
            fd: 3,
            count: 100,
            resolved_path: "/etc/crontab.bak".to_string(),
            alert: false,
            detection_type: None,
            timestamp_ns: 123,
        });

        let alerts = engine.evaluate(&event);
        assert!(!alerts.iter().any(|a| a.rule_id == "BUILTIN-FILE-CRON-001"));
    }

    #[test]
    fn builtin_systemd_rule_does_not_match_file_open() {
        let engine = RuleEngine::new(&[]);
        let event = NormalizedEvent::FileOpen(FileOpen {
            pid: 10,
            tid: 10,
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: "systemctl".to_string(),
            exe_path: "/usr/bin/systemctl".to_string(),
            filename: "/etc/systemd/system/ssh.service".to_string(),
            flags: 0,
            filename_truncated: false,
            alert: false,
            detection_type: None,
            timestamp_ns: 123,
        });

        let alerts = engine.evaluate(&event);
        assert!(
            !alerts
                .iter()
                .any(|a| a.rule_id == "BUILTIN-FILE-SYSTEMD-001")
        );
    }
}
