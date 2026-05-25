use crate::config::types::{RuleAction, RuleConfig, RuleType};

pub fn validate_rule(rule: &RuleConfig) -> anyhow::Result<()> {
    if rule.action != RuleAction::Alert {
        anyhow::bail!("rule '{}' uses an unsupported action", rule.id);
    }

    match rule.rule_type {
        RuleType::Process => {
            if rule.process_names.is_empty() && rule.parent_names.is_empty() {
                anyhow::bail!(
                    "process rule '{}' must define process_names or parent_names",
                    rule.id
                );
            }
            if !rule.paths.is_empty()
                || !rule.patterns.is_empty()
                || !rule.operations.is_empty()
                || rule.direction.is_some()
                || !rule.ports.is_empty()
            {
                anyhow::bail!(
                    "process rule '{}' contains non-process match fields",
                    rule.id
                );
            }
        }
        RuleType::File => {
            if rule.paths.is_empty() && rule.patterns.is_empty() {
                anyhow::bail!("file rule '{}' must define paths or patterns", rule.id);
            }
            if rule.operations.is_empty() {
                anyhow::bail!("file rule '{}' must define operations", rule.id);
            }
            for op in &rule.operations {
                if !is_valid_file_operation(op) {
                    anyhow::bail!(
                        "file rule '{}' uses unrecognized operation '{}'",
                        rule.id,
                        op
                    );
                }
            }
            if !rule.parent_names.is_empty()
                || !rule.process_names.is_empty()
                || rule.direction.is_some()
                || !rule.ports.is_empty()
            {
                anyhow::bail!("file rule '{}' contains non-file match fields", rule.id);
            }
        }
        RuleType::Network => {
            if rule.direction.is_none() {
                anyhow::bail!("network rule '{}' must define direction", rule.id);
            }
            if rule.ports.is_empty() {
                anyhow::bail!("network rule '{}' must define ports", rule.id);
            }
            if !rule.parent_names.is_empty()
                || !rule.paths.is_empty()
                || !rule.patterns.is_empty()
                || !rule.operations.is_empty()
            {
                anyhow::bail!(
                    "network rule '{}' contains non-network match fields",
                    rule.id
                );
            }
        }
    }

    Ok(())
}

const VALID_FILE_OPERATIONS: &[&str] = &[
    "file_open",
    "file_write",
    "file_rename",
    "file_unlink",
    "open",
    "write",
    "rename",
    "unlink",
    "*",
];

pub fn is_valid_file_operation(op: &str) -> bool {
    VALID_FILE_OPERATIONS.contains(&op)
}

#[cfg(test)]
mod tests {
    use crate::config::types::Config;

    #[test]
    fn rejects_invalid_rule_semantics() {
        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.rules[0].process_names.clear();
        config.rules[0].parent_names.clear();

        let err = config
            .validate_current_runtime()
            .expect_err("process rules should require process or parent names");
        assert!(err.to_string().contains("process_names or parent_names"));

        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.rules[1].enabled = true;
        config.rules[1].operations.clear();

        let err = config
            .validate_current_runtime()
            .expect_err("file rules should require operations");
        assert!(err.to_string().contains("must define operations"));

        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.rules[2].enabled = true;
        config.rules[2].direction = None;

        let err = config
            .validate_current_runtime()
            .expect_err("network rules should require direction");
        assert!(err.to_string().contains("must define direction"));
    }

    #[test]
    fn rejects_unsupported_process_options() {
        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.process.hooks.push("clone".to_string());

        let err = config
            .validate_current_runtime()
            .expect_err("unsupported process hooks should be rejected");

        assert!(
            err.to_string()
                .contains("process hook 'clone' is not supported")
        );

        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.process.collect_args = true;

        let err = config
            .validate_current_runtime()
            .expect_err("unsupported process enrichment should be rejected");

        assert!(
            err.to_string()
                .contains("process argument, environment, and cwd collection")
        );
    }

    #[test]
    fn rejects_hooks_in_wrong_section() {
        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.process.hooks.push("openat".to_string());

        let err = config
            .validate_current_runtime()
            .expect_err("file hooks should be rejected in process section");
        assert!(
            err.to_string()
                .contains("process hook 'openat' is not supported")
        );

        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.file.hooks.push("execve".to_string());

        let err = config
            .validate_current_runtime()
            .expect_err("process hooks should be rejected in file section");
        assert!(
            err.to_string()
                .contains("file hook 'execve' is not supported")
        );
    }

    #[test]
    fn rejects_inconsistent_file_event_flags() {
        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.events.file = false;

        let err = config
            .validate_current_runtime()
            .expect_err("enabled file collection should require file events");
        assert!(
            err.to_string()
                .contains("file collection is enabled but file events are disabled")
        );
    }

    #[test]
    fn validates_supported_network_collection() {
        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.events.network = true;
        config.network.enabled = true;

        config
            .validate_current_runtime()
            .expect("supported network hooks should validate when consistently enabled");
    }

    #[test]
    fn rejects_unsupported_network_options() {
        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.network.hooks.push("accept".to_string());

        let err = config
            .validate_current_runtime()
            .expect_err("unsupported network hooks should be rejected");
        assert!(
            err.to_string()
                .contains("network hook 'accept' is not supported")
        );

        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.network.collect_dns = true;
        let err = config
            .validate_current_runtime()
            .expect_err("DNS collection should be rejected");
        assert!(err.to_string().contains("DNS collection is not supported"));

        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.network.collect_payload = true;
        let err = config
            .validate_current_runtime()
            .expect_err("payload collection should be rejected");
        assert!(
            err.to_string()
                .contains("network payload collection is not supported")
        );
    }

    #[test]
    fn rejects_inconsistent_network_event_flags() {
        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.events.network = true;

        let err = config
            .validate_current_runtime()
            .expect_err("enabled network events should require network collection");
        assert!(
            err.to_string()
                .contains("network events are enabled but network collection is disabled")
        );

        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.network.enabled = true;

        let err = config
            .validate_current_runtime()
            .expect_err("enabled network collection should require network events");
        assert!(
            err.to_string()
                .contains("network collection is enabled but network events are disabled")
        );
    }

    #[test]
    fn validates_detect_mode() {
        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.agent.mode = crate::config::types::AgentMode::Detect;

        config
            .validate_current_runtime()
            .expect("detect mode should validate now that alerts are emitted");
    }

    #[test]
    fn rejects_duplicate_rule_ids() {
        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.rules[0].enabled = true;
        config.rules[0].id = "DUPLICATE".to_string();
        config.rules[1].enabled = true;
        config.rules[1].id = "DUPLICATE".to_string();

        let err = config
            .validate_current_runtime()
            .expect_err("duplicate rule IDs should be rejected");
        assert!(err.to_string().contains("duplicate rule id"));
    }

    #[test]
    fn rejects_invalid_file_operation() {
        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.rules[1].enabled = true;
        config.rules[1].operations = vec!["file_opne".to_string()];

        let err = config
            .validate_current_runtime()
            .expect_err("invalid operation name should be rejected");
        assert!(err.to_string().contains("unrecognized operation"));
    }

    #[test]
    fn accepts_short_operation_aliases() {
        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.rules[1].enabled = true;
        config.rules[1].operations = vec![
            "open".to_string(),
            "write".to_string(),
            "rename".to_string(),
            "unlink".to_string(),
        ];

        config
            .validate_current_runtime()
            .expect("short operation aliases should be accepted");
    }

    #[test]
    fn accepts_wildcard_operation() {
        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.rules[1].enabled = true;
        config.rules[1].operations = vec!["*".to_string()];

        config
            .validate_current_runtime()
            .expect("wildcard operation should be accepted");
    }

    #[test]
    fn skips_validation_for_disabled_rules() {
        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.rules[0].enabled = false;
        config.rules[0].process_names.clear();
        config.rules[0].parent_names.clear();

        config
            .validate_current_runtime()
            .expect("disabled rules should skip semantic validation");
    }

    #[test]
    fn rejects_builtin_prefix_in_user_rules() {
        let mut config = Config::from_str(include_str!("../../../../config.example.toml"))
            .expect("example config should parse");
        config.rules[0].enabled = true;
        config.rules[0].id = "BUILTIN-USER-001".to_string();

        let err = config
            .validate_current_runtime()
            .expect_err("BUILTIN- prefix should be rejected in user rules");
        assert!(err.to_string().contains("reserved 'BUILTIN-' prefix"));
    }
}
