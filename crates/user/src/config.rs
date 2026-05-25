use std::{fs, path::Path};

use anyhow::Context;
use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub agent: AgentConfig,
    pub ebpf: EbpfConfig,
    pub events: EventsConfig,
    pub process: ProcessConfig,
    pub file: FileConfig,
    pub network: NetworkConfig,
    pub rules: Vec<RuleConfig>,
    #[serde(default)]
    pub detections: DetectionsConfig,
    pub output: OutputConfig,
    pub performance: PerformanceConfig,
}

impl Config {
    pub fn from_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read config from {}", path.display()))?;

        Self::from_str(&contents)
            .with_context(|| format!("failed to parse config from {}", path.display()))
    }

    pub fn from_str(contents: &str) -> anyhow::Result<Self> {
        toml::from_str(contents).context("invalid TOML config")
    }

    pub fn validate_current_runtime(&self) -> anyhow::Result<()> {
        if !self.ebpf.enabled {
            anyhow::bail!("eBPF is disabled by config");
        }
        if !self.events.process || !self.process.enabled {
            anyhow::bail!("process event collection must be enabled for the current runtime");
        }
        let supported_process_hooks: &[&str] = &["execve", "fork", "exit", "execveat"];
        let supported_file_hooks: &[&str] = &[
            "openat",
            "openat2",
            "write",
            "writev",
            "pwrite64",
            "rename",
            "renameat",
            "renameat2",
            "unlink",
            "unlinkat",
        ];
        let supported_network_hooks: &[&str] = &["connect", "bind", "listen"];
        for hook in &self.process.hooks {
            if !supported_process_hooks.contains(&hook.as_str()) {
                anyhow::bail!(
                    "process hook '{}' is not supported by the current runtime",
                    hook
                );
            }
        }
        for hook in &self.file.hooks {
            if !supported_file_hooks.contains(&hook.as_str()) {
                anyhow::bail!(
                    "file hook '{}' is not supported by the current runtime",
                    hook
                );
            }
        }
        if self.process.collect_args || self.process.collect_env || self.process.collect_cwd {
            anyhow::bail!(
                "process argument, environment, and cwd collection are not supported by the current runtime"
            );
        }
        if self.events.file && !self.file.enabled {
            anyhow::bail!("file events are enabled but file collection is disabled");
        }
        if self.file.enabled && !self.events.file {
            anyhow::bail!("file collection is enabled but file events are disabled");
        }
        for hook in &self.network.hooks {
            if !supported_network_hooks.contains(&hook.as_str()) {
                anyhow::bail!(
                    "network hook '{}' is not supported by the current runtime",
                    hook
                );
            }
        }
        if self.events.network && !self.network.enabled {
            anyhow::bail!("network events are enabled but network collection is disabled");
        }
        if self.network.enabled && !self.events.network {
            anyhow::bail!("network collection is enabled but network events are disabled");
        }
        if self.network.collect_dns {
            anyhow::bail!("DNS collection is not supported by the current runtime");
        }
        if self.network.collect_payload {
            anyhow::bail!("network payload collection is not supported by the current runtime");
        }
        for rule in &self.rules {
            validate_rule(rule)?;
        }
        if self.output.output_type != OutputType::Stdout {
            anyhow::bail!("only stdout output is supported by the current runtime");
        }

        Ok(())
    }
}

fn validate_rule(rule: &RuleConfig) -> anyhow::Result<()> {
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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub id: String,
    pub mode: AgentMode,
    pub log_level: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentMode {
    Monitor,
    Detect,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EbpfConfig {
    pub enabled: bool,
    pub buffer_size: u32,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EventsConfig {
    pub process: bool,
    pub file: bool,
    pub network: bool,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessConfig {
    pub enabled: bool,
    pub hooks: Vec<String>,
    pub collect_args: bool,
    pub collect_env: bool,
    pub collect_cwd: bool,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub enabled: bool,
    pub hooks: Vec<String>,
    pub watch_paths: Vec<String>,
    #[serde(default)]
    pub watch_patterns: Vec<String>,
    pub exclude_paths: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub enabled: bool,
    pub hooks: Vec<String>,
    pub collect_dns: bool,
    pub collect_payload: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    #[serde(rename = "type")]
    pub rule_type: RuleType,
    pub severity: Severity,
    pub action: RuleAction,
    #[serde(default)]
    pub parent_names: Vec<String>,
    #[serde(default)]
    pub process_names: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub direction: Option<NetworkDirection>,
    #[serde(default)]
    pub ports: Vec<u16>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleType {
    Process,
    File,
    Network,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Alert,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutputConfig {
    #[serde(rename = "type")]
    pub output_type: OutputType,
    pub format: OutputFormat,
    pub path: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputType {
    File,
    Stdout,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Json,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PerformanceConfig {
    pub max_events_per_second: u32,
    pub drop_when_full: bool,
}

#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DetectionsConfig {
    #[serde(default)]
    pub persistence: Vec<PersistenceRule>,
    #[serde(default)]
    pub network: Vec<NetworkDetectionRule>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PersistenceRule {
    pub name: String,
    pub paths: Vec<String>,
    #[serde(default)]
    pub patterns: Vec<String>,
    pub operations: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkDetectionRule {
    pub name: String,
    pub directions: Vec<NetworkDirection>,
    pub ports: Vec<u16>,
    #[serde(default)]
    pub process_names: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_config() {
        let config = Config::from_str(include_str!("../../../config.example.toml"))
            .expect("example config should parse");

        assert_eq!(config.agent.id, "dev-host-001");
        assert_eq!(config.agent.mode, AgentMode::Monitor);
        assert!(config.ebpf.enabled);
        assert_eq!(config.ebpf.buffer_size, 8192);
        assert!(config.events.process);
        assert!(config.events.file);
        assert!(!config.events.network);
        assert_eq!(config.process.hooks, ["execve", "fork", "exit", "execveat"]);
        assert!(!config.process.collect_args);
        assert!(!config.process.collect_env);
        assert!(!config.process.collect_cwd);
        assert_eq!(config.file.watch_paths, ["/etc", "/usr/bin", "/bin"]);
        assert_eq!(config.network.hooks, ["connect", "bind", "listen"]);
        assert_eq!(config.rules.len(), 3);
        assert!(config.rules[0].enabled);
        assert_eq!(config.rules[0].rule_type, RuleType::Process);
        assert_eq!(
            config.rules[1].paths,
            ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
        );
        assert_eq!(config.rules[2].direction, Some(NetworkDirection::Outbound));
        assert_eq!(config.rules[2].ports, [4444, 1337, 31337]);
        assert_eq!(config.detections.network.len(), 1);
        assert_eq!(
            config.detections.network[0].name,
            "suspicious_outbound_port"
        );
        assert_eq!(
            config.detections.network[0].directions,
            [NetworkDirection::Outbound]
        );
        assert_eq!(config.detections.network[0].ports, [4444, 1337, 31337]);
        assert_eq!(config.output.output_type, OutputType::Stdout);
        assert_eq!(config.performance.max_events_per_second, 5000);
        config
            .validate_current_runtime()
            .expect("example config should match current runtime support");
    }

    #[test]
    fn defaults_new_optional_file_config_fields() {
        let config = Config::from_str(
            r#"
            rules = []

            [agent]
            id = "dev-host-001"
            mode = "monitor"
            log_level = "info"

            [ebpf]
            enabled = true
            buffer_size = 8192

            [events]
            process = true
            file = true
            network = false

            [process]
            enabled = true
            hooks = ["execve", "fork", "exit", "execveat"]
            collect_args = false
            collect_env = false
            collect_cwd = false

            [file]
            enabled = true
            hooks = ["openat"]
            watch_paths = ["/tmp"]
            exclude_paths = []

            [network]
            enabled = false
            hooks = ["connect"]
            collect_dns = false
            collect_payload = false

            [output]
            type = "stdout"
            format = "json"

            [performance]
            max_events_per_second = 5000
            drop_when_full = true
            "#,
        )
        .expect("new optional config fields should default when omitted");

        assert!(config.file.watch_patterns.is_empty());
        assert!(config.detections.persistence.is_empty());
        config
            .validate_current_runtime()
            .expect("config with omitted optional fields should validate");
    }

    #[test]
    fn validates_enabled_rules() {
        let mut config = Config::from_str(include_str!("../../../config.example.toml"))
            .expect("example config should parse");
        config.rules.iter_mut().for_each(|rule| rule.enabled = true);

        config
            .validate_current_runtime()
            .expect("enabled MVP rules should validate");
    }

    #[test]
    fn rejects_invalid_rule_semantics() {
        let mut config = Config::from_str(include_str!("../../../config.example.toml"))
            .expect("example config should parse");
        config.rules[0].process_names.clear();
        config.rules[0].parent_names.clear();

        let err = config
            .validate_current_runtime()
            .expect_err("process rules should require process or parent names");
        assert!(err.to_string().contains("process_names or parent_names"));

        let mut config = Config::from_str(include_str!("../../../config.example.toml"))
            .expect("example config should parse");
        config.rules[1].operations.clear();

        let err = config
            .validate_current_runtime()
            .expect_err("file rules should require operations");
        assert!(err.to_string().contains("must define operations"));

        let mut config = Config::from_str(include_str!("../../../config.example.toml"))
            .expect("example config should parse");
        config.rules[2].direction = None;

        let err = config
            .validate_current_runtime()
            .expect_err("network rules should require direction");
        assert!(err.to_string().contains("must define direction"));
    }

    #[test]
    fn rejects_unsupported_process_options() {
        let mut config = Config::from_str(include_str!("../../../config.example.toml"))
            .expect("example config should parse");
        config.process.hooks.push("clone".to_string());

        let err = config
            .validate_current_runtime()
            .expect_err("unsupported process hooks should be rejected");

        assert!(
            err.to_string()
                .contains("process hook 'clone' is not supported")
        );

        let mut config = Config::from_str(include_str!("../../../config.example.toml"))
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
        let mut config = Config::from_str(include_str!("../../../config.example.toml"))
            .expect("example config should parse");
        config.process.hooks.push("openat".to_string());

        let err = config
            .validate_current_runtime()
            .expect_err("file hooks should be rejected in process section");
        assert!(
            err.to_string()
                .contains("process hook 'openat' is not supported")
        );

        let mut config = Config::from_str(include_str!("../../../config.example.toml"))
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
        let mut config = Config::from_str(include_str!("../../../config.example.toml"))
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
        let mut config = Config::from_str(include_str!("../../../config.example.toml"))
            .expect("example config should parse");
        config.events.network = true;
        config.network.enabled = true;

        config
            .validate_current_runtime()
            .expect("supported network hooks should validate when consistently enabled");
    }

    #[test]
    fn rejects_unsupported_network_options() {
        let mut config = Config::from_str(include_str!("../../../config.example.toml"))
            .expect("example config should parse");
        config.network.hooks.push("accept".to_string());

        let err = config
            .validate_current_runtime()
            .expect_err("unsupported network hooks should be rejected");
        assert!(
            err.to_string()
                .contains("network hook 'accept' is not supported")
        );

        let mut config = Config::from_str(include_str!("../../../config.example.toml"))
            .expect("example config should parse");
        config.network.collect_dns = true;
        let err = config
            .validate_current_runtime()
            .expect_err("DNS collection should be rejected");
        assert!(err.to_string().contains("DNS collection is not supported"));

        let mut config = Config::from_str(include_str!("../../../config.example.toml"))
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
        let mut config = Config::from_str(include_str!("../../../config.example.toml"))
            .expect("example config should parse");
        config.events.network = true;

        let err = config
            .validate_current_runtime()
            .expect_err("enabled network events should require network collection");
        assert!(
            err.to_string()
                .contains("network events are enabled but network collection is disabled")
        );

        let mut config = Config::from_str(include_str!("../../../config.example.toml"))
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
        let mut config = Config::from_str(include_str!("../../../config.example.toml"))
            .expect("example config should parse");
        config.agent.mode = AgentMode::Detect;

        config
            .validate_current_runtime()
            .expect("detect mode should validate now that alerts are emitted");
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = Config::from_str(
            r#"
            [agent]
            id = "dev-host-001"
            mode = "monitor"
            log_level = "info"
            unexpected = true

            [ebpf]
            enabled = true
            buffer_size = 8192

            [events]
            process = true
            file = true
            network = true

            [process]
            enabled = true
            hooks = ["execve"]
            collect_args = true
            collect_env = false
            collect_cwd = true

            [file]
            enabled = true
            hooks = ["openat"]
            watch_paths = ["/etc"]
            exclude_paths = ["/tmp"]

            [network]
            enabled = true
            hooks = ["connect"]
            collect_dns = false
            collect_payload = false

            [output]
            type = "stdout"
            format = "json"

            [performance]
            max_events_per_second = 5000
            drop_when_full = true
            "#,
        )
        .expect_err("unknown fields should be rejected");

        assert!(err.to_string().contains("invalid TOML config"));
    }
}
