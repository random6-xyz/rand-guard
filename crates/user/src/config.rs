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
        if self.agent.mode != AgentMode::Monitor {
            anyhow::bail!("only monitor mode is supported by the current runtime");
        }
        if !self.ebpf.enabled {
            anyhow::bail!("eBPF is disabled by config");
        }
        if !self.events.process || !self.process.enabled {
            anyhow::bail!("process event collection must be enabled for the current runtime");
        }
        let supported_hooks: &[&str] = &["execve", "fork", "exit", "execveat"];
        for hook in &self.process.hooks {
            if !supported_hooks.contains(&hook.as_str()) {
                anyhow::bail!(
                    "process hook '{}' is not supported by the current runtime",
                    hook
                );
            }
        }
        if self.process.collect_args || self.process.collect_env || self.process.collect_cwd {
            anyhow::bail!(
                "process argument, environment, and cwd collection are not supported by the current runtime"
            );
        }
        if self.events.file || self.file.enabled {
            anyhow::bail!("file event collection is not supported by the current runtime");
        }
        if self.events.network || self.network.enabled {
            anyhow::bail!("network event collection is not supported by the current runtime");
        }
        if self.rules.iter().any(|rule| rule.enabled) {
            anyhow::bail!("detection rules are not supported by the current runtime");
        }
        if self.output.output_type != OutputType::Stdout {
            anyhow::bail!("only stdout output is supported by the current runtime");
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub id: String,
    pub mode: AgentMode,
    pub log_level: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Deserialize, PartialEq, Eq)]
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
    pub operations: Vec<String>,
    #[serde(default)]
    pub direction: Option<NetworkDirection>,
    #[serde(default)]
    pub ports: Vec<u16>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleType {
    Process,
    File,
    Network,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Alert,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
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
        assert!(!config.events.file);
        assert!(!config.events.network);
        assert_eq!(config.process.hooks, ["execve", "fork", "exit", "execveat"]);
        assert!(!config.process.collect_args);
        assert!(!config.process.collect_env);
        assert!(!config.process.collect_cwd);
        assert_eq!(config.file.watch_paths, ["/etc", "/usr/bin", "/bin"]);
        assert_eq!(config.network.hooks, ["connect"]);
        assert_eq!(config.rules.len(), 3);
        assert!(config.rules.iter().all(|rule| !rule.enabled));
        assert_eq!(config.rules[0].rule_type, RuleType::Process);
        assert_eq!(
            config.rules[1].paths,
            ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
        );
        assert_eq!(config.rules[2].direction, Some(NetworkDirection::Outbound));
        assert_eq!(config.rules[2].ports, [4444, 1337, 31337]);
        assert_eq!(config.output.output_type, OutputType::Stdout);
        assert_eq!(config.performance.max_events_per_second, 5000);
        config
            .validate_current_runtime()
            .expect("example config should match current runtime support");
    }

    #[test]
    fn rejects_unsupported_enabled_rules() {
        let mut config = Config::from_str(include_str!("../../../config.example.toml"))
            .expect("example config should parse");
        config.rules[0].enabled = true;

        let err = config
            .validate_current_runtime()
            .expect_err("enabled rules should be rejected until rule engine exists");

        assert!(
            err.to_string()
                .contains("detection rules are not supported")
        );
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
    fn rejects_detect_mode_until_rules_are_supported() {
        let mut config = Config::from_str(include_str!("../../../config.example.toml"))
            .expect("example config should parse");
        config.agent.mode = AgentMode::Detect;

        let err = config
            .validate_current_runtime()
            .expect_err("detect mode should be rejected until rule engine exists");

        assert!(err.to_string().contains("only monitor mode is supported"));
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
