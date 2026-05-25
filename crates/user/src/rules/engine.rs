use crate::config::{RuleConfig, RuleType};
use crate::normalize::NormalizedEvent;
use crate::rules::alerts::{
    Alert, file_alert, network_alert, process_relationship_alert, process_start_alert,
};
use crate::rules::matchers::{
    FileFields, NetworkFields, matches_name, matches_operation, matches_path_rule,
};

pub struct RuleEngine {
    rules: Vec<RuleConfig>,
}

impl RuleEngine {
    pub fn new(config_rules: &[RuleConfig]) -> Self {
        let mut rules = crate::rules::builtins::builtin_rules();
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
