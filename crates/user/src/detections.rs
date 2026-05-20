use crate::config::PersistenceRule;

/// Check whether a file operation matches any configured persistence rule.
///
/// `operation` should be a canonical operation name such as `file_open`,
/// `file_write`, `file_rename`, or `file_unlink`.
pub fn check_persistence(path: &str, operation: &str, rules: &[PersistenceRule]) -> Option<String> {
    for rule in rules {
        let op_match = rule
            .operations
            .iter()
            .any(|op| op == operation || op == "*");
        if !op_match {
            continue;
        }

        let has_paths = !rule.paths.is_empty();
        let has_patterns = !rule.patterns.is_empty();

        let matches_path = rule.paths.iter().any(|p| path.starts_with(p));
        let matches_pattern = rule.patterns.iter().any(|pat| {
            if let Some(suffix) = pat.strip_prefix("*.") {
                path.ends_with(&format!(".{suffix}"))
            } else {
                path.contains(pat.as_str())
            }
        });

        let matched = if has_paths && has_patterns {
            matches_path && matches_pattern
        } else if has_paths {
            matches_path
        } else if has_patterns {
            matches_pattern
        } else {
            false
        };

        if matched {
            return Some(rule.name.clone());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(
        name: &str,
        paths: &[&str],
        patterns: &[&str],
        operations: &[&str],
    ) -> PersistenceRule {
        PersistenceRule {
            name: name.to_string(),
            paths: paths.iter().map(|s| s.to_string()).collect(),
            patterns: patterns.iter().map(|s| s.to_string()).collect(),
            operations: operations.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn detects_systemd_service_modification() {
        let rules = vec![make_rule(
            "systemd_service_modified",
            &["/etc/systemd/system/"],
            &["*.service"],
            &["file_open"],
        )];

        assert_eq!(
            check_persistence("/etc/systemd/system/foo.service", "file_open", &rules),
            Some("systemd_service_modified".to_string())
        );
    }

    #[test]
    fn wildcard_extension_requires_dot_suffix() {
        let rules = vec![make_rule(
            "systemd_service_modified",
            &[],
            &["*.service"],
            &["file_open"],
        )];

        assert_eq!(
            check_persistence("/etc/systemd/system/fooservice", "file_open", &rules),
            None
        );
        assert_eq!(
            check_persistence("/etc/systemd/system/foo.service", "file_open", &rules),
            Some("systemd_service_modified".to_string())
        );
    }

    #[test]
    fn misses_non_matching_path() {
        let rules = vec![make_rule(
            "systemd_service_modified",
            &["/etc/systemd/system/"],
            &["*.service"],
            &["file_open"],
        )];

        assert_eq!(
            check_persistence("/tmp/foo.service", "file_open", &rules),
            None
        );
    }

    #[test]
    fn misses_non_matching_operation() {
        let rules = vec![make_rule(
            "systemd_service_modified",
            &["/etc/systemd/system/"],
            &["*.service"],
            &["file_write"],
        )];

        assert_eq!(
            check_persistence("/etc/systemd/system/foo.service", "file_open", &rules),
            None
        );
    }

    #[test]
    fn wildcard_operation_matches_any() {
        let rules = vec![make_rule("cron_modified", &["/etc/crontab"], &[], &["*"])];

        assert_eq!(
            check_persistence("/etc/crontab", "file_unlink", &rules),
            Some("cron_modified".to_string())
        );
    }
}
