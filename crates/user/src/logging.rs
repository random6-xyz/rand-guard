use anyhow::{Context, anyhow};
use tracing_subscriber::EnvFilter;

pub fn init(default_filter: &str) -> anyhow::Result<()> {
    let rust_log = std::env::var("RUST_LOG").ok();
    let filter = env_filter_from(rust_log.as_deref(), default_filter)
        .context("failed to parse log filter")?;

    tracing_log::LogTracer::init()
        .map_err(|error| anyhow!(error))
        .context("failed to initialize log bridge")?;

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .compact()
        .try_init()
        .map_err(|error| anyhow!(error))
        .context("failed to initialize logging")
}

fn env_filter_from(
    value: Option<&str>,
    default_filter: &str,
) -> Result<EnvFilter, tracing_subscriber::filter::ParseError> {
    match value {
        Some(value) if !value.trim().is_empty() => EnvFilter::try_new(value),
        _ => EnvFilter::try_new(default_filter),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_default_filter_when_rust_log_is_absent() {
        assert!(env_filter_from(None, "info").is_ok());
        assert!(env_filter_from(Some(""), "debug").is_ok());
        assert!(env_filter_from(Some("   "), "warn").is_ok());
    }

    #[test]
    fn rejects_invalid_default_filter() {
        assert!(env_filter_from(None, "edr_user=notalevel").is_err());
    }

    #[test]
    fn rejects_invalid_filter() {
        assert!(env_filter_from(Some("edr_user=notalevel"), "info").is_err());
    }
}
