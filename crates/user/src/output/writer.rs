use std::io::{self, Write};

use anyhow::Context;

use crate::normalize::NormalizedEvent;
use crate::output::alert::format_alert_json;
use crate::output::dispatcher::format_normalized_event_json;
use crate::output::health::{HealthRecord, format_health_json};
use crate::rules::Alert;

pub struct JsonOutput<W> {
    writer: W,
}

impl JsonOutput<io::Stdout> {
    pub fn stdout() -> Self {
        Self::new(io::stdout())
    }
}

impl<W: Write> JsonOutput<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    pub fn write_normalized(&mut self, event: &NormalizedEvent) -> anyhow::Result<()> {
        writeln!(self.writer, "{}", format_normalized_event_json(event))
            .context("failed to write normalized event JSON")
    }

    pub fn write_alert(&mut self, alert: &Alert) -> anyhow::Result<()> {
        writeln!(self.writer, "{}", format_alert_json(alert)).context("failed to write alert JSON")
    }

    pub fn write_health(&mut self, record: &HealthRecord) -> anyhow::Result<()> {
        writeln!(self.writer, "{}", format_health_json(record))
            .context("failed to write health JSON")
    }

    #[cfg(test)]
    pub fn into_inner(self) -> W {
        self.writer
    }
}
