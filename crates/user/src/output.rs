use std::io::{self, Write};

use anyhow::Context;
use edr_common::{EVENT_FLAG_FILENAME_TRUNCATED, ProcessExecEvent};

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

    pub fn write_process_exec(&mut self, event: &ProcessExecEvent) -> anyhow::Result<()> {
        writeln!(self.writer, "{}", format_process_exec_event_json(event))
            .context("failed to write process exec event JSON")
    }

    #[cfg(test)]
    fn into_inner(self) -> W {
        self.writer
    }
}

pub fn format_process_exec_event_json(event: &ProcessExecEvent) -> String {
    let comm = fixed_string(&event.comm, event.comm.len());
    let filename_len = usize::from(event.filename_len).min(event.filename.len());
    let filename = fixed_string(&event.filename, filename_len);

    serde_json::json!({
        "event_type": "process_exec",
        "timestamp_ns": event.header.timestamp_ns,
        "pid": event.header.pid,
        "tid": event.header.tid,
        "ppid": event.header.ppid,
        "uid": event.header.uid,
        "gid": event.header.gid,
        "comm": comm,
        "filename": filename,
        "filename_truncated": event.header.flags & EVENT_FLAG_FILENAME_TRUNCATED != 0,
    })
    .to_string()
}

fn fixed_string(bytes: &[u8], max_len: usize) -> String {
    let len = bytes[..max_len]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(max_len);

    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use edr_common::{EVENT_SCHEMA_VERSION, EventKind};

    #[test]
    fn formats_process_exec_event_as_json() {
        let event = sample_process_exec_event();

        let value: serde_json::Value =
            serde_json::from_str(&format_process_exec_event_json(&event))
                .expect("process exec event output should be valid JSON");

        assert_eq!(value["event_type"], "process_exec");
        assert_eq!(value["timestamp_ns"], 123);
        assert_eq!(value["pid"], 100);
        assert_eq!(value["tid"], 101);
        assert_eq!(value["ppid"], 1);
        assert_eq!(value["uid"], 1000);
        assert_eq!(value["gid"], 1000);
        assert_eq!(value["comm"], "bash");
        assert_eq!(value["filename"], "/usr/bin/bash");
        assert_eq!(value["filename_truncated"], true);
    }

    #[test]
    fn writes_json_line_to_writer() {
        let event = sample_process_exec_event();
        let mut output = JsonOutput::new(Vec::new());

        output
            .write_process_exec(&event)
            .expect("JSON event write should succeed");

        let line = String::from_utf8(output.into_inner()).expect("JSON output should be UTF-8");
        assert!(line.ends_with('\n'));

        let value: serde_json::Value = serde_json::from_str(line.trim_end())
            .expect("written process exec event should be valid JSON");
        assert_eq!(value["event_type"], "process_exec");
        assert_eq!(value["filename"], "/usr/bin/bash");
    }

    #[test]
    fn caps_filename_len_to_buffer_size() {
        let mut event = sample_process_exec_event();
        event.filename_len = u16::MAX;

        let value: serde_json::Value =
            serde_json::from_str(&format_process_exec_event_json(&event))
                .expect("process exec event output should be valid JSON");

        assert_eq!(value["filename"], "/usr/bin/bash");
    }

    fn sample_process_exec_event() -> ProcessExecEvent {
        let mut event = ProcessExecEvent::default();
        event.header.kind = EventKind::ProcessExec.as_u16();
        event.header.version = EVENT_SCHEMA_VERSION;
        event.header.size = ProcessExecEvent::SIZE;
        event.header.flags = EVENT_FLAG_FILENAME_TRUNCATED;
        event.header.timestamp_ns = 123;
        event.header.pid = 100;
        event.header.tid = 101;
        event.header.ppid = 1;
        event.header.uid = 1000;
        event.header.gid = 1000;
        event.comm[..4].copy_from_slice(b"bash");
        event.filename[..13].copy_from_slice(b"/usr/bin/bash");
        event.filename_len = 13;
        event
    }
}
