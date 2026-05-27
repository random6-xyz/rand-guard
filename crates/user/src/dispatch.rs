use edr_common::{
    EVENT_SCHEMA_VERSION, EventKind, ExecSyscallEvent, FileOpenAt2Event, FileOpenEvent,
    FilePWrite64Event, FileRenameAt2Event, FileRenameAtEvent, FileRenameEvent, FileUnlinkAtEvent,
    FileUnlinkEvent, FileWriteEvent, FileWriteVEvent, NetworkBindEvent, NetworkConnectEvent,
    NetworkListenEvent, ProcessExecEvent, ProcessExitEvent, ProcessForkEvent,
};

use crate::config::{FileConfig, NetworkDetectionRule, PersistenceRule};
use crate::normalize::NormalizedEvent;
use crate::process_table::ProcessTable;

pub enum DispatchResult {
    Normalized(NormalizedEvent),
    Filtered,
    InvalidSchema,
    Unsupported,
    Internal,
}

pub struct DispatchContext<'a> {
    pub table: &'a mut ProcessTable,
    pub file_config: Option<&'a FileConfig>,
    pub persistence_detections: &'a [PersistenceRule],
    pub network_detections: &'a [NetworkDetectionRule],
    pub ci_smoke: bool,
    pub ci_smoke_start_seen: &'a mut bool,
    pub ci_smoke_rel_or_exit_seen: &'a mut bool,
    pub ci_smoke_file_open_seen: &'a mut bool,
}

pub fn dispatch_event(bytes: &[u8], ctx: &mut DispatchContext<'_>) -> DispatchResult {
    if bytes.len() < core::mem::size_of::<edr_common::EventHeader>() {
        return DispatchResult::InvalidSchema;
    }

    let header =
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const edr_common::EventHeader) };

    if header.version != EVENT_SCHEMA_VERSION {
        return DispatchResult::InvalidSchema;
    }

    let normalized = match header.kind {
        k if k == EventKind::ProcessExec.as_u16() => {
            if bytes.len() >= core::mem::size_of::<ProcessExecEvent>()
                && header.size as usize == core::mem::size_of::<ProcessExecEvent>()
            {
                let event =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const ProcessExecEvent) };
                Some(crate::normalize::normalize_exec(&event, ctx.table))
            } else {
                return DispatchResult::InvalidSchema;
            }
        }
        k if k == EventKind::ProcessFork.as_u16() => {
            if bytes.len() >= core::mem::size_of::<ProcessForkEvent>()
                && header.size as usize == core::mem::size_of::<ProcessForkEvent>()
            {
                let event =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const ProcessForkEvent) };
                Some(crate::normalize::normalize_fork(&event, ctx.table))
            } else {
                return DispatchResult::InvalidSchema;
            }
        }
        k if k == EventKind::ProcessExit.as_u16() => {
            if bytes.len() >= core::mem::size_of::<ProcessExitEvent>()
                && header.size as usize == core::mem::size_of::<ProcessExitEvent>()
            {
                let event =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const ProcessExitEvent) };
                Some(crate::normalize::normalize_exit(&event, ctx.table))
            } else {
                return DispatchResult::InvalidSchema;
            }
        }
        k if k == EventKind::ExecSyscall.as_u16() => {
            if bytes.len() >= core::mem::size_of::<ExecSyscallEvent>()
                && header.size as usize == core::mem::size_of::<ExecSyscallEvent>()
            {
                let event =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const ExecSyscallEvent) };
                crate::normalize::normalize_exec_syscall(&event, ctx.table);
            }
            return DispatchResult::Internal;
        }
        k if k == EventKind::FileOpen.as_u16() => {
            if bytes.len() >= core::mem::size_of::<FileOpenEvent>()
                && header.size as usize == core::mem::size_of::<FileOpenEvent>()
            {
                let event =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const FileOpenEvent) };
                crate::normalize::normalize_file_open(
                    &event,
                    ctx.table,
                    ctx.file_config,
                    ctx.persistence_detections,
                )
            } else {
                return DispatchResult::InvalidSchema;
            }
        }
        k if k == EventKind::FileOpenAt2.as_u16() => {
            if bytes.len() >= core::mem::size_of::<FileOpenAt2Event>()
                && header.size as usize == core::mem::size_of::<FileOpenAt2Event>()
            {
                let event =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const FileOpenAt2Event) };
                crate::normalize::normalize_file_openat2(
                    &event,
                    ctx.table,
                    ctx.file_config,
                    ctx.persistence_detections,
                )
            } else {
                return DispatchResult::InvalidSchema;
            }
        }
        k if k == EventKind::FileWrite.as_u16() => {
            if bytes.len() >= core::mem::size_of::<FileWriteEvent>()
                && header.size as usize == core::mem::size_of::<FileWriteEvent>()
            {
                let event =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const FileWriteEvent) };
                crate::normalize::normalize_file_write(
                    &event,
                    ctx.table,
                    ctx.file_config,
                    ctx.persistence_detections,
                )
            } else {
                return DispatchResult::InvalidSchema;
            }
        }
        k if k == EventKind::FileWriteV.as_u16() => {
            if bytes.len() >= core::mem::size_of::<FileWriteVEvent>()
                && header.size as usize == core::mem::size_of::<FileWriteVEvent>()
            {
                let event =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const FileWriteVEvent) };
                crate::normalize::normalize_file_writev(
                    &event,
                    ctx.table,
                    ctx.file_config,
                    ctx.persistence_detections,
                )
            } else {
                return DispatchResult::InvalidSchema;
            }
        }
        k if k == EventKind::FilePWrite64.as_u16() => {
            if bytes.len() >= core::mem::size_of::<FilePWrite64Event>()
                && header.size as usize == core::mem::size_of::<FilePWrite64Event>()
            {
                let event = unsafe {
                    core::ptr::read_unaligned(bytes.as_ptr() as *const FilePWrite64Event)
                };
                crate::normalize::normalize_file_pwrite64(
                    &event,
                    ctx.table,
                    ctx.file_config,
                    ctx.persistence_detections,
                )
            } else {
                return DispatchResult::InvalidSchema;
            }
        }
        k if k == EventKind::FileRename.as_u16() => {
            if bytes.len() >= core::mem::size_of::<FileRenameEvent>()
                && header.size as usize == core::mem::size_of::<FileRenameEvent>()
            {
                let event =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const FileRenameEvent) };
                crate::normalize::normalize_file_rename(
                    &event,
                    ctx.table,
                    ctx.file_config,
                    ctx.persistence_detections,
                )
            } else {
                return DispatchResult::InvalidSchema;
            }
        }
        k if k == EventKind::FileRenameAt.as_u16() => {
            if bytes.len() >= core::mem::size_of::<FileRenameAtEvent>()
                && header.size as usize == core::mem::size_of::<FileRenameAtEvent>()
            {
                let event = unsafe {
                    core::ptr::read_unaligned(bytes.as_ptr() as *const FileRenameAtEvent)
                };
                crate::normalize::normalize_file_renameat(
                    &event,
                    ctx.table,
                    ctx.file_config,
                    ctx.persistence_detections,
                )
            } else {
                return DispatchResult::InvalidSchema;
            }
        }
        k if k == EventKind::FileRenameAt2.as_u16() => {
            if bytes.len() >= core::mem::size_of::<FileRenameAt2Event>()
                && header.size as usize == core::mem::size_of::<FileRenameAt2Event>()
            {
                let event = unsafe {
                    core::ptr::read_unaligned(bytes.as_ptr() as *const FileRenameAt2Event)
                };
                crate::normalize::normalize_file_renameat2(
                    &event,
                    ctx.table,
                    ctx.file_config,
                    ctx.persistence_detections,
                )
            } else {
                return DispatchResult::InvalidSchema;
            }
        }
        k if k == EventKind::FileUnlink.as_u16() => {
            if bytes.len() >= core::mem::size_of::<FileUnlinkEvent>()
                && header.size as usize == core::mem::size_of::<FileUnlinkEvent>()
            {
                let event =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const FileUnlinkEvent) };
                crate::normalize::normalize_file_unlink(
                    &event,
                    ctx.table,
                    ctx.file_config,
                    ctx.persistence_detections,
                )
            } else {
                return DispatchResult::InvalidSchema;
            }
        }
        k if k == EventKind::FileUnlinkAt.as_u16() => {
            if bytes.len() >= core::mem::size_of::<FileUnlinkAtEvent>()
                && header.size as usize == core::mem::size_of::<FileUnlinkAtEvent>()
            {
                let event = unsafe {
                    core::ptr::read_unaligned(bytes.as_ptr() as *const FileUnlinkAtEvent)
                };
                crate::normalize::normalize_file_unlinkat(
                    &event,
                    ctx.table,
                    ctx.file_config,
                    ctx.persistence_detections,
                )
            } else {
                return DispatchResult::InvalidSchema;
            }
        }
        k if k == EventKind::NetworkConnect.as_u16() => {
            if bytes.len() >= core::mem::size_of::<NetworkConnectEvent>()
                && header.size as usize == core::mem::size_of::<NetworkConnectEvent>()
            {
                let event = unsafe {
                    core::ptr::read_unaligned(bytes.as_ptr() as *const NetworkConnectEvent)
                };
                crate::normalize::normalize_network_connect(
                    &event,
                    ctx.table,
                    ctx.network_detections,
                )
            } else {
                return DispatchResult::InvalidSchema;
            }
        }
        k if k == EventKind::NetworkBind.as_u16() => {
            if bytes.len() >= core::mem::size_of::<NetworkBindEvent>()
                && header.size as usize == core::mem::size_of::<NetworkBindEvent>()
            {
                let event =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const NetworkBindEvent) };
                crate::normalize::normalize_network_bind(&event, ctx.table, ctx.network_detections)
            } else {
                return DispatchResult::InvalidSchema;
            }
        }
        k if k == EventKind::NetworkListen.as_u16() => {
            if bytes.len() >= core::mem::size_of::<NetworkListenEvent>()
                && header.size as usize == core::mem::size_of::<NetworkListenEvent>()
            {
                let event = unsafe {
                    core::ptr::read_unaligned(bytes.as_ptr() as *const NetworkListenEvent)
                };
                crate::normalize::normalize_network_listen(
                    &event,
                    ctx.table,
                    ctx.network_detections,
                )
            } else {
                return DispatchResult::InvalidSchema;
            }
        }
        _ => return DispatchResult::Unsupported,
    };

    match normalized {
        Some(event) => {
            if ctx.ci_smoke {
                match &event {
                    NormalizedEvent::ProcessStart(_) => *ctx.ci_smoke_start_seen = true,
                    NormalizedEvent::ProcessRelationship(_) | NormalizedEvent::ProcessExit(_) => {
                        *ctx.ci_smoke_rel_or_exit_seen = true
                    }
                    NormalizedEvent::FileOpen(_) => *ctx.ci_smoke_file_open_seen = true,
                    _ => {}
                }
            }
            DispatchResult::Normalized(event)
        }
        None => DispatchResult::Filtered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edr_common::{
        EVENT_SCHEMA_VERSION, EventKind, ExecSource, ExecSyscallEvent, FileOpenEvent,
        ProcessExecEvent,
    };

    struct TestHarness {
        table: ProcessTable,
        start_seen: bool,
        rel_seen: bool,
        file_seen: bool,
    }

    impl TestHarness {
        fn new() -> Self {
            Self {
                table: ProcessTable::new(),
                start_seen: false,
                rel_seen: false,
                file_seen: false,
            }
        }

        fn ctx<'a>(&'a mut self, file_config: Option<&'a FileConfig>) -> DispatchContext<'a> {
            DispatchContext {
                table: &mut self.table,
                file_config,
                persistence_detections: &[],
                network_detections: &[],
                ci_smoke: false,
                ci_smoke_start_seen: &mut self.start_seen,
                ci_smoke_rel_or_exit_seen: &mut self.rel_seen,
                ci_smoke_file_open_seen: &mut self.file_seen,
            }
        }
    }

    #[test]
    fn too_short_bytes_returns_invalid_schema() {
        let mut h = TestHarness::new();
        let mut ctx = h.ctx(None);
        let result = dispatch_event(&[0u8; 4], &mut ctx);
        assert!(matches!(result, DispatchResult::InvalidSchema));
    }

    #[test]
    fn wrong_version_returns_invalid_schema() {
        let mut h = TestHarness::new();
        let mut ctx = h.ctx(None);
        let mut event = ProcessExecEvent::default();
        event.header.kind = EventKind::ProcessExec.as_u16();
        event.header.version = EVENT_SCHEMA_VERSION + 1;
        event.header.size = ProcessExecEvent::SIZE;
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &event as *const _ as *const u8,
                core::mem::size_of::<ProcessExecEvent>(),
            )
        };
        let result = dispatch_event(bytes, &mut ctx);
        assert!(matches!(result, DispatchResult::InvalidSchema));
    }

    #[test]
    fn unknown_kind_returns_unsupported() {
        let mut h = TestHarness::new();
        let mut ctx = h.ctx(None);
        let mut event = ProcessExecEvent::default();
        event.header.kind = 9999;
        event.header.version = EVENT_SCHEMA_VERSION;
        event.header.size = ProcessExecEvent::SIZE;
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &event as *const _ as *const u8,
                core::mem::size_of::<ProcessExecEvent>(),
            )
        };
        let result = dispatch_event(bytes, &mut ctx);
        assert!(matches!(result, DispatchResult::Unsupported));
    }

    #[test]
    fn exec_syscall_returns_internal() {
        let mut h = TestHarness::new();
        let mut ctx = h.ctx(None);
        let mut event = ExecSyscallEvent::default();
        event.header.kind = EventKind::ExecSyscall.as_u16();
        event.header.version = EVENT_SCHEMA_VERSION;
        event.header.size = ExecSyscallEvent::SIZE;
        event.header.pid = 42;
        event.header.tid = 42;
        event.source = ExecSource::Execve as u8;
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &event as *const _ as *const u8,
                core::mem::size_of::<ExecSyscallEvent>(),
            )
        };
        let result = dispatch_event(bytes, &mut ctx);
        assert!(matches!(result, DispatchResult::Internal));
    }

    #[test]
    fn valid_exec_returns_normalized() {
        let mut h = TestHarness::new();
        let mut ctx = h.ctx(None);
        let mut event = ProcessExecEvent::default();
        event.header.kind = EventKind::ProcessExec.as_u16();
        event.header.version = EVENT_SCHEMA_VERSION;
        event.header.size = ProcessExecEvent::SIZE;
        event.header.timestamp_ns = 1000;
        event.header.pid = 42;
        event.header.tid = 42;
        event.comm[..2].copy_from_slice(b"sh");
        event.filename[..7].copy_from_slice(b"/bin/sh");
        event.filename_len = 7;
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &event as *const _ as *const u8,
                core::mem::size_of::<ProcessExecEvent>(),
            )
        };
        let result = dispatch_event(bytes, &mut ctx);
        assert!(matches!(result, DispatchResult::Normalized(_)));
    }

    #[test]
    fn filtered_file_event_returns_filtered() {
        let mut h = TestHarness::new();
        let config = FileConfig {
            enabled: true,
            hooks: vec!["openat".to_string()],
            watch_paths: vec!["/etc".to_string()],
            watch_patterns: vec![],
            exclude_paths: vec![],
        };
        let mut ctx = h.ctx(Some(&config));
        let mut event = FileOpenEvent::default();
        event.header.kind = EventKind::FileOpen.as_u16();
        event.header.version = EVENT_SCHEMA_VERSION;
        event.header.size = FileOpenEvent::SIZE;
        event.header.timestamp_ns = 4000;
        event.header.pid = 42;
        event.header.tid = 42;
        let path = b"/var/log/syslog";
        event.filename[..path.len()].copy_from_slice(path);
        event.filename_len = path.len() as u16;
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &event as *const _ as *const u8,
                core::mem::size_of::<FileOpenEvent>(),
            )
        };
        let result = dispatch_event(bytes, &mut ctx);
        assert!(matches!(result, DispatchResult::Filtered));
    }
}
