#![no_std]

pub const EVENT_SCHEMA_VERSION: u16 = 1;
pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;
pub const EVENT_FLAG_FILENAME_TRUNCATED: u16 = 1 << 0;
pub const FILE_FILTER_MAX_PREFIXES: usize = 8;
pub const FILE_FILTER_PREFIX_LEN: usize = 64;

mod file;
mod header;
mod kinds;
mod network;
mod process;

pub use file::{
    FileOpenAt2Event, FileOpenEvent, FilePWrite64Event, FileRenameAt2Event, FileRenameAtEvent,
    FileRenameEvent, FileUnlinkAtEvent, FileUnlinkEvent, FileWriteEvent, FileWriteVEvent,
};
pub use header::EventHeader;
pub use kinds::{EventKind, ExecSource, NetworkDirection, NetworkFamily};
pub use network::{NetworkBindEvent, NetworkConnectEvent, NetworkListenEvent};
pub use process::{ExecSyscallEvent, ProcessExecEvent, ProcessExitEvent, ProcessForkEvent};

#[derive(Clone, Copy)]
#[repr(C)]
pub struct FileFilterConfig {
    pub prefix_count: u32,
    pub prefixes: [[u8; FILE_FILTER_PREFIX_LEN]; FILE_FILTER_MAX_PREFIXES],
    pub prefix_lens: [u32; FILE_FILTER_MAX_PREFIXES],
}

impl FileFilterConfig {
    pub const fn empty() -> Self {
        Self {
            prefix_count: 0,
            prefixes: [[0u8; FILE_FILTER_PREFIX_LEN]; FILE_FILTER_MAX_PREFIXES],
            prefix_lens: [0u32; FILE_FILTER_MAX_PREFIXES],
        }
    }
}
