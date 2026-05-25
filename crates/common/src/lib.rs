#![no_std]

pub const EVENT_SCHEMA_VERSION: u16 = 1;
pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;
pub const EVENT_FLAG_FILENAME_TRUNCATED: u16 = 1 << 0;

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
