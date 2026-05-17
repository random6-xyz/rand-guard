#![no_std]

pub const EVENT_SCHEMA_VERSION: u16 = 1;
pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;
pub const EVENT_FLAG_FILENAME_TRUNCATED: u16 = 1 << 0;

#[repr(u16)]
#[derive(Clone, Copy)]
pub enum EventKind {
    ProcessExec = 1,
    FileAccess = 2,
    NetworkConnect = 3,
    ProcessFork = 4,
    ProcessExit = 5,
    ExecSyscall = 6,
}

impl EventKind {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct EventHeader {
    pub kind: u16,
    pub version: u16,
    pub size: u16,
    pub flags: u16,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExecEvent {
    pub header: EventHeader,
    pub comm: [u8; COMM_LEN],
    pub filename: [u8; PATH_LEN],
    pub filename_len: u16,
    pub _pad: [u8; 6],
}

impl ProcessExecEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for ProcessExecEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            comm: [0; COMM_LEN],
            filename: [0; PATH_LEN],
            filename_len: 0,
            _pad: [0; 6],
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum ExecSource {
    Execve = 1,
    Execveat = 2,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecSyscallEvent {
    pub header: EventHeader,
    pub filename: [u8; PATH_LEN],
    pub filename_len: u16,
    pub source: u8,
    pub _pad: [u8; 5],
}

impl ExecSyscallEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for ExecSyscallEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            filename: [0; PATH_LEN],
            filename_len: 0,
            source: ExecSource::Execve as u8,
            _pad: [0; 5],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessForkEvent {
    pub header: EventHeader,
    pub parent_pid: u32,
    pub parent_comm: [u8; COMM_LEN],
    pub child_pid: u32,
    pub child_tid: u32,
    pub child_comm: [u8; COMM_LEN],
}

impl ProcessForkEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for ProcessForkEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            parent_pid: 0,
            parent_comm: [0; COMM_LEN],
            child_pid: 0,
            child_tid: 0,
            child_comm: [0; COMM_LEN],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExitEvent {
    pub header: EventHeader,
    pub comm: [u8; COMM_LEN],
    pub group_dead: u8,
    pub _pad: [u8; 7],
}

impl ProcessExitEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for ProcessExitEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            comm: [0; COMM_LEN],
            group_dead: 0,
            _pad: [0; 7],
        }
    }
}
