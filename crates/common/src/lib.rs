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
    FileOpen = 7,
    FileOpenAt2 = 8,
    FileWrite = 9,
    FileWriteV = 10,
    FilePWrite64 = 11,
    FileRename = 12,
    FileRenameAt = 13,
    FileRenameAt2 = 14,
    FileUnlink = 15,
    FileUnlinkAt = 16,
    NetworkBind = 17,
    NetworkListen = 18,
}

impl EventKind {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

#[repr(u16)]
#[derive(Clone, Copy)]
pub enum NetworkFamily {
    Unknown = 0,
    Ipv4 = 2,
    Ipv6 = 10,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum NetworkDirection {
    Outbound = 1,
    Listener = 2,
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileOpenEvent {
    pub header: EventHeader,
    pub filename: [u8; PATH_LEN],
    pub filename_len: u16,
    pub flags: u32,
    pub _pad: [u8; 2],
}

impl FileOpenEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for FileOpenEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            filename: [0; PATH_LEN],
            filename_len: 0,
            flags: 0,
            _pad: [0; 2],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileOpenAt2Event {
    pub header: EventHeader,
    pub filename: [u8; PATH_LEN],
    pub filename_len: u16,
    pub flags: u64,
    pub _pad: [u8; 6],
}

impl FileOpenAt2Event {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for FileOpenAt2Event {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            filename: [0; PATH_LEN],
            filename_len: 0,
            flags: 0,
            _pad: [0; 6],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileWriteEvent {
    pub header: EventHeader,
    pub fd: u64,
    pub count: u64,
}

impl FileWriteEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileWriteVEvent {
    pub header: EventHeader,
    pub fd: u64,
    pub iovcnt: i64,
}

impl FileWriteVEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FilePWrite64Event {
    pub header: EventHeader,
    pub fd: u64,
    pub count: u64,
    pub pos: i64,
}

impl FilePWrite64Event {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileRenameEvent {
    pub header: EventHeader,
    pub old_filename: [u8; PATH_LEN],
    pub old_filename_len: u16,
    pub new_filename: [u8; PATH_LEN],
    pub new_filename_len: u16,
    pub _pad: [u8; 4],
}

impl FileRenameEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for FileRenameEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            old_filename: [0; PATH_LEN],
            old_filename_len: 0,
            new_filename: [0; PATH_LEN],
            new_filename_len: 0,
            _pad: [0; 4],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileRenameAtEvent {
    pub header: EventHeader,
    pub old_filename: [u8; PATH_LEN],
    pub old_filename_len: u16,
    pub new_filename: [u8; PATH_LEN],
    pub new_filename_len: u16,
    pub _pad: [u8; 4],
}

impl FileRenameAtEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for FileRenameAtEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            old_filename: [0; PATH_LEN],
            old_filename_len: 0,
            new_filename: [0; PATH_LEN],
            new_filename_len: 0,
            _pad: [0; 4],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileRenameAt2Event {
    pub header: EventHeader,
    pub old_filename: [u8; PATH_LEN],
    pub old_filename_len: u16,
    pub new_filename: [u8; PATH_LEN],
    pub new_filename_len: u16,
    pub flags: u32,
    pub _pad: [u8; 4],
}

impl FileRenameAt2Event {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for FileRenameAt2Event {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            old_filename: [0; PATH_LEN],
            old_filename_len: 0,
            new_filename: [0; PATH_LEN],
            new_filename_len: 0,
            flags: 0,
            _pad: [0; 4],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileUnlinkEvent {
    pub header: EventHeader,
    pub filename: [u8; PATH_LEN],
    pub filename_len: u16,
    pub _pad: [u8; 6],
}

impl FileUnlinkEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for FileUnlinkEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            filename: [0; PATH_LEN],
            filename_len: 0,
            _pad: [0; 6],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileUnlinkAtEvent {
    pub header: EventHeader,
    pub filename: [u8; PATH_LEN],
    pub filename_len: u16,
    pub flags: u32,
    pub _pad: [u8; 2],
}

impl FileUnlinkAtEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for FileUnlinkAtEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            filename: [0; PATH_LEN],
            filename_len: 0,
            flags: 0,
            _pad: [0; 2],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkConnectEvent {
    pub header: EventHeader,
    pub comm: [u8; COMM_LEN],
    pub family: u16,
    pub socket_fd: i32,
    pub port: u16,
    pub addr_len: u32,
    pub ipv4_addr: u32,
    pub ipv6_addr: [u8; 16],
    pub direction: u8,
    pub _pad: [u8; 5],
}

impl NetworkConnectEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for NetworkConnectEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            comm: [0; COMM_LEN],
            family: NetworkFamily::Unknown as u16,
            socket_fd: 0,
            port: 0,
            addr_len: 0,
            ipv4_addr: 0,
            ipv6_addr: [0; 16],
            direction: NetworkDirection::Outbound as u8,
            _pad: [0; 5],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkBindEvent {
    pub header: EventHeader,
    pub comm: [u8; COMM_LEN],
    pub family: u16,
    pub socket_fd: i32,
    pub port: u16,
    pub addr_len: u32,
    pub ipv4_addr: u32,
    pub ipv6_addr: [u8; 16],
    pub direction: u8,
    pub _pad: [u8; 5],
}

impl NetworkBindEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for NetworkBindEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            comm: [0; COMM_LEN],
            family: NetworkFamily::Unknown as u16,
            socket_fd: 0,
            port: 0,
            addr_len: 0,
            ipv4_addr: 0,
            ipv6_addr: [0; 16],
            direction: NetworkDirection::Listener as u8,
            _pad: [0; 5],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkListenEvent {
    pub header: EventHeader,
    pub comm: [u8; COMM_LEN],
    pub family: u16,
    pub socket_fd: i32,
    pub port: u16,
    pub addr_len: u32,
    pub ipv4_addr: u32,
    pub ipv6_addr: [u8; 16],
    pub backlog: i32,
    pub direction: u8,
    pub _pad: [u8; 5],
}

impl NetworkListenEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for NetworkListenEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            comm: [0; COMM_LEN],
            family: NetworkFamily::Unknown as u16,
            socket_fd: 0,
            port: 0,
            addr_len: 0,
            ipv4_addr: 0,
            ipv6_addr: [0; 16],
            backlog: 0,
            direction: NetworkDirection::Listener as u8,
            _pad: [0; 5],
        }
    }
}
