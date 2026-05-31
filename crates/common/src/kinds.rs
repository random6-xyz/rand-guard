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

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum ExecSource {
    Execve = 1,
    Execveat = 2,
}
