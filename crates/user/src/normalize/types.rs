/// Normalized userspace event emitted after raw ring-buffer records have
/// been decoded and enriched by the process table.
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum NormalizedEvent {
    ProcessStart(ProcessStart),
    ProcessExit(ProcessExit),
    ProcessRelationship(ProcessRelationship),
    FileOpen(FileOpen),
    FileOpenAt2(FileOpenAt2),
    FileWrite(FileWrite),
    FileWriteV(FileWriteV),
    FilePWrite64(FilePWrite64),
    FileRename(FileRename),
    FileRenameAt(FileRenameAt),
    FileRenameAt2(FileRenameAt2),
    FileUnlink(FileUnlink),
    FileUnlinkAt(FileUnlinkAt),
    NetworkConnect(NetworkConnect),
    NetworkBind(NetworkBind),
    NetworkListen(NetworkListen),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessStart {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub source: Option<String>,
    pub timestamp_ns: u64,
    pub filename_truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessExit {
    pub pid: u32,
    pub tid: u32,
    pub comm: String,
    pub group_dead: bool,
    pub uid: u32,
    pub gid: u32,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessRelationship {
    pub parent_pid: u32,
    pub parent_comm: String,
    pub child_pid: u32,
    pub child_tid: u32,
    pub child_comm: String,
    pub uid: u32,
    pub gid: u32,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileOpen {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub filename: String,
    pub flags: u32,
    pub filename_truncated: bool,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileOpenAt2 {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub filename: String,
    pub flags: u64,
    pub filename_truncated: bool,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileWrite {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub fd: u64,
    pub count: u64,
    pub resolved_path: String,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileWriteV {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub fd: u64,
    pub iovcnt: i64,
    pub resolved_path: String,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilePWrite64 {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub fd: u64,
    pub count: u64,
    pub pos: i64,
    pub resolved_path: String,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRename {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub old_filename: String,
    pub new_filename: String,
    pub filename_truncated: bool,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRenameAt {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub old_filename: String,
    pub new_filename: String,
    pub filename_truncated: bool,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRenameAt2 {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub old_filename: String,
    pub new_filename: String,
    pub flags: u32,
    pub filename_truncated: bool,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileUnlink {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub filename: String,
    pub filename_truncated: bool,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileUnlinkAt {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub filename: String,
    pub flags: u32,
    pub filename_truncated: bool,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkConnect {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub family: String,
    pub socket_fd: i32,
    pub remote_addr: String,
    pub remote_port: u16,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkBind {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub family: String,
    pub socket_fd: i32,
    pub local_addr: String,
    pub local_port: u16,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkListen {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub exe_path: String,
    pub family: String,
    pub socket_fd: i32,
    pub local_addr: String,
    pub local_port: u16,
    pub backlog: i32,
    pub alert: bool,
    pub detection_type: Option<String>,
    pub timestamp_ns: u64,
}
