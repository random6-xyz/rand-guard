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
