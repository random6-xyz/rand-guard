#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ExecEvent {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16],
}
