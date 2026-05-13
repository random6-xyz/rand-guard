#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16],
}

impl Default for ExecEvent {
    fn default() -> Self {
        Self {
            pid: 0,
            tid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: [0; 16],
        }
    }
}
