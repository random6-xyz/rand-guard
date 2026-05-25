use crate::{COMM_LEN, EventHeader, NetworkDirection, NetworkFamily};

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
