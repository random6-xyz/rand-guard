use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user,
    },
    macros::tracepoint,
    programs::TracePointContext,
};
use edr_common::{
    EventKind, NetworkBindEvent, NetworkConnectEvent, NetworkDirection, NetworkFamily,
    NetworkListenEvent,
};

use crate::EVENTS;
use crate::helpers::fill_header;

#[tracepoint(name = "sys_enter_connect", category = "syscalls")]
#[inline(never)]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    try_sys_enter_network_sockaddr(ctx, EventKind::NetworkConnect).unwrap_or(1)
}

#[tracepoint(name = "sys_enter_bind", category = "syscalls")]
#[inline(never)]
pub fn sys_enter_bind(ctx: TracePointContext) -> u32 {
    try_sys_enter_network_sockaddr(ctx, EventKind::NetworkBind).unwrap_or(1)
}

fn try_sys_enter_network_sockaddr(ctx: TracePointContext, kind: EventKind) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    let fd = unsafe { ctx.read_at::<i32>(16)? };
    let sockaddr_ptr = unsafe { ctx.read_at::<u64>(24)? } as *const u8;
    let addr_len = unsafe { ctx.read_at::<i32>(32)? };

    if sockaddr_ptr.is_null() || addr_len < 2 {
        return Err(-1);
    }

    let family = unsafe { bpf_probe_read_user::<u16>(sockaddr_ptr as *const u16)? };
    let mut port = 0u16;
    let mut ipv4_addr = 0u32;
    let mut ipv6_addr = [0u8; 16];

    if family == NetworkFamily::Ipv4 as u16 {
        if addr_len < 16 {
            return Err(-1);
        }
        let port_ptr = unsafe { sockaddr_ptr.add(2) } as *const u16;
        let addr_ptr = unsafe { sockaddr_ptr.add(4) } as *const u32;
        port = u16::from_be(unsafe { bpf_probe_read_user::<u16>(port_ptr)? });
        ipv4_addr = u32::from_be(unsafe { bpf_probe_read_user::<u32>(addr_ptr)? });
    } else if family == NetworkFamily::Ipv6 as u16 {
        if addr_len < 28 {
            return Err(-1);
        }
        let port_ptr = unsafe { sockaddr_ptr.add(2) } as *const u16;
        let addr_ptr = unsafe { sockaddr_ptr.add(8) };
        port = u16::from_be(unsafe { bpf_probe_read_user::<u16>(port_ptr)? });
        for (index, item) in ipv6_addr.iter_mut().enumerate() {
            *item = unsafe { bpf_probe_read_user::<u8>(addr_ptr.add(index))? };
        }
    }

    if kind.as_u16() == EventKind::NetworkConnect.as_u16() {
        if let Some(mut entry) = EVENTS.reserve::<NetworkConnectEvent>(0) {
            unsafe {
                let ptr = entry.as_mut_ptr();
                fill_header(
                    &mut (*ptr).header,
                    kind,
                    NetworkConnectEvent::SIZE,
                    pid,
                    tid,
                    uid,
                    gid,
                );
                match bpf_get_current_comm() {
                    Ok(comm) => (*ptr).comm = comm,
                    Err(ret) => {
                        entry.discard(0);
                        return Err(ret);
                    }
                }
                (*ptr).family = family;
                (*ptr).socket_fd = fd;
                (*ptr).port = port;
                (*ptr).addr_len = addr_len as u32;
                (*ptr).ipv4_addr = ipv4_addr;
                (*ptr).ipv6_addr = ipv6_addr;
                (*ptr).direction = NetworkDirection::Outbound as u8;
                (*ptr)._pad = [0; 5];
            }
            entry.submit(0);
        }
    } else if let Some(mut entry) = EVENTS.reserve::<NetworkBindEvent>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();
            fill_header(
                &mut (*ptr).header,
                kind,
                NetworkBindEvent::SIZE,
                pid,
                tid,
                uid,
                gid,
            );
            match bpf_get_current_comm() {
                Ok(comm) => (*ptr).comm = comm,
                Err(ret) => {
                    entry.discard(0);
                    return Err(ret);
                }
            }
            (*ptr).family = family;
            (*ptr).socket_fd = fd;
            (*ptr).port = port;
            (*ptr).addr_len = addr_len as u32;
            (*ptr).ipv4_addr = ipv4_addr;
            (*ptr).ipv6_addr = ipv6_addr;
            (*ptr).direction = NetworkDirection::Listener as u8;
            (*ptr)._pad = [0; 5];
        }
        entry.submit(0);
    }

    Ok(0)
}

#[tracepoint(name = "sys_enter_listen", category = "syscalls")]
#[inline(never)]
pub fn sys_enter_listen(ctx: TracePointContext) -> u32 {
    try_sys_enter_listen(ctx).unwrap_or(1)
}

fn try_sys_enter_listen(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let gid = (uid_gid >> 32) as u32;
    let uid = uid_gid as u32;

    let fd = unsafe { ctx.read_at::<i32>(16)? };
    let backlog = unsafe { ctx.read_at::<i32>(24)? };

    if let Some(mut entry) = EVENTS.reserve::<NetworkListenEvent>(0) {
        unsafe {
            let ptr = entry.as_mut_ptr();
            fill_header(
                &mut (*ptr).header,
                EventKind::NetworkListen,
                NetworkListenEvent::SIZE,
                pid,
                tid,
                uid,
                gid,
            );
            match bpf_get_current_comm() {
                Ok(comm) => (*ptr).comm = comm,
                Err(ret) => {
                    entry.discard(0);
                    return Err(ret);
                }
            }
            (*ptr).family = NetworkFamily::Unknown as u16;
            (*ptr).socket_fd = fd;
            (*ptr).port = 0;
            (*ptr).addr_len = 0;
            (*ptr).ipv4_addr = 0;
            (*ptr).ipv6_addr = [0; 16];
            (*ptr).backlog = backlog;
            (*ptr).direction = NetworkDirection::Listener as u8;
            (*ptr)._pad = [0; 5];
        }
        entry.submit(0);
    }

    Ok(0)
}
