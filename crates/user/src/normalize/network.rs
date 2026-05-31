use edr_common::{NetworkBindEvent, NetworkConnectEvent, NetworkFamily, NetworkListenEvent};

use crate::config::NetworkDetectionRule;
use crate::normalize::helpers::{detect_for_network, enrich_from_table_or_comm};
use crate::normalize::types::*;
use crate::process_table::ProcessTable;

fn network_family(family: u16) -> String {
    match family {
        f if f == NetworkFamily::Ipv4 as u16 => "ipv4".to_string(),
        f if f == NetworkFamily::Ipv6 as u16 => "ipv6".to_string(),
        _ => "unknown".to_string(),
    }
}

fn network_addr(family: u16, ipv4_addr: u32, ipv6_addr: &[u8; 16]) -> String {
    if family == NetworkFamily::Ipv4 as u16 {
        let octets = ipv4_addr.to_be_bytes();
        format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
    } else if family == NetworkFamily::Ipv6 as u16 {
        std::net::Ipv6Addr::from(*ipv6_addr).to_string()
    } else {
        String::new()
    }
}

pub fn normalize_network_connect(
    event: &NetworkConnectEvent,
    table: &mut ProcessTable,
    detections: &[NetworkDetectionRule],
) -> Option<NormalizedEvent> {
    let (comm, exe_path, ppid) = enrich_from_table_or_comm(&event.header, table, &event.comm);
    let (alert, detection_type) = detect_for_network(
        crate::config::NetworkDirection::Outbound,
        event.port,
        &comm,
        detections,
    );

    Some(NormalizedEvent::NetworkConnect(NetworkConnect {
        pid: event.header.pid,
        tid: event.header.tid,
        ppid,
        uid: event.header.uid,
        gid: event.header.gid,
        comm,
        exe_path,
        family: network_family(event.family),
        socket_fd: event.socket_fd,
        remote_addr: network_addr(event.family, event.ipv4_addr, &event.ipv6_addr),
        remote_port: event.port,
        alert,
        detection_type,
        timestamp_ns: event.header.timestamp_ns,
    }))
}

pub fn normalize_network_bind(
    event: &NetworkBindEvent,
    table: &mut ProcessTable,
    detections: &[NetworkDetectionRule],
) -> Option<NormalizedEvent> {
    let (comm, exe_path, ppid) = enrich_from_table_or_comm(&event.header, table, &event.comm);
    let (alert, detection_type) = detect_for_network(
        crate::config::NetworkDirection::Inbound,
        event.port,
        &comm,
        detections,
    );

    Some(NormalizedEvent::NetworkBind(NetworkBind {
        pid: event.header.pid,
        tid: event.header.tid,
        ppid,
        uid: event.header.uid,
        gid: event.header.gid,
        comm,
        exe_path,
        family: network_family(event.family),
        socket_fd: event.socket_fd,
        local_addr: network_addr(event.family, event.ipv4_addr, &event.ipv6_addr),
        local_port: event.port,
        alert,
        detection_type,
        timestamp_ns: event.header.timestamp_ns,
    }))
}

pub fn normalize_network_listen(
    event: &NetworkListenEvent,
    table: &mut ProcessTable,
    detections: &[NetworkDetectionRule],
) -> Option<NormalizedEvent> {
    let (comm, exe_path, ppid) = enrich_from_table_or_comm(&event.header, table, &event.comm);
    let (alert, detection_type) = detect_for_network(
        crate::config::NetworkDirection::Inbound,
        event.port,
        &comm,
        detections,
    );

    Some(NormalizedEvent::NetworkListen(NetworkListen {
        pid: event.header.pid,
        tid: event.header.tid,
        ppid,
        uid: event.header.uid,
        gid: event.header.gid,
        comm,
        exe_path,
        family: network_family(event.family),
        socket_fd: event.socket_fd,
        local_addr: network_addr(event.family, event.ipv4_addr, &event.ipv6_addr),
        local_port: event.port,
        backlog: event.backlog,
        alert,
        detection_type,
        timestamp_ns: event.header.timestamp_ns,
    }))
}
