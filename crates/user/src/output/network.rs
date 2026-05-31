use crate::normalize::{NetworkBind, NetworkConnect, NetworkListen};

pub fn format_network_connect_json(net: &NetworkConnect) -> String {
    serde_json::json!({
        "event_type": "network_connect",
        "timestamp_ns": net.timestamp_ns,
        "pid": net.pid,
        "tid": net.tid,
        "ppid": net.ppid,
        "uid": net.uid,
        "gid": net.gid,
        "comm": net.comm,
        "exe_path": net.exe_path,
        "family": net.family,
        "socket_fd": net.socket_fd,
        "remote_addr": net.remote_addr,
        "remote_port": net.remote_port,
        "alert": net.alert,
        "detection_type": net.detection_type,
    })
    .to_string()
}

pub fn format_network_bind_json(net: &NetworkBind) -> String {
    serde_json::json!({
        "event_type": "network_bind",
        "timestamp_ns": net.timestamp_ns,
        "pid": net.pid,
        "tid": net.tid,
        "ppid": net.ppid,
        "uid": net.uid,
        "gid": net.gid,
        "comm": net.comm,
        "exe_path": net.exe_path,
        "family": net.family,
        "socket_fd": net.socket_fd,
        "local_addr": net.local_addr,
        "local_port": net.local_port,
        "alert": net.alert,
        "detection_type": net.detection_type,
    })
    .to_string()
}

pub fn format_network_listen_json(net: &NetworkListen) -> String {
    serde_json::json!({
        "event_type": "network_listen",
        "timestamp_ns": net.timestamp_ns,
        "pid": net.pid,
        "tid": net.tid,
        "ppid": net.ppid,
        "uid": net.uid,
        "gid": net.gid,
        "comm": net.comm,
        "exe_path": net.exe_path,
        "family": net.family,
        "socket_fd": net.socket_fd,
        "local_addr": net.local_addr,
        "local_port": net.local_port,
        "backlog": net.backlog,
        "alert": net.alert,
        "detection_type": net.detection_type,
    })
    .to_string()
}
