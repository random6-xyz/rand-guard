use crate::config::NetworkDirection;
use crate::normalize::{
    FileOpen, FileOpenAt2, FilePWrite64, FileRename, FileRenameAt, FileRenameAt2, FileUnlink,
    FileUnlinkAt, FileWrite, FileWriteV, NetworkBind, NetworkConnect, NetworkListen,
};

pub fn matches_name(names: &[String], value: &str) -> bool {
    names.is_empty() || names.iter().any(|name| name == value)
}

pub fn matches_operation(operations: &[String], operation: &str) -> bool {
    operations
        .iter()
        .any(|op| op == "*" || canonical_operation(op) == operation)
}

pub fn canonical_operation(operation: &str) -> &str {
    match operation {
        "open" | "file_open" => "file_open",
        "write" | "file_write" => "file_write",
        "rename" | "file_rename" => "file_rename",
        "unlink" | "file_unlink" => "file_unlink",
        other => other,
    }
}

pub fn matches_path_rule(path: &str, paths: &[String], patterns: &[String]) -> bool {
    let has_paths = !paths.is_empty();
    let has_patterns = !patterns.is_empty();
    let matches_path = paths.iter().any(|p| {
        if p.ends_with('/') {
            path.starts_with(p)
        } else {
            path == p || path.starts_with(&format!("{p}/"))
        }
    });
    let matches_pattern = patterns
        .iter()
        .any(|pattern| matches_pattern(path, pattern));

    if has_paths && has_patterns {
        matches_path && matches_pattern
    } else if has_paths {
        matches_path
    } else if has_patterns {
        matches_pattern
    } else {
        false
    }
}

pub fn matches_pattern(path: &str, pattern: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        path.ends_with(&format!(".{suffix}"))
    } else {
        path == pattern
    }
}

pub struct FileFields<'a> {
    pub source_event_type: &'static str,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: &'a str,
    pub exe_path: &'a str,
    pub operation: &'static str,
    pub paths: Vec<&'a str>,
}

impl<'a> FileFields<'a> {
    pub fn from_open(file: &'a FileOpen) -> Self {
        Self::new(
            "file_open",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_open",
            vec![&file.filename],
        )
    }

    pub fn from_openat2(file: &'a FileOpenAt2) -> Self {
        Self::new(
            "file_openat2",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_open",
            vec![&file.filename],
        )
    }

    pub fn from_write(file: &'a FileWrite) -> Self {
        Self::new(
            "file_write",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_write",
            vec![&file.resolved_path],
        )
    }

    pub fn from_writev(file: &'a FileWriteV) -> Self {
        Self::new(
            "file_writev",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_write",
            vec![&file.resolved_path],
        )
    }

    pub fn from_pwrite64(file: &'a FilePWrite64) -> Self {
        Self::new(
            "file_pwrite64",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_write",
            vec![&file.resolved_path],
        )
    }

    pub fn from_rename(file: &'a FileRename) -> Self {
        Self::new(
            "file_rename",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_rename",
            vec![&file.old_filename, &file.new_filename],
        )
    }

    pub fn from_renameat(file: &'a FileRenameAt) -> Self {
        Self::new(
            "file_renameat",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_rename",
            vec![&file.old_filename, &file.new_filename],
        )
    }

    pub fn from_renameat2(file: &'a FileRenameAt2) -> Self {
        Self::new(
            "file_renameat2",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_rename",
            vec![&file.old_filename, &file.new_filename],
        )
    }

    pub fn from_unlink(file: &'a FileUnlink) -> Self {
        Self::new(
            "file_unlink",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_unlink",
            vec![&file.filename],
        )
    }

    pub fn from_unlinkat(file: &'a FileUnlinkAt) -> Self {
        Self::new(
            "file_unlinkat",
            file.timestamp_ns,
            file.pid,
            file.tid,
            file.ppid,
            file.uid,
            file.gid,
            &file.comm,
            &file.exe_path,
            "file_unlink",
            vec![&file.filename],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        source_event_type: &'static str,
        timestamp_ns: u64,
        pid: u32,
        tid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        comm: &'a str,
        exe_path: &'a str,
        operation: &'static str,
        paths: Vec<&'a str>,
    ) -> Self {
        Self {
            source_event_type,
            timestamp_ns,
            pid,
            tid,
            ppid,
            uid,
            gid,
            comm,
            exe_path,
            operation,
            paths,
        }
    }
}

pub struct NetworkFields<'a> {
    pub source_event_type: &'static str,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: &'a str,
    pub exe_path: &'a str,
    pub family: &'a str,
    pub direction: NetworkDirection,
    pub port: u16,
    pub addr: &'a str,
}

impl<'a> NetworkFields<'a> {
    pub fn from_connect(net: &'a NetworkConnect) -> Self {
        Self::new(
            "network_connect",
            net.timestamp_ns,
            net.pid,
            net.tid,
            net.ppid,
            net.uid,
            net.gid,
            &net.comm,
            &net.exe_path,
            &net.family,
            NetworkDirection::Outbound,
            net.remote_port,
            &net.remote_addr,
        )
    }

    pub fn from_bind(net: &'a NetworkBind) -> Self {
        Self::new(
            "network_bind",
            net.timestamp_ns,
            net.pid,
            net.tid,
            net.ppid,
            net.uid,
            net.gid,
            &net.comm,
            &net.exe_path,
            &net.family,
            NetworkDirection::Inbound,
            net.local_port,
            &net.local_addr,
        )
    }

    pub fn from_listen(net: &'a NetworkListen) -> Self {
        Self::new(
            "network_listen",
            net.timestamp_ns,
            net.pid,
            net.tid,
            net.ppid,
            net.uid,
            net.gid,
            &net.comm,
            &net.exe_path,
            &net.family,
            NetworkDirection::Inbound,
            net.local_port,
            &net.local_addr,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        source_event_type: &'static str,
        timestamp_ns: u64,
        pid: u32,
        tid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        comm: &'a str,
        exe_path: &'a str,
        family: &'a str,
        direction: NetworkDirection,
        port: u16,
        addr: &'a str,
    ) -> Self {
        Self {
            source_event_type,
            timestamp_ns,
            pid,
            tid,
            ppid,
            uid,
            gid,
            comm,
            exe_path,
            family,
            direction,
            port,
            addr,
        }
    }
}
