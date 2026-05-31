use crate::config::{NetworkDetectionRule, NetworkDirection, PersistenceRule};
use crate::process_table::ProcessTable;

pub fn enrich_from_table(
    header: &edr_common::EventHeader,
    table: &ProcessTable,
) -> (String, String, u32) {
    if let Some(record) = table.get(&(header.pid, header.tid)) {
        (record.comm.clone(), record.exe_path.clone(), record.ppid)
    } else {
        (String::new(), String::new(), 0)
    }
}

pub fn enrich_from_table_or_comm(
    header: &edr_common::EventHeader,
    table: &ProcessTable,
    raw_comm: &[u8],
) -> (String, String, u32) {
    if let Some(record) = table.get(&(header.pid, header.tid)) {
        (record.comm.clone(), record.exe_path.clone(), record.ppid)
    } else {
        (
            crate::process_table::fixed_string(raw_comm, raw_comm.len()),
            String::new(),
            0,
        )
    }
}

pub fn detect_for_path(
    path: &str,
    operation: &str,
    detections: &[PersistenceRule],
) -> (bool, Option<String>) {
    if let Some(name) = crate::detections::check_persistence(path, operation, detections) {
        (true, Some(name))
    } else {
        (false, None)
    }
}

pub fn detect_for_paths(
    paths: &[&str],
    operation: &str,
    detections: &[PersistenceRule],
) -> (bool, Option<String>) {
    for path in paths {
        if let Some(name) = crate::detections::check_persistence(path, operation, detections) {
            return (true, Some(name));
        }
    }
    (false, None)
}

pub fn detect_for_network(
    direction: NetworkDirection,
    port: u16,
    process_name: &str,
    detections: &[NetworkDetectionRule],
) -> (bool, Option<String>) {
    if let Some(name) = crate::detections::check_network(direction, port, process_name, detections)
    {
        (true, Some(name))
    } else {
        (false, None)
    }
}
