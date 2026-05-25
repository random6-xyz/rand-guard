use crate::normalize::NormalizedEvent;
use crate::output::file::{
    format_file_open_json, format_file_openat2_json, format_file_pwrite64_json,
    format_file_rename_json, format_file_renameat_json, format_file_renameat2_json,
    format_file_unlink_json, format_file_unlinkat_json, format_file_write_json,
    format_file_writev_json,
};
use crate::output::network::{
    format_network_bind_json, format_network_connect_json, format_network_listen_json,
};
use crate::output::process::{
    format_process_exit_json, format_process_relationship_json, format_process_start_json,
};

pub fn format_normalized_event_json(event: &NormalizedEvent) -> String {
    match event {
        NormalizedEvent::ProcessStart(start) => format_process_start_json(start),
        NormalizedEvent::ProcessExit(exit) => format_process_exit_json(exit),
        NormalizedEvent::ProcessRelationship(rel) => format_process_relationship_json(rel),
        NormalizedEvent::FileOpen(file) => format_file_open_json(file),
        NormalizedEvent::FileOpenAt2(file) => format_file_openat2_json(file),
        NormalizedEvent::FileWrite(file) => format_file_write_json(file),
        NormalizedEvent::FileWriteV(file) => format_file_writev_json(file),
        NormalizedEvent::FilePWrite64(file) => format_file_pwrite64_json(file),
        NormalizedEvent::FileRename(file) => format_file_rename_json(file),
        NormalizedEvent::FileRenameAt(file) => format_file_renameat_json(file),
        NormalizedEvent::FileRenameAt2(file) => format_file_renameat2_json(file),
        NormalizedEvent::FileUnlink(file) => format_file_unlink_json(file),
        NormalizedEvent::FileUnlinkAt(file) => format_file_unlinkat_json(file),
        NormalizedEvent::NetworkConnect(net) => format_network_connect_json(net),
        NormalizedEvent::NetworkBind(net) => format_network_bind_json(net),
        NormalizedEvent::NetworkListen(net) => format_network_listen_json(net),
    }
}
