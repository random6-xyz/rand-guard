use aya_ebpf::{helpers::r#gen, programs::TracePointContext};
use edr_common::{
    EVENT_SCHEMA_VERSION, EventHeader, EventKind, FILE_FILTER_MAX_PREFIXES, FileFilterConfig,
};

pub fn fill_header(
    header: &mut EventHeader,
    kind: EventKind,
    size: u16,
    pid: u32,
    tid: u32,
    uid: u32,
    gid: u32,
) {
    header.kind = kind.as_u16();
    header.version = EVENT_SCHEMA_VERSION;
    header.size = size;
    header.flags = 0;
    header.timestamp_ns = unsafe { r#gen::bpf_ktime_get_ns() };
    header.pid = pid;
    header.tid = tid;
    header.ppid = 0;
    header.uid = uid;
    header.gid = gid;
    header._pad = 0;
}

pub unsafe fn read_data_loc_comm(
    ctx: &TracePointContext,
    data_loc_offset: usize,
    buf: &mut [u8],
) -> Result<(), i64> {
    let data_loc = unsafe { ctx.read_at::<u32>(data_loc_offset)? };
    let str_offset = (data_loc & 0xffff) as usize;
    let str_len = (data_loc >> 16) as usize;

    if str_offset == 0 {
        return Err(-1);
    }

    for item in buf.iter_mut() {
        *item = 0;
    }

    for (i, item) in buf.iter_mut().enumerate() {
        if i >= str_len {
            break;
        }
        let byte = unsafe { ctx.read_at::<u8>(str_offset + i)? };
        *item = byte;
        if byte == 0 {
            break;
        }
    }

    Ok(())
}

#[allow(clippy::needless_range_loop)]
pub fn file_passes_filter(filter: &FileFilterConfig, filename: &[u8], filename_len: u16) -> bool {
    if filter.prefix_count == 0 {
        return true;
    }

    let mut matched = false;
    for i in 0..FILE_FILTER_MAX_PREFIXES {
        if i as u32 >= filter.prefix_count {
            break;
        }
        let prefix_len = filter.prefix_lens[i] as usize;
        if prefix_len == 0 || (filename_len as usize) < prefix_len {
            continue;
        }
        let mut prefix_matches = true;
        for j in 0..prefix_len {
            if filename[j] != filter.prefixes[i][j] {
                prefix_matches = false;
                break;
            }
        }
        if prefix_matches {
            matched = true;
            break;
        }
    }
    matched
}
