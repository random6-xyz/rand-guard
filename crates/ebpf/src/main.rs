#![no_std]
#![no_main]

mod exec_syscall;
mod file_open;
mod file_rename;
mod file_unlink;
mod file_write;
mod helpers;
mod network;
mod process;

use aya_ebpf::{macros::map, maps::Array, maps::ring_buf::RingBuf};
use edr_common::FileFilterConfig;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(65536, 0);

#[map]
static FILE_FILTER: Array<FileFilterConfig> = Array::with_max_entries(1, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
