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

use aya_ebpf::{macros::map, maps::ring_buf::RingBuf};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(65536, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
