use crate::{EventHeader, PATH_LEN};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileOpenEvent {
    pub header: EventHeader,
    pub filename: [u8; PATH_LEN],
    pub filename_len: u16,
    pub flags: u32,
    pub _pad: [u8; 2],
}

impl FileOpenEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for FileOpenEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            filename: [0; PATH_LEN],
            filename_len: 0,
            flags: 0,
            _pad: [0; 2],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileOpenAt2Event {
    pub header: EventHeader,
    pub filename: [u8; PATH_LEN],
    pub filename_len: u16,
    pub flags: u64,
    pub _pad: [u8; 6],
}

impl FileOpenAt2Event {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for FileOpenAt2Event {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            filename: [0; PATH_LEN],
            filename_len: 0,
            flags: 0,
            _pad: [0; 6],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileWriteEvent {
    pub header: EventHeader,
    pub fd: u64,
    pub count: u64,
}

impl FileWriteEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileWriteVEvent {
    pub header: EventHeader,
    pub fd: u64,
    pub iovcnt: i64,
}

impl FileWriteVEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FilePWrite64Event {
    pub header: EventHeader,
    pub fd: u64,
    pub count: u64,
    pub pos: i64,
}

impl FilePWrite64Event {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileRenameEvent {
    pub header: EventHeader,
    pub old_filename: [u8; PATH_LEN],
    pub old_filename_len: u16,
    pub new_filename: [u8; PATH_LEN],
    pub new_filename_len: u16,
    pub _pad: [u8; 4],
}

impl FileRenameEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for FileRenameEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            old_filename: [0; PATH_LEN],
            old_filename_len: 0,
            new_filename: [0; PATH_LEN],
            new_filename_len: 0,
            _pad: [0; 4],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileRenameAtEvent {
    pub header: EventHeader,
    pub old_filename: [u8; PATH_LEN],
    pub old_filename_len: u16,
    pub new_filename: [u8; PATH_LEN],
    pub new_filename_len: u16,
    pub _pad: [u8; 4],
}

impl FileRenameAtEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for FileRenameAtEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            old_filename: [0; PATH_LEN],
            old_filename_len: 0,
            new_filename: [0; PATH_LEN],
            new_filename_len: 0,
            _pad: [0; 4],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileRenameAt2Event {
    pub header: EventHeader,
    pub old_filename: [u8; PATH_LEN],
    pub old_filename_len: u16,
    pub new_filename: [u8; PATH_LEN],
    pub new_filename_len: u16,
    pub flags: u32,
    pub _pad: [u8; 4],
}

impl FileRenameAt2Event {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for FileRenameAt2Event {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            old_filename: [0; PATH_LEN],
            old_filename_len: 0,
            new_filename: [0; PATH_LEN],
            new_filename_len: 0,
            flags: 0,
            _pad: [0; 4],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileUnlinkEvent {
    pub header: EventHeader,
    pub filename: [u8; PATH_LEN],
    pub filename_len: u16,
    pub _pad: [u8; 6],
}

impl FileUnlinkEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for FileUnlinkEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            filename: [0; PATH_LEN],
            filename_len: 0,
            _pad: [0; 6],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileUnlinkAtEvent {
    pub header: EventHeader,
    pub filename: [u8; PATH_LEN],
    pub filename_len: u16,
    pub flags: u32,
    pub _pad: [u8; 2],
}

impl FileUnlinkAtEvent {
    pub const SIZE: u16 = core::mem::size_of::<Self>() as u16;
}

impl Default for FileUnlinkAtEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            filename: [0; PATH_LEN],
            filename_len: 0,
            flags: 0,
            _pad: [0; 2],
        }
    }
}
