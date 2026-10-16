//! Narrow Windows FFI wrappers. All pointers are owned, NUL-terminated UTF-16 and remain live for each call.
#![allow(unsafe_code)]
use crate::{FsError, FsResult};
use std::{
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    path::Path,
};
use windows_sys::Win32::Storage::FileSystem::*;
fn wide(path: &Path) -> FsResult<Vec<u16>> {
    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) {
        return Err(FsError::InvalidName("NUL in path"));
    }
    value.push(0);
    Ok(value)
}
pub(crate) fn file_identity(file: &std::fs::File) -> FsResult<zeus_types::FileId> {
    let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: live file handle and valid writable output buffer; read only on success.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let info = unsafe { info.assume_init() };
    Ok(zeus_types::FileId::windows(
        info.dwVolumeSerialNumber as u64,
        ((info.nFileIndexHigh as u128) << 32) | info.nFileIndexLow as u128,
    ))
}
pub(crate) fn move_noreplace(from: &Path, to: &Path) -> FsResult<()> {
    let from = wide(from)?;
    let to = wide(to)?;
    // SAFETY: both paths are live NUL-terminated UTF-16 buffers.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
        let e = std::io::Error::last_os_error();
        return Err(if matches!(e.raw_os_error(), Some(80 | 183)) {
            FsError::AlreadyExists
        } else {
            e.into()
        });
    }
    Ok(())
}
pub(crate) fn replace(from: &Path, to: &Path, backup: &Path) -> FsResult<()> {
    let from = wide(from)?;
    let to = wide(to)?;
    let backup = wide(backup)?;
    // SAFETY: all buffers are valid; reserved parameters must be null.
    if unsafe {
        ReplaceFileW(
            to.as_ptr(),
            from.as_ptr(),
            backup.as_ptr(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
