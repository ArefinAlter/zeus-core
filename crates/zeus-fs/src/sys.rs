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

/// Rename the retained source object into a held destination directory, never replacing its leaf.
pub(crate) fn rename_handle_noreplace(
    source: &std::fs::File,
    destination: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
) -> FsResult<()> {
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_RENAME_INFORMATION, FileRenameInformation, NtSetInformationFile,
    };
    use windows_sys::Win32::{Foundation::RtlNtStatusToDosError, System::IO::IO_STATUS_BLOCK};
    let name: Vec<u16> = name.encode_wide().collect();
    let name_bytes = name
        .len()
        .checked_mul(2)
        .ok_or(FsError::InvalidName("name too long"))?;
    let offset = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let bytes = offset
        .checked_add(name_bytes)
        .ok_or(FsError::InvalidName("name too long"))?
        .max(std::mem::size_of::<FILE_RENAME_INFORMATION>());
    let length = u32::try_from(bytes).map_err(|_| FsError::InvalidName("name too long"))?;
    // A usize allocation provides the pointer alignment required by FILE_RENAME_INFORMATION. Zero-fill
    // includes ReplaceIfExists=false, padding and the unused union bytes. Tail is counted UTF-16.
    let mut buffer = vec![0usize; bytes.div_ceil(std::mem::size_of::<usize>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: the aligned allocation covers the header and all UTF-16 units. Both handles and the
    // allocation remain live through the synchronous call; no references outlive this block.
    // The source is opened by cap-std without OVERLAPPED (FILE_SYNCHRONOUS_IO_NONALERT), so this
    // request completes before returning and cannot retain either output buffer asynchronously.
    let mut status_block = IO_STATUS_BLOCK::default();
    let status = unsafe {
        (*info).RootDirectory = destination.as_raw_handle();
        (*info).FileNameLength = name_bytes as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            name.len(),
        );
        NtSetInformationFile(
            source.as_raw_handle(),
            &mut status_block,
            info.cast(),
            length,
            FileRenameInformation,
        )
    };
    if status < 0 {
        // SAFETY: pure conversion of the returned NT status to the public Win32 error vocabulary.
        let error =
            std::io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32);
        return Err(
            if error.kind() == std::io::ErrorKind::AlreadyExists
                || matches!(error.raw_os_error(), Some(80 | 183))
            {
                FsError::AlreadyExists
            } else {
                error.into()
            },
        );
    }
    Ok(())
}

pub(crate) fn delete_open_file(file: &std::fs::File) -> FsResult<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: create_new opens a synchronous handle with DELETE access. The correctly sized
    // structure and source handle stay live until the call completes; deletion occurs on close.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&info as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
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
