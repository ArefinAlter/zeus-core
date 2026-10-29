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

/// Write the fixed ADS through its retained parent while the original file's handle denies delete
/// sharing. Identity is compared before truncation. The opened stream must belong to that object.
pub(crate) fn mark_retained(
    parent: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
    source: &std::fs::File,
    marks: &crate::provenance::ProvenanceMarks,
    mode: zeus_types::OsMetadataMode,
) -> FsResult<Vec<zeus_types::OsMetadataKind>> {
    use std::{io::Write, os::windows::io::FromRawHandle};
    use windows_sys::{
        Wdk::{
            Foundation::OBJECT_ATTRIBUTES,
            Storage::FileSystem::{
                FILE_NON_DIRECTORY_FILE, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
                FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
            },
        },
        Win32::{
            Foundation::{RtlNtStatusToDosError, UNICODE_STRING},
            System::IO::IO_STATUS_BLOCK,
        },
    };
    let mut stream = name.to_os_string();
    stream.push(":Zone.Identifier");
    let mut encoded: Vec<u16> = stream.encode_wide().collect();
    let bytes = u16::try_from(encoded.len() * 2)
        .map_err(|_| FsError::InvalidName("stream name too long"))?;
    let unicode = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: encoded.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &unicode,
        Attributes: 0,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle = std::ptr::null_mut();
    let mut io = IO_STATUS_BLOCK::default();
    // SAFETY: all pointers refer to live aligned storage. The stream name is a validated leaf plus
    // a fixed suffix, relative to the held parent. Synchronous open returns before storage drops.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            &attributes,
            &mut io,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN_IF,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(std::io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32
        )
        .into());
    }
    // SAFETY: successful NtCreateFile transfers the one owned handle into File, closed on drop.
    let mut output = unsafe { std::fs::File::from_raw_handle(handle) };
    if file_identity(&output)? != file_identity(source)? {
        return Err(FsError::OutsideRoots);
    }
    output.set_len(0)?;
    output.write_all(
        crate::provenance::zone_identifier_text(marks, mode)
            .unwrap_or_default()
            .as_bytes(),
    )?;
    output.sync_all()?;
    Ok(vec![zeus_types::OsMetadataKind::ZoneIdentifier])
}

pub(crate) fn directory_free_space(parent: &cap_std::fs::Dir) -> FsResult<u64> {
    use windows_sys::{
        Wdk::Storage::FileSystem::{FileFsFullSizeInformation, NtQueryVolumeInformationFile},
        Win32::{Foundation::RtlNtStatusToDosError, System::IO::IO_STATUS_BLOCK},
    };
    // FILE_FS_FULL_SIZE_INFORMATION's documented C layout (three LARGE_INTEGER, two ULONG).
    #[repr(C, align(8))]
    #[derive(Default)]
    struct FullSize {
        total: i64,
        caller_available: i64,
        actual_available: i64,
        sectors: u32,
        bytes: u32,
    }
    let mut size = FullSize::default();
    let mut io = IO_STATUS_BLOCK::default();
    // SAFETY: synchronous live directory handle and fully sized writable C-layout output.
    let status = unsafe {
        NtQueryVolumeInformationFile(
            parent.as_raw_handle(),
            &mut io,
            (&mut size as *mut FullSize).cast(),
            std::mem::size_of::<FullSize>() as u32,
            FileFsFullSizeInformation,
        )
    };
    if status < 0 {
        return Err(std::io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32
        )
        .into());
    }
    Ok((size.caller_available.max(0) as u64)
        .saturating_mul(size.sectors as u64)
        .saturating_mul(size.bytes as u64))
}

/// Query allocation and link count without reopening a path. A failed optional query is unknown.
pub(crate) fn storage_observation(file: &std::fs::File) -> (Option<u64>, Option<u64>) {
    let mut compression = std::mem::MaybeUninit::<FILE_COMPRESSION_INFO>::uninit();
    // SAFETY: retained live handle, correct structure/class/size; read only after API success.
    let allocated = if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileCompressionInfo,
            compression.as_mut_ptr().cast(),
            std::mem::size_of::<FILE_COMPRESSION_INFO>() as u32,
        )
    } != 0
    {
        // SAFETY: initialized by the successful call above.
        u64::try_from(unsafe { compression.assume_init() }.CompressedFileSize).ok()
    } else {
        None
    };
    let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: live handle and writable output buffer; inspect only on success.
    let links =
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } != 0 {
            // SAFETY: initialized by the successful call above.
            Some(u64::from(unsafe { info.assume_init() }.nNumberOfLinks))
        } else {
            None
        };
    (allocated, links)
}
