//! Detection of cloud-synchronised, network and removable destinations (04 section 6.5 item 4).
//!
//! Attributes written to such folders can be uploaded or copied to other machines and other people, so
//! the provenance mode is lowered to `mark_only` there. Detection is a heuristic on the path (and, in the
//! implementation, the file-system type); a miss is acceptable, a false positive only lowers privacy-
//! sensitive metadata.

use std::path::Path;

/// A cloud sync client that mirrors a folder to other devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CloudProvider {
    /// Microsoft OneDrive.
    OneDrive,
    /// Dropbox.
    Dropbox,
    /// Apple iCloud Drive.
    ICloudDrive,
    /// Google Drive (Drive for desktop).
    GoogleDrive,
}

/// Returns the provider whose well-known folder name appears as a path component, if any.
///
/// Skeleton behaviour: component-name matching only (`OneDrive`, `OneDrive - <org>`, `Dropbox`,
/// `iCloudDrive`, `Mobile Documents` with `com~apple~CloudDocs`, `Google Drive`, `GoogleDrive`),
/// case-insensitive. The implementation task adds file-system type and network-share detection.
#[must_use]
pub fn detect_cloud_synced(path: &Path) -> Option<CloudProvider> {
    for component in path.to_string_lossy().split(['/', '\\']) {
        let name = component.to_lowercase();
        let found = if name == "onedrive" || name.starts_with("onedrive - ") {
            Some(CloudProvider::OneDrive)
        } else if name == "dropbox" || name.starts_with("dropbox (") {
            Some(CloudProvider::Dropbox)
        } else if name == "iclouddrive" || name == "com~apple~clouddocs" {
            Some(CloudProvider::ICloudDrive)
        } else if name == "google drive" || name == "googledrive" {
            Some(CloudProvider::GoogleDrive)
        } else {
            None
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_folders() {
        let d = |p: &str| detect_cloud_synced(Path::new(p));
        assert_eq!(
            d("C:\\Users\\ada\\OneDrive\\Documents\\a.pdf"),
            Some(CloudProvider::OneDrive)
        );
        assert_eq!(
            d("C:\\Users\\ada\\OneDrive - Contoso\\a.pdf"),
            Some(CloudProvider::OneDrive)
        );
        assert_eq!(d("/home/ada/Dropbox/a.pdf"), Some(CloudProvider::Dropbox));
        assert_eq!(
            d("/Users/ada/Library/Mobile Documents/com~apple~CloudDocs/a.pdf"),
            Some(CloudProvider::ICloudDrive)
        );
        assert_eq!(d("/home/ada/Downloads/a.pdf"), None);
        assert_eq!(d("/home/ada/dropbox-backup/a.pdf"), None);
    }
}
