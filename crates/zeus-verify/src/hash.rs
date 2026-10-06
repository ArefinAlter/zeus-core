//! Incremental dual hashing: SHA-256 (what people compare against published checksums) and BLAKE3
//! (what the audit chain uses and what is fast), computed in one pass over the bytes.
//!
//! Hashes of a finished download are always computed from the bytes **on disk**, never from the
//! buffers handed to `pwrite`, so write-path corruption is caught (03 section 8.1 step F0, I8).
#![expect(
    unused_variables,
    reason = "skeleton: verify_file is filled in by the zeus-verify implementation task"
)]

use std::path::Path;

use sha2::{Digest as _, Sha256};
use zeus_types::Hex256;

use crate::error::{VerifyError, VerifyResult};

/// Both digests of a byte stream and its length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Digests {
    /// SHA-256.
    pub sha256: Hex256,
    /// BLAKE3 (default 32-byte output, unkeyed).
    pub blake3: Hex256,
    /// Number of bytes hashed.
    pub size_bytes: u64,
}

/// An incremental SHA-256 + BLAKE3 hasher.
#[derive(Clone)]
pub struct DualHasher {
    sha256: Sha256,
    blake3: blake3::Hasher,
    size: u64,
}

impl DualHasher {
    /// A hasher over zero bytes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sha256: Sha256::new(),
            blake3: blake3::Hasher::new(),
            size: 0,
        }
    }

    /// Feeds bytes to both hashes.
    pub fn update(&mut self, bytes: &[u8]) {
        self.sha256.update(bytes);
        self.blake3.update(bytes);
        self.size += bytes.len() as u64;
    }

    /// Bytes hashed so far.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size
    }

    /// Finishes and returns both digests.
    #[must_use]
    pub fn finalize(self) -> Digests {
        let sha: [u8; 32] = self.sha256.finalize().into();
        Digests {
            sha256: Hex256::from_bytes(sha),
            blake3: Hex256::from_bytes(*self.blake3.finalize().as_bytes()),
            size_bytes: self.size,
        }
    }
}

impl Default for DualHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for DualHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DualHasher")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

/// Hashes a byte slice in one call.
#[must_use]
pub fn hash_bytes(bytes: &[u8]) -> Digests {
    let mut h = DualHasher::new();
    h.update(bytes);
    h.finalize()
}

/// Constant-time equality of two digests, for comparing against an expected value supplied by a caller.
#[must_use]
pub fn digests_equal(a: &Hex256, b: &Hex256) -> bool {
    a.as_bytes()
        .iter()
        .zip(b.as_bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Progress of [`verify_file`], reported at most every `progress_every_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashProgress {
    /// Bytes hashed so far (becomes `Progress.bytes_done` during `verifying`).
    pub bytes_done: u64,
    /// Total bytes expected.
    pub bytes_total: u64,
}

/// Options of [`verify_file`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyFileOptions {
    /// Read buffer size (default 1 MiB).
    pub buffer_bytes: usize,
    /// Report progress after this many bytes (default 8 MiB).
    pub progress_every_bytes: u64,
}

impl Default for VerifyFileOptions {
    fn default() -> Self {
        Self {
            buffer_bytes: 1 << 20,
            progress_every_bytes: 8 << 20,
        }
    }
}

/// Hashes the file at `path` from disk, reporting progress, and returns both digests plus the first
/// bytes for content sniffing (up to 8 KiB). Blocking: call it from a blocking task. Cancel by
/// returning `false` from `progress`.
pub fn verify_file(
    path: &Path,
    options: &VerifyFileOptions,
    progress: &mut dyn FnMut(HashProgress) -> bool,
) -> VerifyResult<(Digests, Vec<u8>)> {
    Err(VerifyError::NotImplemented("verify_file"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const BLAKE3_EMPTY: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn known_answer_vectors() {
        let empty = hash_bytes(b"");
        assert_eq!(empty.sha256.to_hex(), SHA256_EMPTY);
        assert_eq!(empty.blake3.to_hex(), BLAKE3_EMPTY);
        assert_eq!(empty.size_bytes, 0);
        assert_eq!(hash_bytes(b"abc").sha256.to_hex(), SHA256_ABC);
    }

    #[test]
    fn incremental_equals_one_shot() {
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let mut h = DualHasher::new();
        for chunk in data.chunks(4099) {
            h.update(chunk);
        }
        assert_eq!(h.size_bytes(), 100_000);
        assert_eq!(h.finalize(), hash_bytes(&data));
    }

    #[test]
    fn constant_time_comparison() {
        let a = hash_bytes(b"a").sha256;
        assert!(digests_equal(&a, &a));
        assert!(!digests_equal(&a, &hash_bytes(b"b").sha256));
    }
}
