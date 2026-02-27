/*! Canonical SHA-256 hashing utility for MoonBlokz chain types. */

use sha2::{Digest, Sha256};

/// Fixed size in bytes for SHA-256 hashes.
pub const HASH_SIZE: usize = 32;

/// Calculates the SHA-256 hash for the provided bytes.
///
/// Parameters:
/// - `input`: byte slice to hash.
///
/// Example:
/// ```
/// use moonblokz_chain_types::{calculate_hash, HASH_SIZE};
///
/// let hash = calculate_hash(b"moonblokz");
/// assert_eq!(hash.len(), HASH_SIZE);
/// ```
pub fn calculate_hash(input: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let digest = hasher.finalize();

    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculates_sha256_for_known_vector() {
        let hash = calculate_hash(b"abc");
        assert_eq!(
            hash,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
    }

    #[test]
    fn calculates_sha256_for_empty_input() {
        let hash = calculate_hash(&[]);
        assert_eq!(
            hash,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
    }
}
