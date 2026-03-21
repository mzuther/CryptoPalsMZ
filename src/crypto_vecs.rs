pub mod traits;

// ----------------

mod base64;
mod blocks;
mod byte_blocks;
mod bytes;
mod hexadecimal;
mod unicode;

// ----------------

pub use crate::crypto_vecs::base64::Base64;
pub use crate::crypto_vecs::blocks::Blocks;
pub use crate::crypto_vecs::byte_blocks::ByteBlocks;
pub use crate::crypto_vecs::bytes::Bytes;
pub use crate::crypto_vecs::hexadecimal::Hexadecimal;
pub use crate::crypto_vecs::unicode::Unicode;

// ================

pub fn bits_to_bytes(bits: usize) -> usize {
    assert!(
        bits.is_multiple_of(8),
        "{} bits are not divisible by 8",
        bits
    );

    bits / 8
}
