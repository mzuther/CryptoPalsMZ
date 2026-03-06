pub mod traits;

// ----------------

mod generic_string;
mod generic_vec;

mod base64;
mod block_bytes;
mod blocks;
mod bytes;
mod hexadecimal;
mod unicode;

// ----------------

pub use crate::crypto_vecs::generic_string::CryptoString;
pub use crate::crypto_vecs::generic_vec::CryptoVec;

pub use crate::crypto_vecs::base64::Base64Type;
pub use crate::crypto_vecs::block_bytes::BlockBytes;
pub use crate::crypto_vecs::blocks::Blocks;
pub use crate::crypto_vecs::bytes::BytesType;
pub use crate::crypto_vecs::hexadecimal::HexadecimalType;
pub use crate::crypto_vecs::unicode::UnicodeType;

// ================

fn bits_to_bytes(bits: usize) -> usize {
    assert!(
        bits.is_multiple_of(8),
        "{} bits are not divisible by 8",
        bits
    );

    bits / 8
}
