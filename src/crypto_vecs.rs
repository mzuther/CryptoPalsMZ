pub mod traits;

// ----------------

mod generic_string;
mod generic_vec;

pub use crate::crypto_vecs::block_bytes::BlockBytes;
pub use crate::crypto_vecs::blocks::Blocks;

// ----------------

mod base64;
mod block_bytes;
mod blocks;
mod bytes;
mod hexadecimal;
mod unicode;

// ----------------

pub use crate::crypto_vecs::generic_string::{Base64Type, CryptoString, HexadecimalType, UnicodeType};
pub use crate::crypto_vecs::generic_vec::{BytesType, CryptoVec};

// ----------------

fn bits_to_bytes(bits: usize) -> usize {
    assert!(
        bits.is_multiple_of(8),
        "{} bits are not divisible by 8",
        bits
    );

    bits / 8
}
