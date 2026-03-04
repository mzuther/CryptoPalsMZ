mod base64;
mod block_bytes;
mod blocks;
mod bytes;
mod hexadecimal;
mod unicode;

// ----------------

pub use crate::crypto_vecs::base64::Base64;
pub use crate::crypto_vecs::block_bytes::BlockBytes;
pub use crate::crypto_vecs::blocks::Blocks;
pub use crate::crypto_vecs::bytes::Bytes;
pub use crate::crypto_vecs::hexadecimal::Hexadecimal;
pub use crate::crypto_vecs::unicode::Unicode;

// ----------------

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct Base64Type;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct BytesType;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct HexadecimalType;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnicodeType;

// ----------------

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct CryptoVec<T, D> {
    struct_type: T,
    data: D,
}

#[derive(Clone)]
pub struct CryptoVecIter<'a, T, D> {
    data_ref: &'a self::CryptoVec<T, D>,
    current_index: usize,
}

// ----------------

pub trait LenBytes {
    fn len_bytes(&self) -> usize;

    fn len_bits(&self) -> usize {
        self.len_bytes() * 8
    }

    fn is_empty(&self) -> bool {
        self.len_bytes() == 0
    }

    fn bits_to_bytes(bits: usize) -> usize {
        assert!(
            bits.is_multiple_of(8),
            "{} bits are not divisible by 8",
            bits
        );

        bits / 8
    }
}

// ----------------

pub trait ToBytes {
    fn to_bytes(&self) -> self::Bytes;

    fn to_hexadecimal(&self) -> self::Hexadecimal {
        self::Hexadecimal::from(&self.to_bytes())
    }

    fn to_base64(&self) -> self::Base64 {
        self::Base64::from(&self.to_bytes())
    }

    fn to_unicode(&self) -> self::Unicode {
        self::Unicode::from(&self.to_bytes())
    }
}
