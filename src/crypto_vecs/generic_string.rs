use std::marker;

use crate::crypto_vecs;

// ----------------

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct CryptoString<P> {
    data: String,
    struct_type: marker::PhantomData<P>,
}

// ----------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Base64;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Hexadecimal;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Unicode;

pub type Base64Type = CryptoString<Base64>;
pub type HexadecimalType = CryptoString<self::Hexadecimal>;
pub type UnicodeType = CryptoString<self::Unicode>;

// ----------------

impl<P> CryptoString<P> {
    #[inline]
    pub fn new_from(data: String) -> Self {
        Self {
            data,
            struct_type: marker::PhantomData,
        }
    }

    pub fn new() -> Self {
        Self::new_from(String::new())
    }

    pub fn with_capacity(bytes: usize) -> Self {
        Self::new_from(String::with_capacity(bytes))
    }

    pub fn with_capacity_bits(bits: usize) -> Self {
        let bytes = crypto_vecs::bits_to_bytes(bits);

        Self::new_from(String::with_capacity(bytes))
    }

    pub const fn capacity(&self) -> usize {
        self.data.capacity()
    }

    // ----------------

    pub fn data(&self) -> &str {
        &self.data
    }
}
