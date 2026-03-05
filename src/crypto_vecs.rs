pub mod traits;

mod base64;
mod block_bytes;
mod blocks;
mod bytes;
mod hexadecimal;
mod unicode;

// ----------------

use std::{marker, vec};

use crate::crypto_vecs;

pub use crate::crypto_vecs::block_bytes::BlockBytes;
pub use crate::crypto_vecs::blocks::Blocks;

// ----------------

fn bits_to_bytes(bits: usize) -> usize {
    assert!(
        bits.is_multiple_of(8),
        "{} bits are not divisible by 8",
        bits
    );

    bits / 8
}

// ----------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Base64;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Bytes;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Hexadecimal;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Unicode;

// ----------------

pub type Base64Type = crypto_vecs::CryptoString<Base64>;
pub type BytesType = crypto_vecs::CryptoVec<Bytes>;
pub type HexadecimalType = crypto_vecs::CryptoString<self::Hexadecimal>;
pub type UnicodeType = crypto_vecs::CryptoString<self::Unicode>;

// ----------------

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct CryptoString<P> {
    data: String,
    struct_type: marker::PhantomData<P>,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct CryptoVec<P> {
    data: Vec<u8>,
    struct_type: marker::PhantomData<P>,
}

#[derive(Clone)]
pub struct CryptoVecIter<'a> {
    vec_ref: &'a Vec<u8>,
    current_index: usize,
}

// ----------------

impl<P> self::CryptoVec<P> {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            struct_type: marker::PhantomData,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            struct_type: marker::PhantomData,
        }
    }

    pub fn with_capacity_bits(capacity_bits: usize) -> Self {
        let bytes = crypto_vecs::bits_to_bytes(capacity_bits);

        Self::with_capacity(bytes)
    }

    pub const fn capacity(&self) -> usize {
        self.data.capacity()
    }
}

impl<P> IntoIterator for self::CryptoVec<P> {
    type Item = u8;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<'a> Iterator for self::CryptoVecIter<'a> {
    type Item = &'a u8;

    fn next(&mut self) -> Option<Self::Item> {
        let element = self.vec_ref.get(self.current_index);
        self.current_index += 1;

        element
    }
}

impl<'a> ExactSizeIterator for self::CryptoVecIter<'a> {
    fn len(&self) -> usize {
        let number_of_elements = self.vec_ref.len();
        let bounded_index = self.current_index.min(number_of_elements);

        number_of_elements - bounded_index
    }
}

impl<P> self::CryptoVec<P> {
    pub fn iter(&self) -> self::CryptoVecIter<'_> {
        self::CryptoVecIter {
            vec_ref: &self.data,
            current_index: 0,
        }
    }
}

// ----------------

impl<P> CryptoString<P> {
    pub fn new() -> Self {
        Self {
            data: String::new(),
            struct_type: marker::PhantomData,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: String::with_capacity(capacity),
            struct_type: marker::PhantomData,
        }
    }

    pub fn with_capacity_bits(capacity_bits: usize) -> Self {
        let bytes = crypto_vecs::bits_to_bytes(capacity_bits);

        Self::with_capacity(bytes)
    }

    pub const fn capacity(&self) -> usize {
        self.data.capacity()
    }
}
