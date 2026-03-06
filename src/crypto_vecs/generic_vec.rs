use std::{convert, marker, slice, vec};

use crate::crypto_vecs;
use crate::crypto_vecs::traits::LenBytes;

// ----------------

#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd)]
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

#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Bytes;

pub type BytesType = crypto_vecs::CryptoVec<Bytes>;

// ----------------

impl<P> convert::From<Vec<u8>> for self::CryptoVec<P>
where
    P: Clone,
{
    fn from(data: Vec<u8>) -> Self {
        Self::new_from(data)
    }
}

impl<P> convert::From<&[u8]> for self::CryptoVec<P>
where
    P: Clone,
{
    fn from(data: &[u8]) -> Self {
        Self::new_from(data.to_vec())
    }
}

impl<P> convert::From<u8> for self::CryptoVec<P>
where
    P: Clone,
{
    fn from(element: u8) -> Self {
        Self::new_from(vec![element])
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

impl<P> self::CryptoVec<P>
where
    P: Clone,
{
    pub fn new_from(data: Vec<u8>) -> Self {
        Self {
            data,
            struct_type: marker::PhantomData,
        }
    }

    pub fn new() -> Self {
        Self::new_from(Default::default())
    }

    pub fn with_capacity(bytes: usize) -> Self {
        Self::new_from(Vec::with_capacity(bytes))
    }

    pub fn with_capacity_bits(bits: usize) -> Self {
        let capacity = crypto_vecs::bits_to_bytes(bits);

        Self::new_from(Vec::with_capacity(capacity))
    }

    pub const fn capacity(&self) -> usize {
        self.data.capacity()
    }

    // ----------------

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn iter(&self) -> self::CryptoVecIter<'_> {
        self::CryptoVecIter {
            vec_ref: &self.data,
            current_index: 0,
        }
    }

    // ----------------

    pub fn chunks(&self, chunk_size: usize) -> Vec<Self> {
        assert!(chunk_size > 0, "chunk size must be non-zero");

        self.data
            .chunks(chunk_size)
            .fold(Default::default(), |mut acc, chunk| {
                acc.push(Self::from(chunk));
                acc
            })
    }

    pub fn rchunks(&self, chunk_size: usize) -> Vec<Self> {
        assert!(chunk_size > 0, "chunk size must be non-zero");

        self.data
            .rchunks(chunk_size)
            .fold(Default::default(), |mut acc, chunk| {
                acc.push(Self::from(chunk));
                acc
            })
    }

    // reference to array
    pub const fn as_slice(&self) -> &[u8] {
        self.data.as_slice()
    }

    // reference to mutable array
    pub const fn as_mut_slice(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }

    // clone of underlying vec
    pub fn to_vec(&self) -> Vec<u8> {
        self.data.to_vec()
    }

    // ----------------
    // TODO: add tests
    pub fn get<I>(&self, index: I) -> Option<&I::Output>
    where
        I: slice::SliceIndex<[u8]>,
    {
        self.data.get(index)
    }

    pub fn first_n(&self, length: usize) -> Option<Self> {
        assert!(length > 0);

        self.chunks(length).first().cloned()
    }

    pub fn last_n(&self, length: usize) -> Option<Self> {
        assert!(length > 0);

        self.rchunks(length).first().cloned()
    }

    // ----------------

    pub fn push(&mut self, byte: u8) {
        self.data.push(byte);
    }
}

impl<P> LenBytes for CryptoVec<P> {
    fn len_bytes(&self) -> usize {
        self.data.len()
    }
}

impl<P> AsMut<Vec<u8>> for CryptoVec<P> {
    // reference to mutable vec
    fn as_mut(&mut self) -> &mut Vec<u8> {
        self.data.as_mut()
    }
}

impl<P> AsRef<Vec<u8>> for CryptoVec<P> {
    // reference to vec
    fn as_ref(&self) -> &Vec<u8> {
        self.data.as_ref()
    }
}

impl<P> Extend<u8> for CryptoVec<P> {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = u8>,
    {
        self.data.extend(iter);
    }
}

impl<'a, P> Extend<&'a u8> for CryptoVec<P> {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = &'a u8>,
    {
        self.data.extend(iter);
    }
}
