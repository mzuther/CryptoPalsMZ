use std::{convert, fmt, slice, vec};

use crate::crypto_vecs::traits::{
    FromBytes, InternalData, InternalDataVec, InternalDataVecMut, LenBytes, ToBytes,
};
use crate::crypto_vecs::{Bytes, BytesType};

// ================

#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct CryptoVec<C, E>
where
    C: InternalData<Element = E, Collection = Vec<E>>,
{
    collection: C,
}

#[derive(Clone)]
pub struct CryptoVecIter<'a, E> {
    vec_ref: &'a Vec<E>,
    current_index: usize,
}

// ================

impl<C, E> InternalData for CryptoVec<C, E>
where
    C: InternalDataVec<Element = E, Collection = Vec<E>>,
    E: Clone,
{
    type Element = E;
    type Collection = Vec<E>;

    fn new_from(data: Self::Collection) -> Self {
        Self {
            collection: C::new_from(data),
        }
    }

    fn from_literal(string_literal: &str) -> Self {
        Self {
            collection: C::from_literal(string_literal),
        }
    }

    fn with_capacity(bytes: usize) -> Self {
        Self::new_from(Self::Collection::with_capacity(bytes))
    }

    fn capacity(&self) -> usize {
        self.collection.capacity()
    }

    fn clean_and_validate(data: Vec<E>) -> Result<Vec<E>, String> {
        C::clean_and_validate(data)
    }

    // ----------------

    fn elements(&self) -> impl Iterator<Item = Self::Element> {
        self.collection.elements()
    }

    fn representation_name(&self) -> &str {
        self.collection.representation_name()
    }

    fn representation(&self) -> String {
        self.collection.representation()
    }
}

// ----------------

impl<C, E> InternalDataVec for CryptoVec<C, E>
where
    C: InternalDataVec<Element = E>,
    E: Clone,
{
    fn data(&self) -> &Vec<E> {
        self.collection.data()
    }

    fn chunks(&self, chunk_size: usize) -> slice::Chunks<'_, E> {
        assert!(chunk_size > 0, "chunk size must be non-zero");

        self.collection.chunks(chunk_size)
    }

    fn rchunks(&self, chunk_size: usize) -> slice::RChunks<'_, E> {
        assert!(chunk_size > 0, "chunk size must be non-zero");

        self.collection.rchunks(chunk_size)
    }

    // ----------------

    fn get(&self, index: usize) -> Option<&E> {
        self.collection.get(index)
    }
}

// ----------------

impl<C, E> InternalDataVecMut for CryptoVec<C, E>
where
    C: InternalDataVecMut<Element = E>,
    E: Clone,
{
    fn data_mut(&mut self) -> &mut Vec<Self::Element> {
        self.collection.data_mut()
    }

    fn push(&mut self, value: Self::Element) {
        self.collection.push(value)
    }
}

// ----------------

impl<C, E> fmt::Display for CryptoVec<C, E>
where
    C: InternalData<Element = E, Collection = Vec<E>> + InternalDataVec,
    E: Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{:02}] {{ {} }}",
            self.representation_name(),
            self.collection.len(),
            self.representation()
        )
    }
}

impl<C, E> fmt::Debug for CryptoVec<C, E>
where
    C: InternalData<Element = E, Collection = Vec<E>> + InternalDataVec,
    E: Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

// ----------------

impl<C, E> FromBytes for CryptoVec<C, E>
where
    C: InternalData<Element = E, Collection = Vec<E>> + FromBytes,
{
    fn from_bytes(bytes: &BytesType) -> Self {
        Self {
            collection: C::from_bytes(bytes),
        }
    }
}

impl<C, E> ToBytes for CryptoVec<C, E>
where
    C: InternalData<Element = E, Collection = Vec<E>> + ToBytes,
{
    fn to_bytes_raw(&self) -> Bytes {
        self.collection.to_bytes_raw()
    }
}

// ----------------

impl<C, E> IntoIterator for self::CryptoVec<C, E>
where
    C: IntoIterator<IntoIter = std::vec::IntoIter<E>>
        + InternalData<Element = E, Collection = Vec<E>>,
{
    type Item = E;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.collection.into_iter()
    }
}

impl<C, E> IntoIterator for &self::CryptoVec<C, E>
where
    C: Clone
        + IntoIterator<IntoIter = std::vec::IntoIter<E>>
        + InternalData<Element = E, Collection = Vec<E>>,
{
    type Item = E;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.collection.clone().into_iter()
    }
}

impl<'a, E> Iterator for self::CryptoVecIter<'a, E> {
    type Item = &'a E;

    fn next(&mut self) -> Option<Self::Item> {
        let element = self.vec_ref.get(self.current_index);
        self.current_index += 1;

        element
    }
}

impl<'a, E> ExactSizeIterator for self::CryptoVecIter<'a, E> {
    fn len(&self) -> usize {
        let number_of_elements = self.vec_ref.len();
        let bounded_index = self.current_index.min(number_of_elements);

        number_of_elements - bounded_index
    }
}

// ----------------

impl<C, E> LenBytes for CryptoVec<C, E>
where
    C: InternalData<Element = E, Collection = Vec<E>>,
{
    fn len_bytes(&self) -> usize {
        self.collection.len()
    }
}

// ----------------

impl<C, E> convert::AsMut<Vec<E>> for CryptoVec<C, E>
where
    C: AsMut<Vec<E>> + InternalData<Element = E, Collection = Vec<E>>,
{
    fn as_mut(&mut self) -> &mut Vec<E> {
        self.collection.as_mut()
    }
}

impl<C, E> convert::AsRef<Vec<E>> for CryptoVec<C, E>
where
    C: AsRef<Vec<E>> + InternalData<Element = E, Collection = Vec<E>>,
{
    fn as_ref(&self) -> &Vec<E> {
        self.collection.as_ref()
    }
}

// ----------------

impl<C, E> Extend<E> for CryptoVec<C, E>
where
    C: Extend<E> + InternalData<Element = E, Collection = Vec<E>>,
{
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = E>,
    {
        self.collection.extend(iter);
    }
}

impl<'a, C, E> Extend<&'a E> for CryptoVec<C, E>
where
    C: Extend<E> + InternalData<Element = E, Collection = Vec<E>>,
    E: Copy,
{
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = &'a E>,
    {
        self.collection.extend(iter.into_iter().copied());
    }
}

// ----------------

impl<C, E> self::CryptoVec<C, E>
where
    C: Clone + InternalDataVecMut<Element = E>,
    E: Clone,
{
    pub fn iter(&self) -> self::CryptoVecIter<'_, E> {
        self::CryptoVecIter {
            vec_ref: self.collection.data(),
            current_index: 0,
        }
    }
}
