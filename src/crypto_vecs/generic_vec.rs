use std::{convert, fmt, slice, vec};

use crate::crypto_vecs::BytesType;
use crate::crypto_vecs::traits::{
    Elements, FromBytes, InternalDataVec, InternalDataVecMut, LenBytes, Representation, ToBytes,
};

// ================

#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct CryptoVec<C, E>
where
    C: Elements<Element = E>,
{
    data: C,
}

#[derive(Clone)]
pub struct CryptoVecIter<'a, E> {
    vec_ref: &'a Vec<E>,
    current_index: usize,
}

// ================

impl<C, E> InternalDataVec for CryptoVec<C, E>
where
    C: InternalDataVec<Element = E> + Elements<Element = E>,
{
    type Element = E;

    fn new_from(data: Vec<E>) -> Self {
        Self {
            data: C::new_from(data),
        }
    }

    fn capacity(&self) -> usize {
        self.data.capacity()
    }

    fn clean_and_validate(data: Vec<E>) -> Result<Vec<E>, String> {
        C::clean_and_validate(data)
    }

    // ----------------

    fn data(&self) -> &Vec<E> {
        &self.data.data()
    }

    fn chunks(&self, chunk_size: usize) -> slice::Chunks<'_, E> {
        assert!(chunk_size > 0, "chunk size must be non-zero");

        self.data.chunks(chunk_size)
    }

    fn rchunks(&self, chunk_size: usize) -> slice::RChunks<'_, E> {
        assert!(chunk_size > 0, "chunk size must be non-zero");

        self.data.rchunks(chunk_size)
    }

    // ----------------

    fn get(&self, index: usize) -> Option<&E> {
        self.data.get(index)
    }
}

// ----------------

impl<C, E> InternalDataVecMut for CryptoVec<C, E>
where
    C: Elements<Element = E> + InternalDataVec<Element = E> + InternalDataVecMut<Element = E>,
{
    type Element = E;

    fn data_mut(&mut self) -> &mut Vec<Self::Element> {
        let temp = self.data.data_mut();

        temp
    }

    fn push(&mut self, value: Self::Element) {
        self.data.push(value)
    }
}

// ----------------

impl<C, E> Elements for CryptoVec<C, E>
where
    C: InternalDataVec + Elements<Element = E>,
{
    type Element = E;

    fn elements(&self) -> impl Iterator<Item = Self::Element> {
        self.data.elements()
    }
}

// ----------------

impl<C, E> Representation for CryptoVec<C, E>
where
    C: Representation + Elements<Element = E>,
{
    fn representation_name(&self) -> &str {
        self.data.representation_name()
    }

    fn representation(&self) -> String {
        self.data.representation()
    }
}

// ----------------

impl<C, E> fmt::Display for CryptoVec<C, E>
where
    C: Representation + Elements<Element = E>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{}] {{ {} }}",
            self.representation_name(),
            self.data.len(),
            self.representation()
        )
    }
}

impl<C, E> fmt::Debug for CryptoVec<C, E>
where
    C: Elements<Element = E> + Representation,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

// ----------------

impl<C, E> convert::From<Vec<E>> for self::CryptoVec<C, E>
where
    C: InternalDataVec<Element = E> + Elements<Element = E>,
{
    fn from(data: Vec<E>) -> Self {
        Self::new_from(data)
    }
}

impl<C, E> convert::From<&[E]> for self::CryptoVec<C, E>
where
    C: InternalDataVec<Element = E> + Elements<Element = E>,
    E: Clone,
{
    fn from(data: &[E]) -> Self {
        Self::new_from(data.to_vec())
    }
}

impl<C, E> convert::From<E> for self::CryptoVec<C, E>
where
    C: InternalDataVec<Element = E> + Elements<Element = E>,
    E: Clone,
{
    fn from(element: E) -> Self {
        Self::new_from(vec![element])
    }
}

// impl<C, E> convert::From<&BytesType> for CryptoVec<C, E>
// where
//     C: Elements<Element = E> + FromBytes,
// {
//     fn from(bytes: &BytesType) -> Self {
//         Self::from_bytes(bytes)
//     }
// }

// ----------------

impl<C, E> FromBytes for CryptoVec<C, E>
where
    C: Elements<Element = E> + FromBytes,
{
    fn from_bytes(bytes: &BytesType) -> Self {
        Self {
            data: C::from_bytes(bytes),
        }
    }
}

impl<C, E> ToBytes for CryptoVec<C, E>
where
    C: Elements<Element = E> + ToBytes,
{
    fn to_bytes(&self) -> BytesType {
        self.data.to_bytes()
    }
}

// ----------------

impl<C, E> IntoIterator for self::CryptoVec<C, E>
where
    C: IntoIterator<IntoIter = std::vec::IntoIter<E>>
        + Elements<Element = E>
        + InternalDataVec<Element = E>
        + InternalDataVecMut<Element = E>,
{
    type Item = E;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
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
    C: Elements<Element = E>,
{
    fn len_bytes(&self) -> usize {
        self.data.len()
    }
}

// ----------------

impl<C, E> convert::AsMut<Vec<E>> for CryptoVec<C, E>
where
    C: AsMut<Vec<E>>
        + Elements<Element = E>
        + InternalDataVec<Element = E>
        + InternalDataVecMut<Element = E>,
{
    // reference to mutable vec
    fn as_mut(&mut self) -> &mut Vec<E> {
        self.data.as_mut()
    }
}

impl<C, E> convert::AsRef<Vec<E>> for CryptoVec<C, E>
where
    C: Clone
        + Elements<Element = E>
        + InternalDataVec<Element = E>
        + InternalDataVecMut<Element = E>,
    E: Clone,
{
    // reference to vec
    fn as_ref(&self) -> &Vec<E> {
        self.data().as_ref()
    }
}

// ----------------

impl<C, E> Extend<E> for CryptoVec<C, E>
where
    C: Extend<E> + Elements<Element = E>,
{
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = E>,
    {
        self.data.extend(iter);
    }
}

impl<'a, C, E> Extend<&'a E> for CryptoVec<C, E>
where
    C: Extend<E> + Elements<Element = E>,
    E: Copy,
{
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = &'a E>,
    {
        self.data.extend(iter.into_iter().copied());
    }
}

// ----------------

impl<C, E> self::CryptoVec<C, E>
where
    C: Clone
        + Elements<Element = E>
        + InternalDataVec<Element = E>
        + InternalDataVecMut<Element = E>,
    E: Clone,
{
    pub fn iter(&self) -> self::CryptoVecIter<'_, E> {
        self::CryptoVecIter {
            vec_ref: &self.data.data(),
            current_index: 0,
        }
    }

    // ----------------

    pub fn chunks_as_collection(&self, chunk_size: usize) -> Vec<Self> {
        self.data
            .chunks(chunk_size)
            .map(|chunk| Self::new_from(chunk.to_vec()))
            .collect()
    }

    pub fn rchunks_as_collection(&self, chunk_size: usize) -> Vec<Self> {
        self.data
            .rchunks(chunk_size)
            .map(|chunk| Self::new_from(chunk.to_vec()))
            .collect()
    }

    pub fn first_n_as_collection(&self, length: usize) -> Option<Self> {
        self.first_n(length).map(|x| Self::new_from(x.to_vec()))
    }

    pub fn last_n_as_collection(&self, length: usize) -> Option<Self> {
        self.last_n(length).map(|x| Self::new_from(x.to_vec()))
    }

    // clone of underlying vec
    pub fn to_vec(&self) -> Vec<E> {
        self.data().to_vec()
    }
}
