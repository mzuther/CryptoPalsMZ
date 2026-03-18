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
    collection: C,
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
    E: Clone,
{
    type Element = E;

    fn new_from(data: Vec<E>) -> Self {
        Self {
            collection: C::new_from(data),
        }
    }

    fn capacity(&self) -> usize {
        self.collection.capacity()
    }

    fn clean_and_validate(data: Vec<E>) -> Result<Vec<E>, String> {
        C::clean_and_validate(data)
    }

    // ----------------

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
    C: Elements<Element = E> + InternalDataVec<Element = E> + InternalDataVecMut<Element = E>,
{
    type Element = E;

    fn data_mut(&mut self) -> &mut Vec<Self::Element> {
        self.collection.data_mut()
    }

    fn push(&mut self, value: Self::Element) {
        self.collection.push(value)
    }
}

// ----------------

impl<C, E> Elements for CryptoVec<C, E>
where
    C: InternalDataVec + Elements<Element = E>,
{
    type Element = E;

    fn elements(&self) -> impl Iterator<Item = Self::Element> {
        self.collection.elements()
    }
}

// ----------------

impl<C, E> Representation for CryptoVec<C, E>
where
    C: Representation + Elements<Element = E>,
{
    fn representation_name(&self) -> &str {
        self.collection.representation_name()
    }

    fn representation(&self) -> String {
        self.collection.representation()
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
            "{}[{:02}] {{ {} }}",
            self.representation_name(),
            self.collection.len(),
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
    E: Clone,
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
        Self::new_from_ref(data)
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
            collection: C::from_bytes(bytes),
        }
    }
}

impl<C, E> ToBytes for CryptoVec<C, E>
where
    C: Elements<Element = E> + ToBytes,
{
    fn to_bytes(&self) -> BytesType {
        self.collection.to_bytes()
    }
}

// ----------------

impl<C, E> IntoIterator for self::CryptoVec<C, E>
where
    C: IntoIterator<IntoIter = std::vec::IntoIter<E>> + Elements<Element = E>,
{
    type Item = E;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.collection.into_iter()
    }
}

impl<C, E> IntoIterator for &self::CryptoVec<C, E>
where
    C: Clone + IntoIterator<IntoIter = std::vec::IntoIter<E>> + Elements<Element = E>,
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
    C: Elements<Element = E>,
{
    fn len_bytes(&self) -> usize {
        self.collection.len()
    }
}

// ----------------

impl<C, E> convert::AsMut<Vec<E>> for CryptoVec<C, E>
where
    C: AsMut<Vec<E>> + Elements<Element = E>,
{
    fn as_mut(&mut self) -> &mut Vec<E> {
        self.collection.as_mut()
    }
}

impl<C, E> convert::AsRef<Vec<E>> for CryptoVec<C, E>
where
    C: AsRef<Vec<E>> + Elements<Element = E>,
{
    fn as_ref(&self) -> &Vec<E> {
        self.collection.as_ref()
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
        self.collection.extend(iter);
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
        self.collection.extend(iter.into_iter().copied());
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
            vec_ref: self.collection.data(),
            current_index: 0,
        }
    }
}
