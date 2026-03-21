use std::{convert, fmt, slice};

use crate::crypto_vecs::traits::{FromBytes, InternalData, LenBytes, ToBytes};
use crate::crypto_vecs::{Bytes, BytesType};

// ================

#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct CryptoString<C>
where
    C: InternalData,
{
    collection: C,
}

// ================

impl<C, E> InternalData for CryptoString<C>
where
    C: InternalData<Element = E, Collection = String>,
    E: Clone,
{
    type Element = E;
    type Collection = String;

    fn new_from(data: String) -> Self {
        Self {
            collection: C::new_from(data),
        }
    }

    fn new_from_elements(elements: &[Self::Element]) -> Self {
        Self {
            collection: C::new_from_elements(elements),
        }
    }

    fn from_literal(string_literal: &str) -> Self {
        Self {
            collection: C::from_literal(string_literal),
        }
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            collection: C::with_capacity(capacity),
        }
    }

    fn capacity(&self) -> usize {
        self.collection.capacity()
    }

    fn clean_and_validate(data: String) -> Result<String, String> {
        C::clean_and_validate(data)
    }

    // ----------------

    fn elements(&self) -> impl Iterator<Item = &Self::Element> {
        self.collection.elements()
    }

    fn collection(&self) -> Self::Collection {
        self.collection.collection()
    }

    fn collection_as_ref(&self) -> &Self::Collection {
        self.collection.collection_as_ref()
    }

    fn chunks(&self, chunk_size: usize) -> slice::Chunks<'_, E> {
        self.collection.chunks(chunk_size)
    }

    fn rchunks(&self, chunk_size: usize) -> slice::RChunks<'_, E> {
        self.collection.rchunks(chunk_size)
    }

    // ----------------

    fn representation_name(&self) -> &str {
        self.collection.representation_name()
    }

    fn representation(&self) -> String {
        self.collection.representation()
    }
}

// ----------------

impl<C> fmt::Display for CryptoString<C>
where
    C: InternalData<Collection = String>,
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

impl<C> fmt::Debug for CryptoString<C>
where
    C: InternalData<Collection = String>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

// ----------------

impl<C> convert::From<&BytesType> for CryptoString<C>
where
    C: InternalData + FromBytes,
{
    fn from(bytes: &BytesType) -> Self {
        Self::from_bytes(bytes)
    }
}

// ----------------

impl<C> convert::AsRef<str> for CryptoString<C>
where
    C: AsRef<str> + InternalData,
{
    fn as_ref(&self) -> &str {
        self.collection.as_ref()
    }
}

// ----------------

impl<C> LenBytes for CryptoString<C>
where
    C: InternalData + LenBytes,
{
    fn len_bytes(&self) -> usize {
        self.collection.len_bytes()
    }
}

// ----------------

impl<C> FromBytes for CryptoString<C>
where
    C: InternalData + FromBytes,
{
    fn from_bytes(bytes: &BytesType) -> Self {
        Self {
            collection: C::from_bytes(bytes),
        }
    }
}

impl<C> ToBytes for CryptoString<C>
where
    C: InternalData + ToBytes,
{
    fn to_bytes_raw(&self) -> Bytes {
        self.collection.to_bytes_raw()
    }
}
