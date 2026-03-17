use std::{convert, fmt};

use crate::crypto_vecs::BytesType;
use crate::crypto_vecs::traits::{
    Elements, FromBytes, InternalData, LenBytes, Representation, ToBytes,
};

// ================

#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct CryptoString<C>
where
    C: InternalData,
{
    collection: C,
}

// ================

impl<C> InternalData for CryptoString<C>
where
    C: InternalData<Collection = String>,
{
    type Collection = String;

    fn new_from(data: String) -> Self {
        Self {
            collection: C::new_from(data),
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
}

// ----------------

impl<C, E> Elements for CryptoString<C>
where
    C: InternalData + Elements<Element = E>,
{
    type Element = E;

    fn elements(&self) -> impl Iterator<Item = Self::Element> {
        self.collection.elements()
    }

    // implemented for "Hexadecimal"
    fn len(&self) -> usize {
        self.collection.len()
    }
}

// ----------------

impl<C> Representation for CryptoString<C>
where
    C: InternalData + Representation,
{
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
    C: InternalData + Elements + Representation,
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
    C: InternalData + Elements + Representation,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

// ----------------

impl<C> convert::From<String> for CryptoString<C>
where
    C: InternalData<Collection = String>,
{
    fn from(data: String) -> Self {
        Self::new_from(data)
    }
}

impl<C> convert::From<&str> for CryptoString<C>
where
    C: InternalData<Collection = String>,
{
    fn from(data: &str) -> Self {
        Self::new_from(data.to_string())
    }
}

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
    fn to_bytes(&self) -> BytesType {
        self.collection.to_bytes()
    }
}
