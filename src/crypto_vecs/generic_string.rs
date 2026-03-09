use std::{convert, fmt};

use crate::crypto_vecs::BytesType;
use crate::crypto_vecs::traits::{
    Elements, FromBytes, InternalDataString, LenBytes, Representation, ToBytes,
};

// ================

#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct CryptoString<C>
where
    C: InternalDataString,
{
    data: C,
}

// ================

impl<C> InternalDataString for CryptoString<C>
where
    C: InternalDataString,
{
    fn new_from(data: String) -> Self {
        Self {
            data: C::new_from(data),
        }
    }

    fn capacity(&self) -> usize {
        self.data.capacity()
    }

    fn clean_and_validate(data: String) -> Result<String, String> {
        C::clean_and_validate(data)
    }
}

// ----------------

impl<C, E> Elements for CryptoString<C>
where
    C: InternalDataString + Elements<Element = E>,
{
    type Element = E;

    fn elements(&self) -> impl Iterator<Item = Self::Element> {
        self.data.elements()
    }

    // implemented for "Hexadecimal"
    fn len(&self) -> usize {
        self.data.len()
    }
}

// ----------------

impl<C> Representation for CryptoString<C>
where
    C: InternalDataString + Representation,
{
    fn representation_name(&self) -> &str {
        self.data.representation_name()
    }

    fn representation(&self) -> String {
        self.data.representation()
    }
}

// ----------------

impl<C> fmt::Display for CryptoString<C>
where
    C: InternalDataString + Elements + Representation,
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

impl<C> fmt::Debug for CryptoString<C>
where
    C: InternalDataString + Elements + Representation,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

// ----------------

impl<C> convert::From<String> for CryptoString<C>
where
    C: InternalDataString,
{
    fn from(data: String) -> Self {
        Self::new_from(data)
    }
}

impl<C> convert::From<&str> for CryptoString<C>
where
    C: InternalDataString,
{
    fn from(data: &str) -> Self {
        Self::new_from(data.to_string())
    }
}

impl<C> convert::From<&BytesType> for CryptoString<C>
where
    C: InternalDataString + FromBytes,
{
    fn from(bytes: &BytesType) -> Self {
        Self::from_bytes(bytes)
    }
}

// ----------------

impl<C> LenBytes for CryptoString<C>
where
    C: InternalDataString + LenBytes,
{
    fn len_bytes(&self) -> usize {
        self.data.len_bytes()
    }
}

// ----------------

impl<C> FromBytes for CryptoString<C>
where
    C: InternalDataString + FromBytes,
{
    fn from_bytes(bytes: &BytesType) -> Self {
        Self {
            data: C::from_bytes(bytes),
        }
    }
}

impl<C> ToBytes for CryptoString<C>
where
    C: InternalDataString + ToBytes,
{
    fn to_bytes(&self) -> BytesType {
        self.data.to_bytes()
    }
}
