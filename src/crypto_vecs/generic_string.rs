use std::{convert, fmt};

use crate::crypto_vecs::traits::{InternalData, LenBytes, Representation, ToBytes};
use crate::crypto_vecs::{self, BytesType};

// ----------------

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct CryptoString<T>
where
    T: InternalData,
{
    data: T,
}

// ----------------

impl<T> CryptoString<T>
where
    T: InternalData<Data = String>,
{
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
}

// ----------------

impl<T> InternalData for CryptoString<T>
where
    T: InternalData<Data = String>,
{
    type Data = String;

    fn new_from(data: Self::Data) -> Self {
        Self {
            data: T::new_from(data),
        }
    }

    fn capacity(&self) -> usize {
        self.data.capacity()
    }

    fn clean_and_validate(data: Self::Data) -> Result<Self::Data, String> {
        T::clean_and_validate(data)
    }

    fn get_data(&self) -> &str {
        self.data.get_data()
    }

    fn len(&self) -> usize {
        self.data.len()
    }
}

impl<T> Representation for CryptoString<T>
where
    T: InternalData + Representation,
{
    fn representation_name(&self) -> String {
        self.data.representation_name()
    }

    fn representation_len(&self) -> usize {
        self.data.representation_len()
    }

    fn representation(&self) -> String {
        self.data.representation()
    }
}

// ----------------

impl<T> fmt::Display for CryptoString<T>
where
    T: InternalData + Representation,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{}] {{ {} }}",
            self.representation_name(),
            self.representation_len(),
            self.representation()
        )
    }
}

impl<T> fmt::Debug for CryptoString<T>
where
    T: InternalData + Representation,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

// ----------------

impl<T> convert::From<String> for CryptoString<T>
where
    T: InternalData<Data = String>,
{
    fn from(data: String) -> Self {
        Self::new_from(data)
    }
}

impl<T> convert::From<&str> for CryptoString<T>
where
    T: InternalData<Data = String>,
{
    fn from(data: &str) -> Self {
        Self::new_from(String::from(data))
    }
}

// ----------------

impl<T> LenBytes for CryptoString<T>
where
    T: InternalData + LenBytes,
{
    fn len_bytes(&self) -> usize {
        self.data.len_bytes()
    }
}

// ----------------

impl<T> ToBytes for CryptoString<T>
where
    T: InternalData + ToBytes,
{
    fn to_bytes(&self) -> BytesType {
        self.data.to_bytes()
    }
}
