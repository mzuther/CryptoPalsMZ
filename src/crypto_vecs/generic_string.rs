use std::fmt;

use crate::crypto_vecs::traits::{DataAccess, LenBytes, ToBytes};
use crate::crypto_vecs::{self, BytesType};

// ----------------

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct CryptoString<T>
where
    T: DataAccess,
{
    data: T,
}

// ----------------

impl<T> CryptoString<T>
where
    T: DataAccess,
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

impl<T> DataAccess for CryptoString<T>
where
    T: DataAccess,
{
    fn new_from(data: String) -> Self {
        Self {
            data: T::new_from(data),
        }
    }

    fn get_data(&self) -> &str {
        self.data.get_data()
    }

    fn capacity(&self) -> usize {
        self.data.capacity()
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    fn get_representation_name(&self) -> String {
        self.data.get_representation_name()
    }

    fn get_representation_len(&self) -> usize {
        self.data.get_representation_len()
    }

    fn get_representation(&self) -> String {
        self.data.get_representation()
    }
}

// ----------------

impl<T> fmt::Display for CryptoString<T>
where
    T: DataAccess + LenBytes,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{}] {{ {} }}",
            self.get_representation_name(),
            self.get_representation_len(),
            self.get_representation()
        )
    }
}

impl<T> fmt::Debug for CryptoString<T>
where
    T: DataAccess + LenBytes,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

// ----------------

impl<T> LenBytes for CryptoString<T>
where
    T: DataAccess + LenBytes,
{
    fn len_bytes(&self) -> usize {
        self.data.len_bytes()
    }
}

// ----------------

impl<T> ToBytes for CryptoString<T>
where
    T: DataAccess + ToBytes,
{
    fn to_bytes(&self) -> BytesType {
        self.data.to_bytes()
    }
}
