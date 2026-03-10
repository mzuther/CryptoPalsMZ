use std::slice;

use crate::crypto_vecs::{self, Base64Type, BytesType, HexadecimalType, UnicodeType};

// ================

pub trait InternalData {
    type Collection;

    fn new_from(data: Self::Collection) -> Self;
    fn with_capacity(capacity: usize) -> Self;

    fn capacity(&self) -> usize;
    fn clean_and_validate(data: Self::Collection) -> Result<Self::Collection, String>;

    fn get_data(&self) -> &Self::Collection;

    // ----------------

    fn with_capacity_bits(capacity_bits: usize) -> Self
    where
        Self: Sized,
    {
        let capacity = crypto_vecs::bits_to_bytes(capacity_bits);

        Self::with_capacity(capacity)
    }
}

pub trait InternalDataVec {
    type Element;

    fn new_from(data: Vec<Self::Element>) -> Self;

    fn capacity(&self) -> usize;
    fn clean_and_validate(data: Vec<Self::Element>) -> Result<Vec<Self::Element>, String>;

    fn data(&self) -> &Vec<Self::Element>;
    fn chunks(&self, chunk_size: usize) -> slice::Chunks<'_, Self::Element>;
    fn rchunks(&self, chunk_size: usize) -> slice::RChunks<'_, Self::Element>;

    fn get(&self, index: usize) -> Option<&Self::Element>;

    // ----------------

    fn with_capacity(bytes: usize) -> Self
    where
        Self: Sized,
    {
        Self::new_from(Vec::with_capacity(bytes))
    }

    fn with_capacity_bits(bits: usize) -> Self
    where
        Self: Sized,
    {
        let bytes = crypto_vecs::bits_to_bytes(bits);

        Self::new_from(Vec::with_capacity(bytes))
    }

    fn as_slice(&self) -> &[Self::Element] {
        self.data().as_slice()
    }

    fn first_n(&self, length: usize) -> Option<&[Self::Element]> {
        assert!(length > 0);

        self.chunks(length).next()
    }

    fn last_n(&self, length: usize) -> Option<&[Self::Element]> {
        assert!(length > 0);

        self.rchunks(length).next()
    }
}

pub trait InternalDataVecMut {
    type Element;

    fn data_mut(&mut self) -> &mut Vec<Self::Element>;

    fn push(&mut self, value: Self::Element);

    // ----------------

    fn as_mut_slice(&mut self) -> &mut [Self::Element] {
        self.data_mut().as_mut_slice()
    }
}

// ----------------

// iterate over / count logical elements (String or char)
pub trait Elements {
    type Element;

    fn elements(&self) -> impl Iterator<Item = Self::Element>;

    // ----------------

    fn to_elements(&self) -> Vec<Self::Element> {
        self.elements().collect::<Vec<Self::Element>>()
    }

    fn len(&self) -> usize {
        self.elements().count()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ----------------

pub trait Representation {
    fn representation_name(&self) -> &str;
    fn representation(&self) -> String;
}

// ----------------

pub trait LenBytes {
    fn len_bytes(&self) -> usize;

    // ----------------

    fn len_bits(&self) -> usize {
        self.len_bytes() * 8
    }
}

// ----------------

pub trait FromBytes {
    fn from_bytes(bytes: &BytesType) -> Self;
}

// ----------------

pub trait ToBytes {
    fn to_bytes(&self) -> self::BytesType;

    // ----------------

    fn to_hexadecimal(&self) -> self::HexadecimalType {
        self::HexadecimalType::from(&self.to_bytes())
    }

    fn to_base64(&self) -> self::Base64Type {
        self::Base64Type::from(&self.to_bytes())
    }

    fn to_unicode(&self) -> self::UnicodeType {
        self::UnicodeType::from(&self.to_bytes())
    }
}
