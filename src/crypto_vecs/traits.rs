use crate::crypto_vecs::{Base64Type, BytesType, HexadecimalType, UnicodeType};

// ----------------

pub trait InternalData {
    type Collection;

    fn new_from(data: Self::Collection) -> Self;
    fn capacity(&self) -> usize;
    fn clean_and_validate(data: Self::Collection) -> Result<Self::Collection, String>;

    fn len(&self) -> usize;

    // ----------------

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ----------------

pub trait Representation {
    fn representation_name(&self) -> String;
    fn representation_len(&self) -> usize;
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
