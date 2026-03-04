use crate::crypto_vecs;

use std::{convert, fmt, marker};

// ----------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnicodeType;

pub type Unicode = crypto_vecs::CryptoString<self::UnicodeType>;

// ----------------

impl fmt::Display for self::Unicode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unicode[{}] {{ {} }}", self.len(), self.data)
    }
}

impl fmt::Debug for self::Unicode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl convert::From<String> for self::Unicode {
    fn from(unicode_string: String) -> Self {
        Self {
            data: unicode_string,
            struct_type: marker::PhantomData,
        }
    }
}

impl convert::From<&str> for self::Unicode {
    fn from(unicode_string: &str) -> Self {
        Self::from(String::from(unicode_string))
    }
}

impl convert::From<&crypto_vecs::Bytes> for self::Unicode {
    fn from(bytes: &crypto_vecs::Bytes) -> Self {
        let unicode_string = String::from_utf8(bytes.to_vec()).expect("invalid UTF-8 string");

        Self::from(unicode_string)
    }
}

impl crypto_vecs::ToBytes for self::Unicode {
    fn to_bytes(&self) -> crypto_vecs::Bytes {
        let unicode_bytes = Vec::from(self.data.clone());

        crypto_vecs::Bytes::from(unicode_bytes)
    }

    // performance: prevent intermediate conversion to Bytes
    fn to_unicode(&self) -> Self {
        self.clone()
    }
}

impl crypto_vecs::LenBytes for self::Unicode {
    fn len_bytes(&self) -> usize {
        self.data.len()
    }
}

impl self::Unicode {
    // number of characters
    pub fn len(&self) -> usize {
        self.data.chars().count()
    }
}

// ----------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_vecs::{LenBytes, ToBytes};

    // ----------------

    #[test]
    fn unit_unicode_from_bytes_ascii() {
        let bytes = crypto_vecs::Bytes::from(vec![0x41, 0x62, 0x33]);
        let expected_result = self::Unicode::from("Ab3");

        let result = self::Unicode::from(&bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_from_bytes_unicode() {
        let bytes = crypto_vecs::Bytes::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);
        let expected_result = self::Unicode::from("Aü你");

        let result = self::Unicode::from(&bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_to_unicode_ascii() {
        let bytes = crypto_vecs::Bytes::from(vec![0x41, 0x62, 0x33]);
        let expected_result = self::Unicode::from("Ab3");

        let result = bytes.to_unicode();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_to_unicode_unicode() {
        let bytes = crypto_vecs::Bytes::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);
        let expected_result = self::Unicode::from("Aü你");

        let result = bytes.to_unicode();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_to_bytes_ascii() {
        let unicode = self::Unicode::from("Ab3");
        let expected_result = crypto_vecs::Bytes::from(vec![0x41, 0x62, 0x33]);

        let result = unicode.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_to_bytes_unicode() {
        let unicode = self::Unicode::from("Aü你");
        let expected_result = crypto_vecs::Bytes::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);

        let result = unicode.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_to_string() {
        let unicode = self::Unicode::from("Hi. Servus. Grüezi. 你好.");
        let expected_result = String::from("Unicode[23] { Hi. Servus. Grüezi. 你好. }");

        let result = unicode.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_to_string_keep_whitespace() {
        let unicode = self::Unicode::from("\n Hi. Servus. Grüezi. 你好.\t");
        let expected_result = String::from("Unicode[26] { \n Hi. Servus. Grüezi. 你好.\t }");

        let result = unicode.to_string();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_unicode_len_ascii() {
        let unicode = self::Unicode::from("Hi. Servus. Moin.");

        let expected_result = 17;

        let result = unicode.len();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_len_unicode() {
        let unicode = self::Unicode::from("Hi. Servus. Grüezi. 你好.");

        let expected_result = 23;

        let result = unicode.len();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_len_bytes_ascii() {
        let unicode = self::Unicode::from("Hi. Servus. Moin.");

        let expected_result = 17;

        let result = unicode.len_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_len_bytes_unicode() {
        let unicode = self::Unicode::from("Hi. Servus. Grüezi. 你好.");

        // single-byte characters: ASCII
        let mut expected_result = 20;
        // dual-byte characters: ü
        expected_result += 2;
        // triple-byte characters: 你好
        expected_result += 6;

        let result = unicode.len_bytes();

        assert_eq!(result, expected_result);
    }
}
