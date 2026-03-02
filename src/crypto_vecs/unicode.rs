use crate::crypto_vecs;

use std::{convert, fmt};

// ----------------

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct Unicode {
    unicode_string: String,
}

impl fmt::Display for self::Unicode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Unicode[{}] {{ {} }}",
            self.unicode_string.chars().count(),
            self.unicode_string
        )
    }
}

impl fmt::Debug for self::Unicode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string(),)
    }
}

impl convert::From<String> for self::Unicode {
    fn from(unicode_string: String) -> Self {
        Self {
            unicode_string: unicode_string,
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
        let unicode_bytes = Vec::from(self.unicode_string.clone());

        crypto_vecs::Bytes::from(unicode_bytes)
    }

    // performance: prevent intermediate conversion to Bytes
    fn to_unicode(&self) -> Self {
        self.clone()
    }
}

// ----------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_vecs::ToBytes;

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
}
