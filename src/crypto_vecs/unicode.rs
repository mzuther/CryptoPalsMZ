use std::convert;

use crate::crypto_vecs::traits::{FromBytes, InternalData, LenBytes, ToBytes};
use crate::crypto_vecs::{Bytes, BytesType, CryptoString};

// ================

#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Unicode {
    unicode: String,
    element_cache: Vec<char>,
}

pub type UnicodeType = CryptoString<self::Unicode>;

// ================

impl InternalData for Unicode {
    type Element = char;
    type Collection = String;

    fn new_from(data: Self::Collection) -> Self {
        match Self::clean_and_validate(data) {
            Ok(data) => Self {
                element_cache: data.chars().collect(),
                unicode: data,
            },
            Err(error) => panic!("{}", error),
        }
    }

    fn new_from_elements(elements: &[Self::Element]) -> Self {
        Self::new_from(elements.iter().collect())
    }

    fn from_literal(string_literal: &str) -> Self {
        Self::new_from(string_literal.to_string())
    }

    fn with_capacity(capacity: usize) -> Self {
        Self::new_from(Self::Collection::with_capacity(capacity))
    }

    fn capacity(&self) -> usize {
        self.unicode.capacity()
    }

    fn clean_and_validate(data: Self::Collection) -> Result<Self::Collection, String> {
        Ok(data.clone())
    }

    // ----------------

    // iterate over single characters (graphemes)
    fn elements(&self) -> impl Iterator<Item = &Self::Element> {
        self.element_cache.iter()
    }

    fn collection(&self) -> Self::Collection {
        self.unicode.clone()
    }

    fn collection_as_ref(&self) -> &Self::Collection {
        &self.unicode
    }

    fn chunks(&self, chunk_size: usize) -> std::slice::Chunks<'_, Self::Element> {
        assert!(chunk_size > 0, "chunk size must be non-zero");

        self.element_cache.chunks(chunk_size)
    }

    fn rchunks(&self, chunk_size: usize) -> std::slice::RChunks<'_, Self::Element> {
        assert!(chunk_size > 0, "chunk size must be non-zero");

        self.element_cache.rchunks(chunk_size)
    }

    // ----------------

    fn representation_name(&self) -> &str {
        "Unicode"
    }

    fn representation(&self) -> String {
        self.unicode.clone()
    }
}

// ----------------

impl LenBytes for Unicode {
    fn len_bytes(&self) -> usize {
        self.unicode.len()
    }
}

// ----------------

impl convert::AsRef<str> for Unicode {
    fn as_ref(&self) -> &str {
        self.unicode.as_ref()
    }
}

// ----------------

impl FromBytes for Unicode {
    fn from_bytes(bytes: &BytesType) -> Self {
        let unicode_string =
            String::from_utf8(bytes.collection()).expect("invalid UTF-8 string");

        Self::new_from(unicode_string)
    }
}

// ----------------

impl ToBytes for Unicode {
    fn to_bytes_raw(&self) -> Bytes {
        let unicode_bytes = Vec::from(self.unicode.clone());

        Bytes::new_from(unicode_bytes)
    }
}

// ================

impl UnicodeType {
    // TODO: add tests
    pub fn replace_prefix(unicode: &str, prefix: &str, mut new_prefix: String) -> String {
        let without_prefix = unicode
            .strip_prefix(prefix)
            .unwrap_or_else(|| panic!("prefix \"{}\" not found", prefix));

        new_prefix.push_str(without_prefix);

        new_prefix
    }

    // TODO: add tests
    pub fn replace_suffix(unicode: &str, suffix: &str, new_suffix: &str) -> String {
        let mut with_new_suffix = unicode
            .strip_suffix(suffix)
            .unwrap_or_else(|| panic!("suffix \"{}\" not found", suffix))
            .to_string();

        with_new_suffix.push_str(new_suffix);

        with_new_suffix
    }
}

// ================

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------

    #[test]
    fn unit_unicode_to_unicode_ascii() {
        let bytes = BytesType::new_from(vec![0x41, 0x62, 0x33]);
        let expected_result = UnicodeType::from_literal("Ab3");

        let result = bytes.to_unicode();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_to_unicode_unicode() {
        let bytes = BytesType::new_from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);
        let expected_result = UnicodeType::from_literal("Aü你");

        let result = bytes.to_unicode();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_to_bytes_ascii() {
        let unicode = UnicodeType::from_literal("Ab3");
        let expected_result = BytesType::new_from(vec![0x41, 0x62, 0x33]);

        let result = unicode.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_to_bytes_unicode() {
        let unicode = UnicodeType::from_literal("Aü你");
        let expected_result =
            BytesType::new_from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);

        let result = unicode.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_to_string() {
        let unicode = UnicodeType::from_literal("Hi. Servus. Grüezi. 你好.");
        let expected_result = String::from("Unicode[23] { Hi. Servus. Grüezi. 你好. }");

        let result = unicode.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_to_string_keep_whitespace() {
        let unicode = UnicodeType::from_literal("\n Hi. Servus. Grüezi. 你好.\t");
        let expected_result =
            String::from("Unicode[26] { \n Hi. Servus. Grüezi. 你好.\t }");

        let result = unicode.to_string();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_unicode_len_ascii() {
        let unicode = UnicodeType::from_literal("Hi. Servus. Moin.");

        let expected_result = 17;

        let result = unicode.len();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_len_unicode() {
        let unicode = UnicodeType::from_literal("Hi. Servus. Grüezi. 你好.");

        let expected_result = 23;

        let result = unicode.len();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_len_bytes_ascii() {
        let unicode = UnicodeType::from_literal("Hi. Servus. Moin.");

        let expected_result = 17;

        let result = unicode.len_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_len_bytes_unicode() {
        let unicode = UnicodeType::from_literal("Hi. Servus. Grüezi. 你好.");

        // single-byte characters: ASCII
        let mut expected_result = 20;
        // dual-byte characters: ü
        expected_result += 2;
        // triple-byte characters: 你好
        expected_result += 6;

        let result = unicode.len_bytes();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_unicode_to_elements() {
        let unicode = UnicodeType::from_literal("Grüezi. 你好.");

        let expected_result =
            vec!['G', 'r', 'ü', 'e', 'z', 'i', '.', ' ', '你', '好', '.'];

        let result = unicode.to_elements();

        assert_eq!(result, expected_result);
    }
}
