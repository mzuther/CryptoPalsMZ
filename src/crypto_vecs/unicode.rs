use crate::crypto_vecs::traits::{FromBytes, InternalData, LenBytes, Representation, ToBytes};
use crate::crypto_vecs::{BytesType, CryptoString};

// ----------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Unicode {
    unicode: String,
}

pub type UnicodeType = CryptoString<self::Unicode>;

// ----------------

impl InternalData for Unicode {
    type Data = String;

    fn new_from(data: Self::Data) -> Self {
        match Self::clean_and_validate(data) {
            Ok(data) => Self { unicode: data },
            Err(error) => panic!("{}", error),
        }
    }

    fn capacity(&self) -> usize {
        self.unicode.capacity()
    }

    fn clean_and_validate(data: Self::Data) -> Result<Self::Data, String> {
        Ok(data)
    }

    // number of characters (graphemes)
    fn len(&self) -> usize {
        self.unicode.chars().count()
    }
}

impl Representation for Unicode {
    fn representation_name(&self) -> String {
        String::from("Unicode")
    }

    fn representation_len(&self) -> usize {
        self.len()
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

impl FromBytes for Unicode {
    fn from_bytes(bytes: &BytesType) -> Self {
        let unicode_string = String::from_utf8(bytes.to_vec()).expect("invalid UTF-8 string");

        Self::new_from(unicode_string)
    }
}

// ----------------

impl ToBytes for Unicode {
    fn to_bytes(&self) -> BytesType {
        let unicode_bytes = Vec::from(self.unicode.clone());

        BytesType::from(unicode_bytes)
    }
}

// ----------------

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------

    #[test]
    fn unit_unicode_from_bytes_ascii() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0x33]);
        let expected_result = UnicodeType::from("Ab3");

        let result = UnicodeType::from(&bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_from_bytes_unicode() {
        let bytes = BytesType::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);
        let expected_result = UnicodeType::from("Aü你");

        let result = UnicodeType::from(&bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_to_unicode_ascii() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0x33]);
        let expected_result = UnicodeType::from("Ab3");

        let result = bytes.to_unicode();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_to_unicode_unicode() {
        let bytes = BytesType::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);
        let expected_result = UnicodeType::from("Aü你");

        let result = bytes.to_unicode();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_to_bytes_ascii() {
        let unicode = UnicodeType::from("Ab3");
        let expected_result = BytesType::from(vec![0x41, 0x62, 0x33]);

        let result = unicode.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_to_bytes_unicode() {
        let unicode = UnicodeType::from("Aü你");
        let expected_result = BytesType::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);

        let result = unicode.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_to_string() {
        let unicode = UnicodeType::from("Hi. Servus. Grüezi. 你好.");
        let expected_result = String::from("Unicode[23] { Hi. Servus. Grüezi. 你好. }");

        let result = unicode.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_to_string_keep_whitespace() {
        let unicode = UnicodeType::from("\n Hi. Servus. Grüezi. 你好.\t");
        let expected_result = String::from("Unicode[26] { \n Hi. Servus. Grüezi. 你好.\t }");

        let result = unicode.to_string();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_unicode_len_ascii() {
        let unicode = UnicodeType::from("Hi. Servus. Moin.");

        let expected_result = 17;

        let result = unicode.len();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_len_unicode() {
        let unicode = UnicodeType::from("Hi. Servus. Grüezi. 你好.");

        let expected_result = 23;

        let result = unicode.len();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_len_bytes_ascii() {
        let unicode = UnicodeType::from("Hi. Servus. Moin.");

        let expected_result = 17;

        let result = unicode.len_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_unicode_len_bytes_unicode() {
        let unicode = UnicodeType::from("Hi. Servus. Grüezi. 你好.");

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
