use hex;
use std::{convert, fmt};

use crate::crypto_vecs::Bytes;
use crate::crypto_vecs::traits::{CryptoVec, LenBytes, ToBytes};

// ================

#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Hexadecimal {
    hexadecimal: String,
    element_cache: Vec<String>,
}

// ================

impl CryptoVec for Hexadecimal {
    type Element = String;
    type Collection = String;

    fn new_from(data: Self::Collection) -> Self {
        match Self::clean_and_validate(data) {
            Ok(data) => Self {
                element_cache: {
                    assert!(data.len().is_multiple_of(2));

                    let odd_chars = data.chars().step_by(2);
                    let even_chars = data.chars().skip(1).step_by(2);

                    odd_chars.zip(even_chars).fold(
                        Vec::default(),
                        |mut acc, (first_char, second_char)| {
                            acc.push(format!("{}{}", first_char, second_char));

                            acc
                        },
                    )
                },
                hexadecimal: data,
            },
            Err(error) => panic!("{}", error),
        }
    }

    fn new_from_elements(elements: &[Self::Element]) -> Self {
        Self::new_from(elements.join(""))
    }

    fn from_literal(string_literal: &str) -> Self {
        Self::new_from(string_literal.to_string())
    }

    fn with_capacity(capacity: usize) -> Self {
        Self::new_from(Self::Collection::with_capacity(capacity))
    }

    fn capacity(&self) -> usize {
        self.hexadecimal.capacity()
    }

    fn clean_and_validate(data: Self::Collection) -> Result<Self::Collection, String> {
        let string_without_whitespace = data
            .split_ascii_whitespace()
            .fold(String::default(), |acc, string_slice| acc + string_slice)
            .to_lowercase();

        let invalid_characters: String = string_without_whitespace
            .chars()
            .filter(|c| !Hexadecimal::VALID_CHARACTERS.contains(*c))
            .collect();

        if invalid_characters.is_empty() {
            if string_without_whitespace.len().is_multiple_of(2) {
                Ok(string_without_whitespace)
            } else {
                // prepend zero as hexadecimals are bounded on the right
                Ok(format!("0{}", string_without_whitespace))
            }
        } else {
            Err(format!(
                "found invalid hexadecimal characters: {}",
                invalid_characters
            ))
        }
    }

    // ----------------

    // iterate over bytes (Strings of two characters)
    fn elements(&self) -> impl Iterator<Item = &Self::Element> {
        self.element_cache.iter()
    }

    fn collection(&self) -> Self::Collection {
        self.hexadecimal.clone()
    }

    fn collection_as_ref(&self) -> &Self::Collection {
        &self.hexadecimal
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
        "Hexadecimal"
    }

    fn representation(&self) -> String {
        let block_size = 4;

        let hex_blocks = self.elements().enumerate().fold(
            String::default(),
            |mut acc, (index, element)| {
                acc.push_str(element);

                // separate blocks
                if index % block_size == block_size - 1 {
                    acc.push(' ');
                }

                acc
            },
        );

        String::from(hex_blocks.trim_end())
    }
}

// ----------------

impl LenBytes for Hexadecimal {
    fn len_bytes(&self) -> usize {
        self.hexadecimal.len() / 2
    }
}

// ----------------
impl fmt::Display for Hexadecimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{:02}] {{ {} }}",
            self.representation_name(),
            self.element_cache.len(),
            self.representation()
        )
    }
}

// ----------------

impl convert::AsRef<str> for Hexadecimal {
    fn as_ref(&self) -> &str {
        self.hexadecimal.as_ref()
    }
}

// ----------------

impl convert::From<&Bytes> for Hexadecimal {
    fn from(bytes: &Bytes) -> Self {
        Self::new_from(hex::encode(bytes.as_ref()))
    }
}

// ----------------

impl ToBytes for Hexadecimal {
    fn to_bytes_raw(&self) -> Bytes {
        let hex_bytes = hex::decode(&self.hexadecimal).expect("broken conversion");

        Bytes::new_from(hex_bytes)
    }
}

// ----------------

impl Hexadecimal {
    // valid hexadecimal characters
    pub const VALID_CHARACTERS: &str = "0123456789abcdef";
}

// ================

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------

    #[test]
    fn unit_hexadecimal_to_hexadecimal() {
        let bytes = Bytes::new_from(vec![0x3b, 0x44, 0x2c, 0x4e, 0xcc, 0x0f]);
        let expected_result = Hexadecimal::from_literal("3b442c4ecc0f");

        let result = bytes.to_hexadecimal();

        assert_eq!(result, expected_result);
    }

    #[test]
    #[should_panic(expected = "found invalid hexadecimal characters: !!g")]
    fn unit_hexadecimal_hex_from_invalid_string() {
        let _ = Hexadecimal::from_literal("4A!f3!c6g1D298");
    }

    #[test]
    fn unit_hexadecimal_to_bytes_lowercase() {
        let hexadecimal = Hexadecimal::from_literal("41c3bce4bda0");
        let expected_result = Bytes::new_from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);

        let result = hexadecimal.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_bytes_uppercase() {
        let hexadecimal = Hexadecimal::from_literal("21A3DCF4DBA1");
        let expected_result = Bytes::new_from(vec![0x21, 0xa3, 0xdc, 0xf4, 0xdb, 0xa1]);

        let result = hexadecimal.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_string() {
        let hexadecimal = Hexadecimal::from_literal("41c3bc");
        let expected_result = String::from("Hexadecimal[03] { 41c3bc }");

        let result = hexadecimal.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_string_two_blocks() {
        let hexadecimal = Hexadecimal::from_literal("21a3dcf4 dba1");
        let expected_result = String::from("Hexadecimal[06] { 21a3dcf4 dba1 }");

        let result = hexadecimal.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_string_odd_length() {
        let hexadecimal = Hexadecimal::from_literal(" 1a3dcf4 dba1");
        let expected_result = String::from("Hexadecimal[06] { 01a3dcf4 dba1 }");

        let result = hexadecimal.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_string_no_space_at_end() {
        let hexadecimal = Hexadecimal::from_literal("21a3dcf4dba1bddb");
        let expected_result = String::from("Hexadecimal[08] { 21a3dcf4 dba1bddb }");

        let result = hexadecimal.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_string_trim_whitespace() {
        let hexadecimal = Hexadecimal::from_literal("\t41\n  c3b\n\tce4b\n da\r\n 0\n\n");
        let expected_result = String::from("Hexadecimal[06] { 41c3bce4 bda0 }");

        let result = hexadecimal.to_string();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_hexadecimal_len_bytes_single_byte() {
        let hexadecimal = Hexadecimal::from_literal("d3");
        let expected_result = 1;

        let result = hexadecimal.len_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_len_bytes_several_bytes() {
        let hexadecimal = Hexadecimal::from_literal("41c3bce4 bda0");
        let expected_result = 6;

        let result = hexadecimal.len_bytes();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_hexadecimal_to_elements() {
        let hexadecimal = Hexadecimal::from_literal("41c3bce4 bda0");

        let expected_result = vec!["41", "c3", "bc", "e4", "bd", "a0"];

        let result = hexadecimal.to_elements();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_elements_odd_length() {
        let hexadecimal = Hexadecimal::from_literal(" 1c3bce4 bda0");

        let expected_result = vec!["01", "c3", "bc", "e4", "bd", "a0"];

        let result = hexadecimal.to_elements();

        assert_eq!(result, expected_result);
    }
}
