use crate::crypto_vecs;

use hex;
use std::{convert, fmt};

// ----------------

// all valid hexadecimal characters
const HEXADECIMAL_VALID_CHARACTERS: &str = "0123456789abcdef";

// ----------------

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct Hexadecimal {
    hex_string: String,
}

impl fmt::Display for self::Hexadecimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Hexadecimal[{}] {{ {} }}",
            self.len(),
            self.get_representation()
        )
    }
}

impl fmt::Debug for self::Hexadecimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl convert::From<String> for self::Hexadecimal {
    fn from(hex_string: String) -> Self {
        let string_without_whitespace = hex_string
            .split_ascii_whitespace()
            .fold(String::new(), |acc, string_slice| acc + string_slice)
            .to_lowercase();

        let invalid_characters: String = string_without_whitespace
            .chars()
            .filter(|c| !HEXADECIMAL_VALID_CHARACTERS.contains(*c))
            .collect();

        assert!(
            invalid_characters.is_empty(),
            "found invalid hexadecimal characters: {}",
            invalid_characters
        );

        Self {
            hex_string: string_without_whitespace,
        }
    }
}

impl convert::From<&str> for self::Hexadecimal {
    fn from(hex_string: &str) -> Self {
        Self::from(String::from(hex_string))
    }
}

impl convert::From<&crypto_vecs::Bytes> for self::Hexadecimal {
    fn from(bytes: &crypto_vecs::Bytes) -> Self {
        Self::from(hex::encode(bytes.as_ref()))
    }
}

impl crypto_vecs::ToBytes for self::Hexadecimal {
    fn to_bytes(&self) -> crypto_vecs::Bytes {
        let hex_bytes = hex::decode(&self.hex_string).expect("broken conversion");

        crypto_vecs::Bytes::from(hex_bytes)
    }

    // performance: prevent intermediate conversion to Bytes
    fn to_hexadecimal(&self) -> Self {
        self.clone()
    }
}

impl self::Hexadecimal {
    pub const fn len(&self) -> usize {
        self.hex_string.len() / 2
    }

    pub fn get_representation(&self) -> String {
        let block_size = 8;

        let hex_blocks: String =
            self.hex_string
                .chars()
                .enumerate()
                .fold(String::new(), |mut acc, (index, char)| {
                    acc.push(char);

                    if index % block_size == block_size - 1 {
                        acc.push(' ');
                    }

                    acc
                });

        String::from(hex_blocks.trim_end())
    }
}

// ----------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_vecs::ToBytes;

    // ----------------

    #[test]
    fn unit_hexadecimal_from_bytes() {
        let bytes = crypto_vecs::Bytes::from(vec![0x3b, 0x44, 0x2c, 0x4e, 0xcc, 0x0f]);
        let expected_result = self::Hexadecimal::from("3b442c4ecc0f");

        let result = self::Hexadecimal::from(&bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_hexadecimal() {
        let bytes = crypto_vecs::Bytes::from(vec![0x3b, 0x44, 0x2c, 0x4e, 0xcc, 0x0f]);
        let expected_result = self::Hexadecimal::from("3b442c4ecc0f");

        let result = bytes.to_hexadecimal();

        assert_eq!(result, expected_result);
    }

    #[test]
    #[should_panic(expected = "found invalid hexadecimal characters: !!g")]
    fn unit_hexadecimal_hex_from_invalid_string() {
        let _ = self::Hexadecimal::from("4A!f3!c6g1D298");
    }

    #[test]
    fn unit_hexadecimal_to_bytes_lowercase() {
        let hexadecimal = self::Hexadecimal::from("41c3bce4bda0");
        let expected_result = crypto_vecs::Bytes::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);

        let result = hexadecimal.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_bytes_uppercase() {
        let hexadecimal = self::Hexadecimal::from("21A3DCF4DBA1");
        let expected_result = crypto_vecs::Bytes::from(vec![0x21, 0xa3, 0xdc, 0xf4, 0xdb, 0xa1]);

        let result = hexadecimal.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_string() {
        let hexadecimal = self::Hexadecimal::from("41c3bc");
        let expected_result = String::from("Hexadecimal[3] { 41c3bc }");

        let result = hexadecimal.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_string_two_blocks() {
        let hexadecimal = self::Hexadecimal::from("21a3dcf4dba1");
        let expected_result = String::from("Hexadecimal[6] { 21a3dcf4 dba1 }");

        let result = hexadecimal.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_string_no_space_at_end() {
        let hexadecimal = self::Hexadecimal::from("21a3dcf4dba1bddb");
        let expected_result = String::from("Hexadecimal[8] { 21a3dcf4 dba1bddb }");

        let result = hexadecimal.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_string_trim_whitespace() {
        let hexadecimal = self::Hexadecimal::from("\t41\n  c3b\n\tce4b\n da\r\n 0\n\n");
        let expected_result = String::from("Hexadecimal[6] { 41c3bce4 bda0 }");

        let result = hexadecimal.to_string();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_hexadecimal_len_single_byte() {
        let hexadecimal = self::Hexadecimal::from("d3");
        let expected_result = 1;

        let result = hexadecimal.len();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_len_several_bytes() {
        let hexadecimal = self::Hexadecimal::from("41c3bce4 bda0");
        let expected_result = 6;

        let result = hexadecimal.len();

        assert_eq!(result, expected_result);
    }
}
