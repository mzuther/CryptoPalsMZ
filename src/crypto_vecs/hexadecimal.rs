use hex;

use crate::crypto_vecs::traits::{FromBytes, InternalData, LenBytes, Representation, ToBytes};
use crate::crypto_vecs::{BytesType, CryptoString};

// ----------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Hexadecimal {
    hexadecimal: String,
}

pub type HexadecimalType = CryptoString<self::Hexadecimal>;

// ----------------

impl InternalData for Hexadecimal {
    type Data = String;

    fn new_from(data: Self::Data) -> Self {
        match Self::clean_and_validate(data) {
            Ok(data) => Self { hexadecimal: data },
            Err(error) => panic!("{}", error),
        }
    }

    fn capacity(&self) -> usize {
        self.hexadecimal.capacity()
    }

    fn clean_and_validate(data: Self::Data) -> Result<Self::Data, String> {
        let string_without_whitespace = data
            .split_ascii_whitespace()
            .fold(String::new(), |acc, string_slice| acc + string_slice)
            .to_lowercase();

        let invalid_characters: String = string_without_whitespace
            .chars()
            .filter(|c| !Hexadecimal::VALID_CHARACTERS.contains(*c))
            .collect();

        if invalid_characters.is_empty() {
            Ok(string_without_whitespace)
        } else {
            Err(format!(
                "found invalid hexadecimal characters: {}",
                invalid_characters
            ))
        }
    }

    // number of characters (hexadecimal alphabet)
    fn len(&self) -> usize {
        self.hexadecimal.chars().count()
    }
}

impl Representation for Hexadecimal {
    fn representation_len(&self) -> usize {
        self.len_bytes()
    }

    fn representation_name(&self) -> String {
        String::from("Hexadecimal")
    }

    fn representation(&self) -> String {
        let block_size = 8;

        let hex_blocks: String =
            self.hexadecimal
                .chars()
                .enumerate()
                .fold(String::new(), |mut acc, (index, char)| {
                    acc.push(char);

                    // separate blocks
                    if index % block_size == block_size - 1 {
                        acc.push(' ');
                    }

                    acc
                });

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

impl FromBytes for Hexadecimal {
    fn from_bytes(bytes: &BytesType) -> Self {
        Self::new_from(hex::encode(bytes.as_ref()))
    }
}

// ----------------

impl ToBytes for Hexadecimal {
    fn to_bytes(&self) -> BytesType {
        let hex_bytes = hex::decode(&self.hexadecimal).expect("broken conversion");

        BytesType::from(hex_bytes)
    }
}

// ----------------

impl Hexadecimal {
    // all valid hexadecimal characters
    pub const VALID_CHARACTERS: &str = "0123456789abcdef";
}

// ----------------

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------

    #[test]
    fn unit_hexadecimal_from_bytes() {
        let bytes = BytesType::from(vec![0x3b, 0x44, 0x2c, 0x4e, 0xcc, 0x0f]);
        let expected_result = HexadecimalType::from("3b442c4ecc0f");

        let result = HexadecimalType::from(&bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_hexadecimal() {
        let bytes = BytesType::from(vec![0x3b, 0x44, 0x2c, 0x4e, 0xcc, 0x0f]);
        let expected_result = HexadecimalType::from("3b442c4ecc0f");

        let result = bytes.to_hexadecimal();

        assert_eq!(result, expected_result);
    }

    #[test]
    #[should_panic(expected = "found invalid hexadecimal characters: !!g")]
    fn unit_hexadecimal_hex_from_invalid_string() {
        let _ = HexadecimalType::from("4A!f3!c6g1D298");
    }

    #[test]
    fn unit_hexadecimal_to_bytes_lowercase() {
        let hexadecimal = HexadecimalType::from("41c3bce4bda0");
        let expected_result = BytesType::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);

        let result = hexadecimal.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_bytes_uppercase() {
        let hexadecimal = HexadecimalType::from("21A3DCF4DBA1");
        let expected_result = BytesType::from(vec![0x21, 0xa3, 0xdc, 0xf4, 0xdb, 0xa1]);

        let result = hexadecimal.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_string() {
        let hexadecimal = HexadecimalType::from("41c3bc");
        let expected_result = String::from("Hexadecimal[3] { 41c3bc }");

        let result = hexadecimal.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_string_two_blocks() {
        let hexadecimal = HexadecimalType::from("21a3dcf4dba1");
        let expected_result = String::from("Hexadecimal[6] { 21a3dcf4 dba1 }");

        let result = hexadecimal.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_string_no_space_at_end() {
        let hexadecimal = HexadecimalType::from("21a3dcf4dba1bddb");
        let expected_result = String::from("Hexadecimal[8] { 21a3dcf4 dba1bddb }");

        let result = hexadecimal.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_to_string_trim_whitespace() {
        let hexadecimal = HexadecimalType::from("\t41\n  c3b\n\tce4b\n da\r\n 0\n\n");
        let expected_result = String::from("Hexadecimal[6] { 41c3bce4 bda0 }");

        let result = hexadecimal.to_string();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_hexadecimal_len_bytes_single_byte() {
        let hexadecimal = HexadecimalType::from("d3");
        let expected_result = 1;

        let result = hexadecimal.len_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hexadecimal_len_bytes_several_bytes() {
        let hexadecimal = HexadecimalType::from("41c3bce4 bda0");
        let expected_result = 6;

        let result = hexadecimal.len_bytes();

        assert_eq!(result, expected_result);
    }
}
