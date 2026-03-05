use std::convert;

use crate::crypto_vecs::traits::{DataAccess, LenBytes, ToBytes};
use crate::crypto_vecs::{BytesType, CryptoString};

// ----------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Base64 {
    base64: String,
}

pub type Base64Type = CryptoString<Base64>;

// ----------------

impl DataAccess for Base64 {
    fn new_from(data: String) -> Self {
        Self { base64: data }
    }

    fn capacity(&self) -> usize {
        self.base64.capacity()
    }

    fn get_data(&self) -> &str {
        &self.base64
    }

    // number of characters (base64 alphabet)
    fn len(&self) -> usize {
        self.base64.chars().count()
    }

    fn get_representation_name(&self) -> String {
        String::from("Base64")
    }

    fn get_representation_len(&self) -> usize {
        self.len()
    }

    fn get_representation(&self) -> String {
        let block_size = 8;

        let base64_blocks: String =
            self.base64
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

        String::from(base64_blocks.trim_end())
    }
}

// ----------------

impl LenBytes for Base64 {
    fn len_bytes(&self) -> usize {
        self.to_bytes().len_bytes()
    }
}

// ----------------

impl ToBytes for Base64 {
    fn to_bytes(&self) -> BytesType {
        let decoded_bytes = self.base64.bytes().fold(Vec::new(), |mut acc, char_int| {
            let char_option;

            // plus
            if char_int == 43 {
                char_option = Some(62);
            // slash
            } else if char_int == 47 {
                char_option = Some(63);
            // padding character (=)
            } else if char_int == 61 {
                char_option = None;
            // digit
            } else if char_int <= 57 {
                char_option = Some(char_int + 4);
            // upper case letter
            } else if char_int <= 90 {
                char_option = Some(char_int - 65);
            // lower case letter
            } else {
                char_option = Some(char_int - 71);
            }

            assert!(
                char_option.is_none_or(|x| x < 64),
                "{:?} is not valid base64",
                char_option
            );

            acc.push(char_option);
            acc
        });

        let base64_bytes = self::assemble_bytes_from_segments(&decoded_bytes, 6);

        BytesType::from(base64_bytes)
    }
}

// ----------------

impl convert::From<String> for Base64Type {
    fn from(base64_string: String) -> Self {
        let string_without_whitespace = base64_string
            .split_ascii_whitespace()
            .fold(String::new(), |acc, string_slice| acc + string_slice);

        let invalid_characters: String = string_without_whitespace
            .chars()
            .filter(|c| !Base64Type::VALID_CHARACTERS.contains(*c))
            .collect();

        assert!(
            invalid_characters.is_empty(),
            "found invalid base64 characters: {}",
            invalid_characters
        );

        CryptoString::new_from(string_without_whitespace)
    }
}

impl convert::From<&str> for Base64Type {
    fn from(base64_string: &str) -> Self {
        Self::from(String::from(base64_string))
    }
}

impl convert::From<&BytesType> for Base64Type {
    fn from(bytes: &BytesType) -> Self {
        let base64_segments = self::split_bytes_into_segments(bytes, 6);

        let base64_string = base64_segments
            .iter()
            .fold(String::new(), |mut acc, &segment| {
                let mut char_int: u8;

                // padding character (=)
                if segment.is_none() {
                    char_int = 61;
                } else {
                    char_int = segment.unwrap();
                    assert!(char_int < 64, "{} is not a valid base64 segment", char_int);

                    // upper case letter
                    if char_int < 26 {
                        char_int += 65
                    // lower case letter
                    } else if char_int < 52 {
                        char_int += 71
                    // plus
                    } else if char_int == 62 {
                        char_int = 43
                    // slash
                    } else if char_int == 63 {
                        char_int = 47
                    // digit
                    } else {
                        char_int -= 4
                    }
                }

                acc.push(char_int as char);
                acc
            });

        Self::from(base64_string)
    }
}

impl Base64Type {
    // all valid base64 characters
    const VALID_CHARACTERS: &str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    // base64-encoded string containing complete base64 alphabet
    pub const COMPLETE_ALPHABET: &str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // plain-text bytes which yield the base64-encoded string above
    pub const COMPLETE_ALPHABET_BYTES: [u8; 48] = [
        0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8b, 0x30, 0xd3, 0x8f, 0x41, 0x14, 0x93,
        0x51, 0x55, 0x97, 0x61, 0x96, 0x9b, 0x71, 0xd7, 0x9f, 0x82, 0x18, 0xa3, 0x92, 0x59, 0xa7,
        0xa2, 0x9a, 0xab, 0xb2, 0xdb, 0xaf, 0xc3, 0x1c, 0xb3, 0xd3, 0x5d, 0xb7, 0xe3, 0x9e, 0xbb,
        0xf3, 0xdf, 0xbf,
    ];

    // plain-text hexadecimal string which yields the base64-encoded string above
    pub const COMPLETE_ALPHABET_HEX: &str = "00108310518720928b30d38f41149351559761969b71d79f8218a39259a7a29aabb2dbafc31cb3d35db7e39ebbf3dfbf";
}

// ----------------

fn split_bytes_into_segments(bytes: &BytesType, bits_per_segment: u8) -> Vec<Option<u8>> {
    let bits_per_byte = 8;
    let mut bits_with_value = 0;
    let mut remainder = 0;

    let mut segments_to_encode = bytes.iter().fold(Vec::new(), |mut acc, &byte| {
        bits_with_value = (bits_with_value + bits_per_segment) % bits_per_byte;
        let bits_with_remainder = bits_per_byte - bits_with_value;

        let mask_remainder = (1 << bits_with_remainder) - 1;
        let mask_value = 0xff - mask_remainder;

        let value = ((byte & mask_value) >> bits_with_remainder) + remainder;
        remainder = (byte & mask_remainder) << (bits_per_segment - bits_with_remainder);

        acc.push(Some(value));

        if bits_with_value == (bits_per_byte - bits_per_segment) {
            bits_with_value = (bits_with_value + bits_per_segment) % bits_per_byte;

            acc.push(Some(remainder));
            remainder = 0;
        }

        acc
    });

    // add padding characters
    if bits_with_value > 0 {
        segments_to_encode.push(Some(remainder));
        segments_to_encode.push(None);

        if bits_with_value == 6 {
            segments_to_encode.push(None);
        }
    }

    segments_to_encode
}

fn assemble_bytes_from_segments(bytes: &[Option<u8>], bits_per_segment: u8) -> BytesType {
    let bits_per_byte = 8;
    let mut inverted_bit_output = 0;
    let mut byte_in_progress = 0;

    bytes
        .iter()
        .fold(BytesType::new(), |mut acc, byte_input_option| {
            // padding
            if byte_input_option.is_none() {
                return acc;
            }

            let byte_input = byte_input_option.unwrap();

            for inverted_bit_input in 0..bits_per_segment {
                let current_bit_input = bits_per_segment - inverted_bit_input - 1;
                let current_bit_output: u8 = bits_per_byte - inverted_bit_output - 1;

                let current_mask_input = 1 << current_bit_input;
                let current_mask_output = 1 << current_bit_output;

                if (byte_input & current_mask_input) > 0 {
                    byte_in_progress += current_mask_output;
                }

                inverted_bit_output = (inverted_bit_output + 1) % bits_per_byte;

                if inverted_bit_output == 0 {
                    acc.push(byte_in_progress);
                    byte_in_progress = 0;
                }
            }

            acc
        })
}

// ----------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_vecs::{HexadecimalType, UnicodeType};

    // ----------------

    #[test]
    fn unit_base64_from_bytes() {
        let bytes = BytesType::from(Base64Type::COMPLETE_ALPHABET_BYTES.to_vec());
        let expected_result = Base64Type::from(Base64Type::COMPLETE_ALPHABET);

        let result = Base64Type::from(&bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_to_base64() {
        let bytes = BytesType::from(Base64Type::COMPLETE_ALPHABET_BYTES.to_vec());
        let expected_result = Base64Type::from(Base64Type::COMPLETE_ALPHABET);

        let result = bytes.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_to_base64_padding_one_byte() {
        let mut bytes_raw = Base64Type::COMPLETE_ALPHABET_BYTES.to_vec();
        bytes_raw.push(0x00);
        bytes_raw.push(0x11);

        let bytes = BytesType::from(bytes_raw);
        let expected_result = Base64Type::from(format!("{}ABE=", Base64Type::COMPLETE_ALPHABET));

        let result = bytes.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_to_base64_padding_two_bytes() {
        let mut bytes_raw = Base64Type::COMPLETE_ALPHABET_BYTES.to_vec();
        bytes_raw.push(0x00);

        let bytes = BytesType::from(bytes_raw);
        let expected_result = Base64Type::from(format!("{}AA==", Base64Type::COMPLETE_ALPHABET));

        let result = bytes.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    #[should_panic(expected = "found invalid base64 characters: ._.")]
    fn unit_base64_from_invalid_string() {
        let _ = Base64Type::from("HUIfTQ.sP_A.h9");
    }

    #[test]
    fn unit_base64_to_bytes() {
        let base64 = Base64Type::from(Base64Type::COMPLETE_ALPHABET);
        let expected_result = BytesType::from(Base64Type::COMPLETE_ALPHABET_BYTES.to_vec());

        let result = base64.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_to_bytes_padding_one_byte() {
        let mut expected_result_raw = Base64Type::COMPLETE_ALPHABET_BYTES.to_vec();
        expected_result_raw.push(0x00);
        expected_result_raw.push(0x11);

        let base64 = Base64Type::from(format!("{}ABE=", Base64Type::COMPLETE_ALPHABET));
        let expected_result = BytesType::from(expected_result_raw);

        let result = base64.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_to_bytes_padding_two_bytes() {
        let mut expected_result_raw = Base64Type::COMPLETE_ALPHABET_BYTES.to_vec();
        expected_result_raw.push(0x00);

        let base64 = Base64Type::from(format!("{}AA==", Base64Type::COMPLETE_ALPHABET));
        let expected_result = BytesType::from(expected_result_raw);

        let result = base64.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_to_string() {
        let base64 = Base64Type::from(Base64Type::COMPLETE_ALPHABET);
        let expected_result = String::from(
            "Base64[64] { ABCDEFGH IJKLMNOP QRSTUVWX YZabcdef ghijklmn opqrstuv wxyz0123 456789+/ }",
        );

        let result = base64.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_to_string_trim_whitespace() {
        let base64 = Base64Type::from(
            "\r\nABCD\nEFGH\n  IJKL\nMNOP\t\nQRSTUV\nW\n\t XYZa\nbcdef\nghi\njklmn\nopqrstuv\nwxyz01234\n5\n67\n89+/\t",
        );
        let expected_result = String::from(
            "Base64[64] { ABCDEFGH IJKLMNOP QRSTUVWX YZabcdef ghijklmn opqrstuv wxyz0123 456789+/ }",
        );

        let result = base64.to_string();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_base64_hex_to_base64_via_bytes() {
        let hexadecimal = HexadecimalType::from(Base64Type::COMPLETE_ALPHABET_HEX);
        let expected_result = Base64Type::from(Base64Type::COMPLETE_ALPHABET);

        let result = hexadecimal.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_to_hex_via_bytes() {
        let base64 = Base64Type::from(Base64Type::COMPLETE_ALPHABET);
        let expected_result = HexadecimalType::from(Base64Type::COMPLETE_ALPHABET_HEX);

        let result = base64.to_hexadecimal();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_unicode_to_base64_via_bytes() {
        let unicode = UnicodeType::from("Hi. Servus. Grüezi. 你好.");
        let expected_result = Base64Type::from("SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg==");

        let result = unicode.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_to_unicode_via_bytes() {
        let base64 = Base64Type::from("SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg==");
        let expected_result = UnicodeType::from("Hi. Servus. Grüezi. 你好.");

        let result = base64.to_unicode();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_base64_len() {
        let base64 = Base64Type::from("SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg==");

        let expected_result = 40;

        let result = base64.len();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_len_bytes() {
        let base64 = Base64Type::from("SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg==");

        let expected_result = 28;

        let result = base64.len_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_len_bits() {
        let base64 = Base64Type::from("SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg==");

        let expected_result = 224;

        let result = base64.len_bits();

        assert_eq!(result, expected_result);
    }
}
