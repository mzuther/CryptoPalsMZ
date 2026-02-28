use crate::constants;
use crate::crypto_vecs::ToBytes;

use std::{convert, fmt};

// ----------------

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct Base64 {
    base64_string: String,
}

impl fmt::Display for self::Base64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Base64[{}] {{ {} }}",
            self.base64_string.chars().count(),
            self.get_representation()
        )
    }
}

impl fmt::Debug for self::Base64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Base64[{}] {{ {} }}",
            self.base64_string.chars().count(),
            self.get_representation()
        )
    }
}

impl convert::From<String> for self::Base64 {
    fn from(base64_string: String) -> Self {
        let string_without_whitespace = base64_string
            .split_ascii_whitespace()
            .fold(String::new(), |acc, string_slice| acc + string_slice);

        let invalid_characters: String = string_without_whitespace
            .chars()
            .filter(|c| !constants::BASE64_VALID_CHARACTERS.contains(*c))
            .collect();

        assert!(
            invalid_characters.len() == 0,
            "found invalid base64 characters: {}",
            invalid_characters
        );

        self::Base64 {
            base64_string: string_without_whitespace,
        }
    }
}

impl convert::From<&str> for self::Base64 {
    fn from(base64_string: &str) -> Self {
        Self::from(String::from(base64_string))
    }
}

impl convert::From<&super::Bytes> for self::Base64 {
    fn from(bytes: &super::Bytes) -> Self {
        let base64_segments = self::split_bytes_into_segments(&bytes, 6);

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

impl ToBytes for self::Base64 {
    fn to_bytes(&self) -> super::Bytes {
        let decoded_bytes = self
            .base64_string
            .bytes()
            .fold(Vec::new(), |mut acc, char_int| {
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

        super::Bytes::from(base64_bytes)
    }

    // performance: prevent intermediate conversion to Bytes
    fn to_base64(&self) -> self::Base64 {
        self.clone()
    }
}

impl self::Base64 {
    pub fn get_representation(&self) -> String {
        let block_size = 8;

        let base64_blocks: String =
            self.base64_string
                .chars()
                .enumerate()
                .fold(String::new(), |mut acc, (index, char)| {
                    acc.push(char);

                    if index % block_size == block_size - 1 {
                        acc.push(' ');
                    }

                    acc
                });

        String::from(base64_blocks.trim_end())
    }
}

// ----------------

fn split_bytes_into_segments(bytes: &super::Bytes, bits_per_segment: u8) -> Vec<Option<u8>> {
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

fn assemble_bytes_from_segments(bytes: &Vec<Option<u8>>, bits_per_segment: u8) -> super::Bytes {
    let bits_per_byte = 8;
    let mut inverted_bit_output = 0;
    let mut byte_in_progress = 0;

    let assembled_segments =
        bytes
            .iter()
            .fold(super::Bytes::new(), |mut acc, byte_input_option| {
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
            });

    assembled_segments
}

// ----------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_vecs::{Bytes, Hexadecimal, Unicode};

    #[test]
    fn unit_conversion_bytes_to_base64_1() {
        let bytes = self::Bytes::from(constants::get_base64_complete_alphabet_as_bytes());
        let expected_result = self::Base64::from(constants::BASE64_COMPLETE_ALPHABET);

        let result = self::Base64::from(&bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_base64_2() {
        let bytes = self::Bytes::from(constants::get_base64_complete_alphabet_as_bytes());
        let expected_result = self::Base64::from(constants::BASE64_COMPLETE_ALPHABET);

        let result = bytes.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_base64_padding_1() {
        let mut bytes_raw = constants::get_base64_complete_alphabet_as_bytes();
        bytes_raw.push(0x00);
        bytes_raw.push(0x11);

        let bytes = self::Bytes::from(bytes_raw);
        let expected_result =
            self::Base64::from(format!("{}ABE=", constants::BASE64_COMPLETE_ALPHABET));

        let result = bytes.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_base64_padding_2() {
        let mut bytes_raw = constants::get_base64_complete_alphabet_as_bytes();
        bytes_raw.push(0x00);

        let bytes = self::Bytes::from(bytes_raw);
        let expected_result =
            self::Base64::from(format!("{}AA==", constants::BASE64_COMPLETE_ALPHABET));

        let result = bytes.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    #[should_panic(expected = "found invalid base64 characters: ._.")]
    fn unit_conversion_base64_invalid_string() {
        let _ = self::Base64::from("HUIfTQ.sP_A.h9");
    }

    #[test]
    fn unit_conversion_base64_to_bytes() {
        let base64 = self::Base64::from(constants::BASE64_COMPLETE_ALPHABET);
        let expected_result = self::Bytes::from(constants::get_base64_complete_alphabet_as_bytes());

        let result = base64.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_bytes_padding_1() {
        let mut expected_result_raw = constants::get_base64_complete_alphabet_as_bytes();
        expected_result_raw.push(0x00);
        expected_result_raw.push(0x11);

        let base64 = self::Base64::from(format!("{}ABE=", constants::BASE64_COMPLETE_ALPHABET));
        let expected_result = self::Bytes::from(expected_result_raw);

        let result = base64.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_bytes_padding_2() {
        let mut expected_result_raw = constants::get_base64_complete_alphabet_as_bytes();
        expected_result_raw.push(0x00);

        let base64 = self::Base64::from(format!("{}AA==", constants::BASE64_COMPLETE_ALPHABET));
        let expected_result = self::Bytes::from(expected_result_raw);

        let result = base64.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_string() {
        let base64 = self::Base64::from(constants::BASE64_COMPLETE_ALPHABET);
        let expected_result = String::from(
            "Base64[64] { ABCDEFGH IJKLMNOP QRSTUVWX YZabcdef ghijklmn opqrstuv wxyz0123 456789+/ }",
        );

        let result = base64.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_string_trim_whitespace() {
        let base64 = self::Base64::from(
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
    fn unit_conversion_hex_to_base64_via_bytes() {
        let hexadecimal = self::Hexadecimal::from(constants::BASE64_COMPLETE_ALPHABET_HEX);
        let expected_result = self::Base64::from(constants::BASE64_COMPLETE_ALPHABET);

        let result = hexadecimal.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_hex_via_bytes() {
        let base64 = self::Base64::from(constants::BASE64_COMPLETE_ALPHABET);
        let expected_result = self::Hexadecimal::from(constants::BASE64_COMPLETE_ALPHABET_HEX);

        let result = base64.to_hexadecimal();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_unicode_to_base64_via_bytes() {
        let unicode = self::Unicode::from("Hi. Servus. Grüezi. 你好.");
        let expected_result = self::Base64::from("SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg==");

        let result = unicode.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_unicode_via_bytes() {
        let base64 = self::Base64::from("SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg==");
        let expected_result = self::Unicode::from("Hi. Servus. Grüezi. 你好.");

        let result = base64.to_unicode();

        assert_eq!(result, expected_result);
    }
}
