use crate::constants;
use hex;
use std::{convert, fmt, slice, vec};

// ----------------

pub trait ToBytes {
    fn to_bytes(&self) -> self::Bytes;

    fn to_hexadecimal(&self) -> self::Hexadecimal {
        self::Hexadecimal::from(&self.to_bytes())
    }

    fn to_base64(&self) -> self::Base64 {
        self::Base64::from(&self.to_bytes())
    }

    fn to_unicode(&self) -> self::Unicode {
        self::Unicode::from(&self.to_bytes())
    }
}

// ----------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Bytes {
    bytes: Vec<u8>,
}

impl fmt::Display for self::Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let formatted_string = self
            .iter()
            .fold(String::new(), |acc, &byte| format!("{acc}{byte:#x}, "));

        let stripped_string = formatted_string
            .strip_suffix(", ")
            .expect("string always ends in ', '");

        write!(f, "[{}]", stripped_string)
    }
}

impl convert::From<Vec<u8>> for self::Bytes {
    fn from(bytes: Vec<u8>) -> Self {
        self::Bytes { bytes: bytes }
    }
}

impl convert::From<&[u8]> for self::Bytes {
    fn from(bytes: &[u8]) -> Self {
        Self::from(bytes.to_vec())
    }
}

impl convert::From<u8> for self::Bytes {
    fn from(byte: u8) -> Self {
        Self::from(vec![byte])
    }
}

impl ToBytes for self::Bytes {
    fn to_bytes(&self) -> self::Bytes {
        self.clone()
    }

    // performance: prevent intermediate conversion to Bytes
    fn to_hexadecimal(&self) -> self::Hexadecimal {
        self::Hexadecimal::from(self)
    }

    // performance: prevent intermediate conversion to Bytes
    fn to_base64(&self) -> self::Base64 {
        self::Base64::from(self)
    }

    // performance: prevent intermediate conversion to Bytes
    fn to_unicode(&self) -> self::Unicode {
        self::Unicode::from(self)
    }
}

impl IntoIterator for self::Bytes {
    type Item = u8;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.bytes.into_iter()
    }
}

impl self::Bytes {
    pub fn new() -> Self {
        Self::from(Vec::new())
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self::from(Vec::with_capacity(capacity))
    }

    pub const fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    // ----------------

    pub fn iter(&self) -> slice::Iter<'_, u8> {
        self.bytes.iter()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    pub fn to_iso_8859_1(&self) -> String {
        self.iter()
            .fold(String::new(), |acc, &byte| format!("{acc}{}", byte as char))
    }

    // ----------------

    pub fn push(&mut self, byte: u8) {
        self.bytes.push(byte);
    }

    pub fn extend<T>(&mut self, bytes: T)
    where
        T: Into<Vec<u8>>,
    {
        self.bytes.extend(bytes.into());
    }

    // ----------------

    pub fn fixed_xor(&self, key: &self::Bytes) -> self::Bytes {
        assert!(key.len() > 0);

        let mut bytes_key_endless = key.iter().cycle();

        self.iter()
            .fold(self::Bytes::new(), |mut acc, &byte_plain| {
                let byte_key = bytes_key_endless
                    .next()
                    .expect("infinite key was finite after all");

                acc.push((byte_plain | byte_key) & !(byte_plain & byte_key));
                acc
            })
    }

    pub fn hamming_distance_bits(&self, other: &self::Bytes) -> u32 {
        let bytes_with_differing_bits = self.fixed_xor(&other);

        bytes_with_differing_bits.iter().fold(0, |acc, &byte| {
            let nibble_value_low = byte & 0x0f;
            let nibble_value_high = byte >> 4;

            let differing_bits_low = constants::LOOKUP_BITS_IN_NIBBLE
                .get(nibble_value_low as usize)
                .expect("index must be between 0 and 15")
                .clone();

            let differing_bits_high = constants::LOOKUP_BITS_IN_NIBBLE
                .get(nibble_value_high as usize)
                .expect("index must be between 0 and 15")
                .clone();

            acc + differing_bits_low + differing_bits_high
        })
    }

    pub fn transpose_bytes(&self, number_of_blocks: usize) -> Vec<self::Bytes> {
        assert!(number_of_blocks > 0);

        // performance: handle special case
        //
        // may come in useful when automatically processing single-byte keys
        if number_of_blocks == 1 {
            return vec![self.clone()];
        }

        let block_capacity = (self.len() / number_of_blocks) + 1;
        let mut transposed_blocks =
            vec![self::Bytes::with_capacity(block_capacity); number_of_blocks];

        for (index, &byte) in self.iter().enumerate() {
            let block_index = index % number_of_blocks;
            transposed_blocks[block_index].push(byte);
        }

        transposed_blocks
    }
}

// ----------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Hexadecimal {
    hex_string: String,
}

impl fmt::Display for self::Hexadecimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "hex:{}", self.hex_string)
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
            .filter(|c| !constants::HEXADECIMAL_VALID_CHARACTERS.contains(*c))
            .collect();

        assert!(
            invalid_characters.len() == 0,
            "found invalid hexadecimal characters: {}",
            invalid_characters
        );

        self::Hexadecimal {
            hex_string: string_without_whitespace,
        }
    }
}

impl convert::From<&str> for self::Hexadecimal {
    fn from(hex_string: &str) -> Self {
        Self::from(String::from(hex_string))
    }
}

impl convert::From<&self::Bytes> for self::Hexadecimal {
    fn from(bytes: &self::Bytes) -> Self {
        Self::from(hex::encode(bytes.to_vec()))
    }
}

impl ToBytes for self::Hexadecimal {
    fn to_bytes(&self) -> self::Bytes {
        let hex_bytes = hex::decode(&self.hex_string).expect("Broken conversion");

        self::Bytes::from(hex_bytes)
    }

    // performance: prevent intermediate conversion to Bytes
    fn to_hexadecimal(&self) -> self::Hexadecimal {
        self.clone()
    }
}

// ----------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Base64 {
    base64_string: String,
}

impl fmt::Display for self::Base64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "base64:{}", self.base64_string)
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

impl convert::From<&self::Bytes> for self::Base64 {
    fn from(bytes: &self::Bytes) -> Self {
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
    fn to_bytes(&self) -> self::Bytes {
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

        self::Bytes::from(base64_bytes)
    }

    // performance: prevent intermediate conversion to Bytes
    fn to_base64(&self) -> self::Base64 {
        self.clone()
    }
}

// ----------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Unicode {
    unicode_string: String,
}

impl fmt::Display for self::Unicode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.unicode_string)
    }
}

impl convert::From<String> for self::Unicode {
    fn from(unicode_string: String) -> Self {
        self::Unicode {
            unicode_string: unicode_string,
        }
    }
}

impl convert::From<&str> for self::Unicode {
    fn from(unicode_string: &str) -> Self {
        Self::from(String::from(unicode_string))
    }
}

impl convert::From<&self::Bytes> for self::Unicode {
    fn from(bytes: &self::Bytes) -> Self {
        let unicode_string = String::from_utf8(bytes.to_vec()).expect("invalid UTF-8 string");

        Self::from(unicode_string)
    }
}

impl ToBytes for self::Unicode {
    fn to_bytes(&self) -> self::Bytes {
        let unicode_bytes = Vec::from(self.unicode_string.clone());

        self::Bytes::from(unicode_bytes)
    }

    // performance: prevent intermediate conversion to Bytes
    fn to_unicode(&self) -> self::Unicode {
        self.clone()
    }
}

// ----------------

fn split_bytes_into_segments(bytes: &self::Bytes, bits_per_segment: u8) -> Vec<Option<u8>> {
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

fn assemble_bytes_from_segments(bytes: &Vec<Option<u8>>, bits_per_segment: u8) -> self::Bytes {
    let bits_per_byte = 8;
    let mut inverted_bit_output = 0;
    let mut byte_in_progress = 0;

    let assembled_segments = bytes
        .iter()
        .fold(self::Bytes::new(), |mut acc, byte_input_option| {
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

    #[test]
    fn unit_conversion_bytes_new() {
        let expected_result = self::Bytes::from(Vec::new());

        let result = self::Bytes::new();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_with_capacity_1() {
        let capacity = 10;
        let bytes = self::Bytes::with_capacity(capacity);

        assert!(bytes.capacity() >= capacity);
        assert!(bytes.capacity() < capacity * 10);
    }

    #[test]
    fn unit_conversion_bytes_with_capacity_2() {
        let capacity = 100;
        let bytes = self::Bytes::with_capacity(capacity);

        assert!(bytes.capacity() >= capacity);
        assert!(bytes.capacity() < capacity * 10);
    }

    #[test]
    fn unit_conversion_bytes_with_capacity_3() {
        let capacity = 10_000;
        let bytes = self::Bytes::with_capacity(capacity);

        assert!(bytes.capacity() >= capacity);
        assert!(bytes.capacity() < capacity * 10);
    }

    #[test]
    fn unit_conversion_single_byte_to_bytes() {
        // avoid "vec!" macro as this is used by the implementation
        let mut expected_result_vec = Vec::new();
        expected_result_vec.push(0xd3);

        let expected_result = self::Bytes::from(expected_result_vec);

        let result = self::Bytes::from(0xd3);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_vector_to_bytes() {
        // avoid "vec!" macro as this is used by the implementation
        let mut expected_result_vec = Vec::new();
        expected_result_vec.push(0x41);
        expected_result_vec.push(0x62);
        expected_result_vec.push(0x33);

        let expected_result = self::Bytes::from(expected_result_vec);

        let result = self::Bytes::from(vec![0x41, 0x62, 0x33]);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_length_single_byte() {
        let bytes = self::Bytes::from(0xd3);
        let expected_result = 1;

        let result = bytes.len();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_length_bytes() {
        let bytes = self::Bytes::from(vec![0x41, 0x62, 0x33]);
        let expected_result = 3;

        let result = bytes.len();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_push_1() {
        let expected_result = self::Bytes::from(vec![0xd3, 0x42, 0x6f]);

        let mut result = self::Bytes::new();
        result.push(0xd3);
        result.push(0x42);
        result.push(0x6f);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_push_2() {
        let expected_result = self::Bytes::from(vec![0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut result = self::Bytes::from(vec![0xd3, 0x42, 0x6f]);
        result.push(0x12);
        result.push(0x0d);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_extend_1() {
        let expected_result = self::Bytes::from(vec![0xd3, 0x42, 0x6f]);

        let mut result = self::Bytes::new();
        result.extend(vec![0xd3, 0x42, 0x6f]);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_extend_2() {
        let expected_result = self::Bytes::from(vec![0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut result = self::Bytes::from(vec![0xd3, 0x42, 0x6f]);
        result.extend(vec![0x12, 0x0d]);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_iter() {
        let bytes = self::Bytes::from(vec![0xd3, 0x42, 0x6f]);
        let mut bytes_iter = bytes.iter();

        assert_eq!(bytes_iter.next(), Some(&0xd3));
        assert_eq!(bytes_iter.next(), Some(&0x42));
        assert_eq!(bytes_iter.next(), Some(&0x6f));
        assert_eq!(bytes_iter.next(), None);
    }

    #[test]
    fn unit_conversion_bytes_into_iter() {
        let bytes = self::Bytes::from(vec![0xd3, 0x42, 0x6f]);
        let mut bytes_iter = bytes.into_iter();

        assert_eq!(bytes_iter.next(), Some(0xd3));
        assert_eq!(bytes_iter.next(), Some(0x42));
        assert_eq!(bytes_iter.next(), Some(0x6f));
        assert_eq!(bytes_iter.next(), None);
    }

    #[test]
    fn unit_conversion_byte_to_string() {
        let bytes = self::Bytes::from(0xaf);
        let expected_result = String::from("[0xaf]");

        let result = bytes.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_string() {
        let bytes = self::Bytes::from(vec![0x41, 0x62, 0xf3]);
        let expected_result = String::from("[0x41, 0x62, 0xf3]");

        let result = bytes.to_string();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_conversion_bytes_to_hex_1() {
        let bytes = self::Bytes::from(vec![0x3b, 0x44, 0x2c, 0x4e, 0xcc, 0x0f]);
        let expected_result = self::Hexadecimal::from("3b442c4ecc0f");

        let result = self::Hexadecimal::from(&bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_hex_2() {
        let bytes = self::Bytes::from(vec![0x3b, 0x44, 0x2c, 0x4e, 0xcc, 0x0f]);
        let expected_result = self::Hexadecimal::from("3b442c4ecc0f");

        let result = bytes.to_hexadecimal();

        assert_eq!(result, expected_result);
    }

    #[test]
    #[should_panic(expected = "found invalid hexadecimal characters: !!g")]
    fn unit_conversion_hex_invalid_string() {
        let _ = self::Hexadecimal::from("4A!f3!c6g1D298");
    }

    #[test]
    fn unit_conversion_hex_to_bytes_lowercase() {
        let hexadecimal = self::Hexadecimal::from("41c3bce4bda0");
        let expected_result = self::Bytes::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);

        let result = hexadecimal.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_hex_to_bytes_uppercase() {
        let hexadecimal = self::Hexadecimal::from("21A3DCF4DBA1");
        let expected_result = self::Bytes::from(vec![0x21, 0xa3, 0xdc, 0xf4, 0xdb, 0xa1]);

        let result = hexadecimal.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_hex_to_string_lowercase() {
        let hexadecimal = self::Hexadecimal::from("41c3bce4bda0");
        let expected_result = String::from("hex:41c3bce4bda0");

        let result = hexadecimal.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_hex_to_string_uppercase_spaces() {
        let hexadecimal = self::Hexadecimal::from("21A3DCF4DBA1");
        let expected_result = String::from("hex:21a3dcf4dba1");

        let result = hexadecimal.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_hex_to_string_trim_whitespace() {
        let hexadecimal = self::Hexadecimal::from("\t41\n  c3b\n\tce4b\n da\r\n 0\n\n");
        let expected_result = String::from("hex:41c3bce4bda0");

        let result = hexadecimal.to_string();

        assert_eq!(result, expected_result);
    }

    // ----------------

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
        let expected_result =
            String::from(format!("base64:{}", constants::BASE64_COMPLETE_ALPHABET));

        let result = base64.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_string_trim_whitespace() {
        let base64 = self::Base64::from(
            "\r\nABCD\nEFGH\n  IJKL\nMNOP\t\nQRSTUV\nW\n\t XYZa\nbcdef\nghi\njklmn\nopqrstuv\nwxyz01234\n5\n67\n89+/\t",
        );
        let expected_result =
            String::from(format!("base64:{}", constants::BASE64_COMPLETE_ALPHABET));

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

    // ----------------

    #[test]
    fn unit_conversion_bytes_to_unicode_1() {
        let bytes = self::Bytes::from(vec![0x41, 0x62, 0x33]);
        let expected_result = self::Unicode::from("Ab3");

        let result = self::Unicode::from(&bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_unicode_2() {
        let bytes = self::Bytes::from(vec![0x41, 0x62, 0x33]);
        let expected_result = self::Unicode::from("Ab3");

        let result = bytes.to_unicode();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_unicode_3() {
        let bytes = self::Bytes::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);
        let expected_result = self::Unicode::from("Aü你");

        let result = self::Unicode::from(&bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_unicode_4() {
        let bytes = self::Bytes::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);
        let expected_result = self::Unicode::from("Aü你");

        let result = bytes.to_unicode();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_unicode_to_bytes_1() {
        let unicode = self::Unicode::from("Ab3");
        let expected_result = self::Bytes::from(vec![0x41, 0x62, 0x33]);

        let result = unicode.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_unicode_to_bytes_2() {
        let unicode = self::Unicode::from("Aü你");
        let expected_result = self::Bytes::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);

        let result = unicode.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_unicode_to_string() {
        let unicode = self::Unicode::from("Hi. Servus. Grüezi. 你好.");
        let expected_result = String::from("Hi. Servus. Grüezi. 你好.");

        let result = unicode.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_unicode_to_string_keep_whitespace() {
        let unicode = self::Unicode::from("\n Hi. Servus. Grüezi. 你好.\t");
        let expected_result = String::from("\n Hi. Servus. Grüezi. 你好.\t");

        let result = unicode.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_to_iso_8859_1_01() {
        let bytes = self::Bytes::from(vec![0x41, 0x62, 0x33]);
        let expected_result = String::from("Ab3");

        let result = bytes.to_iso_8859_1();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_to_iso_8859_1_02() {
        let bytes = self::Bytes::from(vec![0x46, 0x72, 0xc3, 0xbc, 0x68, 0x6a, 0x61, 0x68, 0x72]);
        let expected_result = String::from("FrÃ¼hjahr");

        let result = bytes.to_iso_8859_1();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_fixed_xor_single_byte() {
        let plain = self::Bytes::from(0x1c);
        let key = self::Bytes::from(0x74);
        let expected_result = self::Bytes::from(0x68);

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_fixed_xor_single_byte_key() {
        let plain = self::Bytes::from(vec![
            0x1c, 0x01, 0x11, 0x00, 0x1f, 0xa2, 0x4b, 0x53, 0x98, 0xc5,
        ]);
        let key = self::Bytes::from(0x74);
        let expected_result = self::Bytes::from(vec![
            0x68, 0x75, 0x65, 0x74, 0x6b, 0xd6, 0x3f, 0x27, 0xec, 0xb1,
        ]);

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_fixed_xor_full_length_key() {
        let plain = self::Bytes::from(vec![
            0x1c, 0x01, 0x11, 0x00, 0x1f, 0x01, 0x01, 0x00, 0x06, 0x1a, 0x02, 0x4b, 0x53, 0x53,
            0x50, 0x09, 0x18, 0x1c,
        ]);
        let key = self::Bytes::from(vec![
            0x68, 0x69, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x62, 0x75, 0x6c, 0x6c, 0x27, 0x73,
            0x20, 0x65, 0x79, 0x65,
        ]);
        let expected_result = self::Bytes::from(vec![
            0x74, 0x68, 0x65, 0x20, 0x6b, 0x69, 0x64, 0x20, 0x64, 0x6f, 0x6e, 0x27, 0x74, 0x20,
            0x70, 0x6c, 0x61, 0x79,
        ]);

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_fixed_xor_key_too_long() {
        let plain = self::Bytes::from(vec![0x1c, 0x01, 0x11, 0x00]);
        let key = self::Bytes::from(vec![0x68, 0x69, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20]);
        let expected_result = self::Bytes::from(vec![0x74, 0x68, 0x65, 0x20]);

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_hamming_distance_bits_1() {
        // from u8
        let bytes = self::Bytes::from(0x02);
        // from Vec<u8>
        let other = self::Bytes::from(vec![0xa0]);
        let expected_result = 3;

        let result = bytes.hamming_distance_bits(&other);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hamming_distance_bits_2() {
        let bytes = self::Bytes::from(vec![0x02, 0xb0]);
        let other = self::Bytes::from(vec![0xa0, 0x01]);
        let expected_result = 7;

        let result = bytes.hamming_distance_bits(&other);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hamming_distance_bits_3() {
        let bytes = self::Bytes::from(vec![0x1d, 0x42]);
        let other = self::Bytes::from(vec![0x1f, 0x4d]);
        let expected_result = 5;

        let result = bytes.hamming_distance_bits(&other);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hamming_distance_bits_4() {
        let bytes = self::Bytes::from(vec![0x1d, 0x42, 0x1f]);
        let other = self::Bytes::from(vec![0x4d, 0x0b, 0x0f]);
        let expected_result = 6;

        let result = bytes.hamming_distance_bits(&other);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hamming_distance_bits_5() {
        let bytes = self::Bytes::from(vec![0x1d, 0x42, 0x1f, 0x4d, 0x0b]);
        let other = self::Bytes::from(vec![0x0f, 0x02, 0x1f, 0x4f, 0x13]);
        let expected_result = 6;

        let result = bytes.hamming_distance_bits(&other);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_transpose_bytes_no_transposition() {
        let bytes = self::Bytes::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let keysize = 1;

        let transposed_vecs = bytes.transpose_bytes(keysize);

        assert_eq!(transposed_vecs.len(), keysize);

        assert_eq!(transposed_vecs[0], bytes);
    }

    #[test]
    fn unit_transpose_bytes_equal_distribution() {
        let bytes = self::Bytes::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let keysize = 2;

        let transposed_vecs = bytes.transpose_bytes(keysize);

        assert_eq!(transposed_vecs.len(), keysize);

        assert_eq!(transposed_vecs[0], self::Bytes::from(vec![1, 3, 5, 7, 9]));
        assert_eq!(transposed_vecs[1], self::Bytes::from(vec![2, 4, 6, 8, 10]));
    }

    #[test]
    fn unit_transpose_bytes_unequal_distribution() {
        let bytes = self::Bytes::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let keysize = 3;

        let transposed_vecs = bytes.transpose_bytes(keysize);

        assert_eq!(transposed_vecs.len(), keysize);

        assert_eq!(transposed_vecs[0], self::Bytes::from(vec![1, 4, 7, 10]));
        assert_eq!(transposed_vecs[1], self::Bytes::from(vec![2, 5, 8]));
        assert_eq!(transposed_vecs[2], self::Bytes::from(vec![3, 6, 9]));
    }

    #[test]
    fn unit_transpose_bytes_not_enough_elements() {
        let bytes = self::Bytes::from(vec![1, 2, 3]);
        let keysize = bytes.len() + 1;

        let transposed_vecs = bytes.transpose_bytes(keysize);

        assert_eq!(transposed_vecs.len(), keysize);

        assert_eq!(transposed_vecs[0], self::Bytes::from(1));
        assert_eq!(transposed_vecs[1], self::Bytes::from(2));
        assert_eq!(transposed_vecs[2], self::Bytes::from(3));
        assert_eq!(transposed_vecs[3], self::Bytes::new());
    }
}
