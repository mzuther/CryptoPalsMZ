use hex;
use std::{convert, fmt, slice, vec};

// ----------------

pub trait ToBytes {
    fn to_bytes(&self) -> self::Bytes;

    fn to_hexadecimal(&self) -> self::Hexadecimal {
        self::Hexadecimal::from(self.to_bytes())
    }

    fn to_base64(&self) -> self::Base64 {
        self::Base64::from(self.to_bytes())
    }

    fn to_unicode(&self) -> self::Unicode {
        self::Unicode::from(self.to_bytes())
    }
}

// ----------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Bytes {
    bytes: Vec<u8>,
}

impl fmt::Display for self::Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut formatted_string = String::new();

        for byte in self.iter() {
            formatted_string.push_str(&format!("{byte:#x}, "));
        }

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
}

impl IntoIterator for self::Bytes {
    type Item = u8;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.bytes.into_iter()
    }
}

// impl Iterator for self::Bytes {
//     type Item = u8;

//     fn next(&mut self) -> Option<Self::Item> {
//         self.bytes.iter().next().copied()
//     }
// }

// impl Iterator for &self::Bytes {
//     type Item = u8;

//     fn next(&mut self) -> Option<Self::Item> {
//         self.bytes.iter().next().copied()
//     }
// }

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

    // ----------------

    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn iter(&self) -> slice::Iter<'_, u8> {
        self.bytes.iter()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
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
        let bytes_plain = self.iter();
        let mut bytes_key_endless = key.iter().cycle();

        let mut result_xor = self::Bytes::new();

        for byte_plain in bytes_plain {
            let byte_key = bytes_key_endless
                .next()
                .expect("infinite key was finite after all");
            let byte_xor = (byte_plain | byte_key) & !(byte_plain & byte_key);

            result_xor.push(byte_xor);
        }

        result_xor
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
        self::Hexadecimal {
            hex_string: hex_string.trim().to_lowercase(),
        }
    }
}

impl convert::From<&str> for self::Hexadecimal {
    fn from(hex_string: &str) -> Self {
        Self::from(String::from(hex_string))
    }
}

impl convert::From<self::Bytes> for self::Hexadecimal {
    fn from(b: self::Bytes) -> Self {
        Self::from(hex::encode(b.to_vec()))
    }
}

impl ToBytes for self::Hexadecimal {
    fn to_bytes(&self) -> self::Bytes {
        let hex_bytes = hex::decode(&self.hex_string).expect("Broken conversion");

        self::Bytes::from(hex_bytes)
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
        self::Base64 {
            base64_string: String::from(base64_string.trim()),
        }
    }
}

impl convert::From<&str> for self::Base64 {
    fn from(base64_string: &str) -> Self {
        Self::from(String::from(base64_string))
    }
}

impl convert::From<self::Bytes> for self::Base64 {
    fn from(b: self::Bytes) -> Self {
        let segments_to_encode = self::split_bytes_into_segments(&b, 6);
        let mut encoded_bytes = String::new();

        for segment in &segments_to_encode {
            let mut char_int: u8;

            // padding character (=)
            if segment.is_none() {
                char_int = 61;
            } else {
                char_int = segment.unwrap();

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

            encoded_bytes.push(char_int as char);
        }

        Self::from(encoded_bytes)
    }
}

impl ToBytes for self::Base64 {
    fn to_bytes(&self) -> self::Bytes {
        let mut decoded_bytes = Vec::new();

        for char_int in self.base64_string.bytes() {
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
                "{} is not valid base64",
                char_option.unwrap()
            );

            decoded_bytes.push(char_option);
        }

        let base64_bytes = self::assemble_bytes_from_segments(&decoded_bytes, 6);
        self::Bytes::from(base64_bytes)
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

impl self::Unicode {
    pub fn to_iso_8859_1(self) -> String {
        let mut iso_string = String::new();

        for byte in self.to_bytes().to_vec() {
            let iso_char = byte as char;
            iso_string.push(iso_char);
        }

        iso_string
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

impl convert::From<self::Bytes> for self::Unicode {
    fn from(b: self::Bytes) -> Self {
        let unicode_string = String::from_utf8(b.to_vec()).expect("invalid UTF-8 string");

        Self::from(unicode_string)
    }
}

impl ToBytes for self::Unicode {
    fn to_bytes(&self) -> self::Bytes {
        let unicode_bytes = Vec::from(self.unicode_string.clone());

        self::Bytes::from(unicode_bytes)
    }
}

// ----------------

fn split_bytes_into_segments(bytes: &self::Bytes, bits_per_segment: u8) -> Vec<Option<u8>> {
    let mut segments_to_encode = Vec::new();

    let bits_per_byte = 8;
    let mut bits_with_value = 0;
    let mut remainder = 0;

    for byte in bytes.iter() {
        bits_with_value = (bits_with_value + bits_per_segment) % bits_per_byte;
        let bits_with_remainder = bits_per_byte - bits_with_value;

        let mask_remainder = (1 << bits_with_remainder) - 1;
        let mask_value = 0xff - mask_remainder;

        let value = ((byte & mask_value) >> bits_with_remainder) + remainder;
        remainder = (byte & mask_remainder) << (bits_per_segment - bits_with_remainder);

        segments_to_encode.push(Some(value));

        if bits_with_value == (bits_per_byte - bits_per_segment) {
            bits_with_value = (bits_with_value + bits_per_segment) % bits_per_byte;

            segments_to_encode.push(Some(remainder));
            remainder = 0;
        }
    }

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
    let mut assembled_segments = self::Bytes::new();

    let bits_per_byte = 8;
    let mut inverted_bit_output = 0;
    let mut byte_in_progress = 0;

    for byte_input in bytes {
        // padding
        if byte_input.is_none() {
            return assembled_segments;
        }

        for inverted_bit_input in 0..bits_per_segment {
            let current_bit_input = bits_per_segment - inverted_bit_input - 1;
            let current_bit_output: u8 = bits_per_byte - inverted_bit_output - 1;

            let current_mask_input = 1 << current_bit_input;
            let current_mask_output = 1 << current_bit_output;

            if (byte_input.unwrap() & current_mask_input) > 0 {
                byte_in_progress += current_mask_output;
            }

            inverted_bit_output = (inverted_bit_output + 1) % bits_per_byte;

            if inverted_bit_output == 0 {
                assembled_segments.push(byte_in_progress);
                byte_in_progress = 0;
            }
        }
    }

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

        let result = self::Hexadecimal::from(bytes);

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
        let hexadecimal = self::Hexadecimal::from(" \t41c3bce4bda0\n");
        let expected_result = String::from("hex:41c3bce4bda0");

        let result = hexadecimal.to_string();

        assert_eq!(result, expected_result);
    }

    // ----------------

    // base64-encoded string containing complete base64 alphabet
    const BASE64_COMPLETE_ALPHABET: &str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // plain-text bytes which yields the base64-encoded string above
    fn get_base64_complete_alphabet_as_bytes() -> Vec<u8> {
        vec![
            0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8b, 0x30, 0xd3, 0x8f, 0x41, 0x14,
            0x93, 0x51, 0x55, 0x97, 0x61, 0x96, 0x9b, 0x71, 0xd7, 0x9f, 0x82, 0x18, 0xa3, 0x92,
            0x59, 0xa7, 0xa2, 0x9a, 0xab, 0xb2, 0xdb, 0xaf, 0xc3, 0x1c, 0xb3, 0xd3, 0x5d, 0xb7,
            0xe3, 0x9e, 0xbb, 0xf3, 0xdf, 0xbf,
        ]
    }

    // plain-text hexadecimal string which yields the base64-encoded string above
    const BASE64_COMPLETE_ALPHABET_HEX: &str = "00108310518720928b30d38f41149351559761969b71d79f8218a39259a7a29aabb2dbafc31cb3d35db7e39ebbf3dfbf";

    #[test]
    fn unit_conversion_bytes_to_base64_1() {
        let bytes = self::Bytes::from(get_base64_complete_alphabet_as_bytes());
        let expected_result = self::Base64::from(BASE64_COMPLETE_ALPHABET);

        let result = self::Base64::from(bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_base64_2() {
        let bytes = self::Bytes::from(get_base64_complete_alphabet_as_bytes());
        let expected_result = self::Base64::from(BASE64_COMPLETE_ALPHABET);

        let result = bytes.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_base64_padding_1() {
        let mut bytes_raw = get_base64_complete_alphabet_as_bytes();
        bytes_raw.push(0x00);
        bytes_raw.push(0x11);

        let bytes = self::Bytes::from(bytes_raw);
        let expected_result = self::Base64::from(format!("{BASE64_COMPLETE_ALPHABET}ABE="));

        let result = bytes.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_base64_padding_2() {
        let mut bytes_raw = get_base64_complete_alphabet_as_bytes();
        bytes_raw.push(0x00);

        let bytes = self::Bytes::from(bytes_raw);
        let expected_result = self::Base64::from(format!("{BASE64_COMPLETE_ALPHABET}AA=="));

        let result = bytes.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_bytes() {
        let base64 = self::Base64::from(BASE64_COMPLETE_ALPHABET);
        let expected_result = self::Bytes::from(get_base64_complete_alphabet_as_bytes());

        let result = base64.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_bytes_padding_1() {
        let mut expected_result_raw = get_base64_complete_alphabet_as_bytes();
        expected_result_raw.push(0x00);
        expected_result_raw.push(0x11);

        let base64 = self::Base64::from(format!("{BASE64_COMPLETE_ALPHABET}ABE="));
        let expected_result = self::Bytes::from(expected_result_raw);

        let result = base64.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_bytes_padding_2() {
        let mut expected_result_raw = get_base64_complete_alphabet_as_bytes();
        expected_result_raw.push(0x00);

        let base64 = self::Base64::from(format!("{BASE64_COMPLETE_ALPHABET}AA=="));
        let expected_result = self::Bytes::from(expected_result_raw);

        let result = base64.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_string() {
        let base64 = self::Base64::from(BASE64_COMPLETE_ALPHABET);
        let expected_result = String::from(format!("base64:{BASE64_COMPLETE_ALPHABET}"));

        let result = base64.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_string_trim_whitespace() {
        let base64 = self::Base64::from(format!("\t\n{BASE64_COMPLETE_ALPHABET} "));
        let expected_result = String::from(format!("base64:{BASE64_COMPLETE_ALPHABET}"));

        let result = base64.to_string();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_conversion_hex_to_base64_via_bytes() {
        let hexadecimal = self::Hexadecimal::from(BASE64_COMPLETE_ALPHABET_HEX);
        let expected_result = self::Base64::from(BASE64_COMPLETE_ALPHABET);

        let result = hexadecimal.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_hex_via_bytes() {
        let base64 = self::Base64::from(BASE64_COMPLETE_ALPHABET);
        let expected_result = self::Hexadecimal::from(BASE64_COMPLETE_ALPHABET_HEX);

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

        let result = self::Unicode::from(bytes);

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

        let result = self::Unicode::from(bytes);

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

        let result_unicode = bytes.to_unicode();
        let result = result_unicode.to_iso_8859_1();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_to_iso_8859_1_02() {
        let bytes = self::Bytes::from(vec![0x46, 0x72, 0xc3, 0xbc, 0x68, 0x6a, 0x61, 0x68, 0x72]);
        let expected_result = String::from("FrÃ¼hjahr");

        let result_unicode = bytes.to_unicode();
        let result = result_unicode.to_iso_8859_1();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_fixed_xor_single_byte() {
        let plain_text = self::Bytes::from(0x1c);
        let key = self::Bytes::from(0x74);
        let expected_result = self::Bytes::from(0x68);

        let result = plain_text.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_fixed_xor_single_byte_key() {
        let plain_text = self::Bytes::from(vec![
            0x1c, 0x01, 0x11, 0x00, 0x1f, 0xa2, 0x4b, 0x53, 0x98, 0xc5,
        ]);
        let key = self::Bytes::from(0x74);
        let expected_result = self::Bytes::from(vec![
            0x68, 0x75, 0x65, 0x74, 0x6b, 0xd6, 0x3f, 0x27, 0xec, 0xb1,
        ]);

        let result = plain_text.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_fixed_xor_full_length_key() {
        let plain_text = self::Bytes::from(vec![
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

        let result = plain_text.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_fixed_xor_key_too_long() {
        let plain_text = self::Bytes::from(vec![0x1c, 0x01, 0x11, 0x00]);
        let key = self::Bytes::from(vec![0x68, 0x69, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20]);
        let expected_result = self::Bytes::from(vec![0x74, 0x68, 0x65, 0x20]);

        let result = plain_text.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }
}
