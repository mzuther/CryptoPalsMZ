use hex;

// ----------------

pub trait FromToBytes {
    fn to_bytes_struct(&self) -> Bytes;
    fn from_bytes_struct(b: &Bytes) -> Self;

    fn to_bytes(&self) -> Vec<u8> {
        let b = self.to_bytes_struct();

        b.bytes
    }

    fn from_bytes<T: FromToBytes>(bytes: &Vec<u8>) -> T {
        let b = Bytes {
            bytes: bytes.clone(),
        };

        T::from_bytes_struct(&b)
    }
}

// ----------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Bytes {
    bytes: Vec<u8>,
}

impl From<Vec<u8>> for Bytes {
    fn from(bytes: Vec<u8>) -> Self {
        Bytes { bytes: bytes }
    }
}

impl From<&[u8]> for Bytes {
    fn from(bytes: &[u8]) -> Self {
        Bytes {
            bytes: bytes.to_vec(),
        }
    }
}

impl From<u8> for Bytes {
    fn from(byte: u8) -> Self {
        Bytes { bytes: vec![byte] }
    }
}

impl FromToBytes for Bytes {
    fn to_bytes_struct(&self) -> Bytes {
        self.clone()
    }

    fn from_bytes_struct(b: &Bytes) -> Self {
        b.clone()
    }
}

// ----------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Hexadecimal {
    hex_string: String,
}

impl From<String> for Hexadecimal {
    fn from(hex_string: String) -> Self {
        Hexadecimal {
            hex_string: hex_string,
        }
    }
}

impl From<&str> for Hexadecimal {
    fn from(hex_string: &str) -> Self {
        Hexadecimal {
            hex_string: String::from(hex_string),
        }
    }
}

impl FromToBytes for Hexadecimal {
    fn to_bytes_struct(&self) -> Bytes {
        Bytes {
            bytes: hex::decode(&self.to_string()).expect("Broken conversion"),
        }
    }

    fn from_bytes_struct(b: &Bytes) -> Self {
        Self {
            hex_string: hex::encode(&b.bytes),
        }
    }
}

impl ToString for Hexadecimal {
    fn to_string(&self) -> String {
        self.hex_string.clone()
    }
}

// ----------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Base64 {
    base64_string: String,
}

impl From<String> for Base64 {
    fn from(base64_string: String) -> Self {
        Base64 {
            base64_string: base64_string,
        }
    }
}

impl From<&str> for Base64 {
    fn from(base64_string: &str) -> Self {
        Base64 {
            base64_string: String::from(base64_string),
        }
    }
}

impl FromToBytes for Base64 {
    fn to_bytes_struct(&self) -> Bytes {
        let mut decoded_bytes = Vec::new();

        for char_int in self.to_string().bytes() {
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

        Bytes {
            bytes: assemble_bytes_from_segments(&decoded_bytes, 6),
        }
    }

    fn from_bytes_struct(b: &Bytes) -> Self {
        let segments_to_encode = split_bytes_into_segments(&b.bytes, 6);

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

        Self {
            base64_string: encoded_bytes,
        }
    }
}

impl ToString for Base64 {
    fn to_string(&self) -> String {
        self.base64_string.clone()
    }
}

// ----------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Unicode {
    unicode_string: String,
}

impl Unicode {
    fn get_iso_8859_1(self) -> String {
        let mut bytes_as_string = String::new();

        for byte in self.to_bytes() {
            let iso_character = byte as char;
            bytes_as_string.push(iso_character);
        }

        bytes_as_string
    }
}

impl From<String> for Unicode {
    fn from(unicode_string: String) -> Self {
        Unicode {
            unicode_string: unicode_string,
        }
    }
}

impl From<&str> for Unicode {
    fn from(unicode_string: &str) -> Self {
        Unicode {
            unicode_string: String::from(unicode_string),
        }
    }
}

impl FromToBytes for Unicode {
    fn to_bytes_struct(&self) -> Bytes {
        Bytes {
            bytes: Vec::from(self.to_string()),
        }
    }

    fn from_bytes_struct(b: &Bytes) -> Self {
        Self {
            unicode_string: String::from_utf8(b.to_bytes()).expect("invalid UTF-8 string"),
        }
    }
}

impl ToString for Unicode {
    fn to_string(&self) -> String {
        self.unicode_string.clone()
    }
}

// ----------------

fn split_bytes_into_segments(bytes: &[u8], bits_per_segment: u8) -> Vec<Option<u8>> {
    let mut segments_to_encode = Vec::new();

    let bits_per_byte = 8;
    let mut bits_with_value = 0;
    let mut remainder = 0;

    for &byte in bytes {
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

fn assemble_bytes_from_segments(bytes: &Vec<Option<u8>>, bits_per_segment: u8) -> Vec<u8> {
    let mut assembled_segments = Vec::new();

    let bits_per_byte = 8;
    let mut inverted_bit_output = 0;
    let mut byte_in_progress = 0;

    for &byte_input in bytes {
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
    fn unit_conversion_single_byte_to_bytes() {
        let bytes = Bytes::from(0xd3);

        // avoid "vec!" macro as this is used by the implementation
        let mut expected_vec = Vec::new();
        expected_vec.push(0xd3);

        let expected_result = Bytes::from(expected_vec);

        let result = bytes.to_bytes_struct();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_vector_to_bytes() {
        let bytes = Bytes::from(vec![0x41, 0x62, 0x33]);

        // avoid "vec!" macro as this is used by the implementation
        let mut expected_vec = Vec::new();
        expected_vec.push(0x41);
        expected_vec.push(0x62);
        expected_vec.push(0x33);

        let expected_result = Bytes::from(expected_vec);

        let result = bytes.to_bytes_struct();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_conversion_hex_to_bytes_1() {
        let hex_string = Hexadecimal::from("41c3bce4bda0");
        let expected_result = Bytes::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);

        let result = hex_string.to_bytes_struct();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_hex_to_bytes_2() {
        let hex_string = Hexadecimal::from("21A3DCF4DBA1");
        let expected_result = Bytes::from(vec![0x21, 0xa3, 0xdc, 0xf4, 0xdb, 0xa1]);

        let result = hex_string.to_bytes_struct();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_hex() {
        let bytes = Bytes::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);
        let expected_result = Hexadecimal::from("41c3bce4bda0");

        let result = Hexadecimal::from_bytes_struct(&bytes.to_bytes_struct());

        assert_eq!(result, expected_result);
    }

    // ----------------

    // contains complete base64 alphabet
    const BASE64_COMPLETE_ALPHABET: &str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const BASE64_COMPLETE_ALPHABET_HEX: &str = "00108310518720928b30d38f41149351559761969b71d79f8218a39259a7a29aabb2dbafc31cb3d35db7e39ebbf3dfbf";

    fn get_base64_complete_alphabet_as_bytes() -> Bytes {
        Bytes::from(vec![
            0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8b, 0x30, 0xd3, 0x8f, 0x41, 0x14,
            0x93, 0x51, 0x55, 0x97, 0x61, 0x96, 0x9b, 0x71, 0xd7, 0x9f, 0x82, 0x18, 0xa3, 0x92,
            0x59, 0xa7, 0xa2, 0x9a, 0xab, 0xb2, 0xdb, 0xaf, 0xc3, 0x1c, 0xb3, 0xd3, 0x5d, 0xb7,
            0xe3, 0x9e, 0xbb, 0xf3, 0xdf, 0xbf,
        ])
    }

    #[test]
    fn unit_conversion_bytes_to_base64() {
        let bytes = get_base64_complete_alphabet_as_bytes();
        let expected_result = Base64::from(BASE64_COMPLETE_ALPHABET);

        let result = Base64::from_bytes_struct(&bytes.to_bytes_struct());

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_bytes() {
        let base64_bytes = Base64::from(BASE64_COMPLETE_ALPHABET);
        let expected_result = get_base64_complete_alphabet_as_bytes();

        let result = base64_bytes.to_bytes_struct();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_conversion_unicode_to_bytes_1() {
        let unicode_string = Unicode::from("Ab3");
        let expected_result = Bytes::from(vec![0x41, 0x62, 0x33]);

        let result = unicode_string.to_bytes_struct();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_unicode_to_bytes_2() {
        let unicode_string = Unicode::from("Aü你");
        let expected_result = Bytes::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);

        let result = unicode_string.to_bytes_struct();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_unicode_1() {
        let bytes = Bytes::from(vec![0x41, 0x62, 0x33]);
        let expected_result = Unicode::from("Ab3");

        let result = Unicode::from_bytes_struct(&bytes.to_bytes_struct());

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_unicode_2() {
        let bytes = Bytes::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);
        let expected_result = Unicode::from("Aü你");

        let result = Unicode::from_bytes_struct(&bytes.to_bytes_struct());

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_conversion_hex_to_base64() {
        let hex_string = Hexadecimal::from(BASE64_COMPLETE_ALPHABET_HEX);
        let expected_result = Base64::from(BASE64_COMPLETE_ALPHABET);

        let result = Base64::from_bytes_struct(&hex_string.to_bytes_struct());

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_hex_to_base64_padding_1() {
        let hex_string = Hexadecimal::from(format!("{BASE64_COMPLETE_ALPHABET_HEX}0011"));
        let expected_result = Base64::from(format!("{BASE64_COMPLETE_ALPHABET}ABE="));

        let result = Base64::from_bytes_struct(&hex_string.to_bytes_struct());

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_hex_to_base64_padding_2() {
        let hex_string = Hexadecimal::from(format!("{BASE64_COMPLETE_ALPHABET_HEX}00"));
        let expected_result = Base64::from(format!("{BASE64_COMPLETE_ALPHABET}AA=="));

        let result = Base64::from_bytes_struct(&hex_string.to_bytes_struct());

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_hex() {
        let base64_string = Base64::from(BASE64_COMPLETE_ALPHABET);
        let expected_result = Hexadecimal::from(BASE64_COMPLETE_ALPHABET_HEX);

        let result = Hexadecimal::from_bytes_struct(&base64_string.to_bytes_struct());

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_hex_padding_1() {
        let base64_string = Base64::from(format!("{BASE64_COMPLETE_ALPHABET}ABE="));
        let expected_result = Hexadecimal::from(format!("{BASE64_COMPLETE_ALPHABET_HEX}0011"));

        let result = Hexadecimal::from_bytes_struct(&base64_string.to_bytes_struct());

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_hex_padding_2() {
        let base64_string = Base64::from(format!("{BASE64_COMPLETE_ALPHABET}AA=="));
        let expected_result = Hexadecimal::from(format!("{BASE64_COMPLETE_ALPHABET_HEX}00"));

        let result = Hexadecimal::from_bytes_struct(&base64_string.to_bytes_struct());

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_unicode_to_base64() {
        let unicode_string = Unicode::from("Hi. Servus. Grüezi. 你好.");
        let expected_result = Base64::from("SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg==");

        let result = Base64::from_bytes_struct(&unicode_string.to_bytes_struct());

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_unicode() {
        let base64_string = Base64::from("SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg==");
        let expected_result = Unicode::from("Hi. Servus. Grüezi. 你好.");

        let result = Unicode::from_bytes_struct(&base64_string.to_bytes_struct());

        assert_eq!(result, expected_result);
    }

    // #[test]
    // fn unit_conversion_get_bytes() {
    //     let cryptovec_bytes = CryptoVec::from(Bytes::from(vec![0x51, 0x55, 0x97, 0x61, 0x96]));
    //     let expected_result: Vec<u8> = vec![0x51, 0x55, 0x97, 0x61, 0x96];

    //     let result = cryptovec_bytes.get_bytes();

    //     assert_eq!(result, expected_result);
    // }

    // #[test]
    // fn unit_conversion_get_hex() {
    //     let cryptovec_hex = CryptoVec::from(Hexadecimal::from("a01bc5ef"));
    //     let expected_result = String::from("a01bc5ef");

    //     let result = cryptovec_hex.get_hex();

    //     assert_eq!(result, expected_result);
    // }

    // #[test]
    // fn unit_conversion_get_base64() {
    //     let cryptovec_base64 = CryptoVec::from(Base64::from("HUIfTQ"));
    //     let expected_result = String::from("HUIfTQ");

    //     let result = cryptovec_base64.get_base64();

    //     assert_eq!(result, expected_result);
    // }

    // #[test]
    // fn unit_conversion_get_unicode() {
    //     let cryptovec_unicode = CryptoVec::from(Unicode::from("Hi. Servus. Grüezi. 你好."));
    //     let expected_result = String::from("Hi. Servus. Grüezi. 你好.");

    //     let result = cryptovec_unicode.get_unicode();

    //     assert_eq!(result, expected_result);
    // }

    #[test]
    fn unit_conversion_get_iso_8859_1_01() {
        let bytes = Bytes::from(vec![0x41, 0x62, 0x33]);
        let expected_result = String::from("Ab3");

        let result = Unicode::from_bytes_struct(&bytes).get_iso_8859_1();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_get_iso_8859_1_02() {
        let bytes = Bytes::from(vec![0x46, 0x72, 0xc3, 0xbc, 0x68, 0x6a, 0x61, 0x68, 0x72]);
        let expected_result = String::from("FrÃ¼hjahr");

        let result = Unicode::from_bytes_struct(&bytes).get_iso_8859_1();

        assert_eq!(result, expected_result);
    }
}
