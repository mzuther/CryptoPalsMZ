use hex;

#[derive(Debug, PartialEq)]
enum CryptoVec {
    Bytes(Vec<u8>),
    Hexadecimal(String),
    Base64(String),
    Unicode(String),
}

impl CryptoVec {
    fn to_bytes(self) -> CryptoVec {
        match self {
            CryptoVec::Bytes(ref _v) => self,
            CryptoVec::Hexadecimal(s) => Self::Bytes(hex::decode(s).expect("Broken conversion")),
            CryptoVec::Base64(s) => {
                let mut decoded_bytes = Vec::new();

                for char_int in Vec::from(s) {
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

                Self::Bytes(_assemble_bytes_from_segments(&decoded_bytes, 6))
            }
            CryptoVec::Unicode(s) => Self::Bytes(Vec::from(s)),
        }
    }

    fn to_hex(self) -> CryptoVec {
        match self {
            CryptoVec::Hexadecimal(ref _s) => self,
            other => CryptoVec::Hexadecimal(hex::encode(other.get_bytes())),
        }
    }

    fn to_base64(self) -> CryptoVec {
        match self {
            CryptoVec::Base64(ref _s) => self,
            other => {
                let bytes = other.get_bytes();
                let segments_to_encode = _split_bytes_into_segments(&bytes, 6);

                let mut encoded_bytes = Vec::new();

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

                    encoded_bytes.push(char_int);
                }

                let iso_8859_1 = CryptoVec::Bytes(encoded_bytes).get_iso_8859_1();
                CryptoVec::Base64(iso_8859_1)
            }
        }
    }

    fn to_unicode(self) -> CryptoVec {
        match self {
            CryptoVec::Unicode(ref _s) => self,
            other => CryptoVec::Unicode(
                String::from_utf8(other.get_bytes()).expect("invalid UTF-8 string"),
            ),
        }
    }

    fn get_bytes(self) -> Vec<u8> {
        match self {
            CryptoVec::Bytes(b) => b,
            other => other.to_bytes().get_bytes(),
        }
    }

    fn get_hex(self) -> String {
        match self {
            CryptoVec::Hexadecimal(s) => s,
            other => other.to_hex().get_hex(),
        }
    }

    fn get_base64(self) -> String {
        match self {
            CryptoVec::Base64(s) => s,
            other => other.to_base64().get_base64(),
        }
    }

    fn get_unicode(self) -> String {
        match self {
            CryptoVec::Unicode(s) => s,
            other => other.to_unicode().get_unicode(),
        }
    }

    fn get_iso_8859_1(self) -> String {
        let mut bytes_as_string = String::new();

        for byte in self.get_bytes() {
            let iso_character = byte as char;
            bytes_as_string.push(iso_character);
        }

        bytes_as_string
    }
}

fn _split_bytes_into_segments(bytes: &[u8], bits_per_segment: u8) -> Vec<Option<u8>> {
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

fn _assemble_bytes_from_segments(bytes: &Vec<Option<u8>>, bits_per_segment: u8) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_conversion_bytes_to_bytes() {
        let bytes = CryptoVec::Bytes(vec![0x41, 0x62, 0x33]);
        let expected_result = CryptoVec::Bytes(vec![0x41, 0x62, 0x33]);

        let result = bytes.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_unicode_to_bytes_1() {
        let unicode_string = CryptoVec::Unicode(String::from("Ab3"));
        let expected_result = CryptoVec::Bytes(vec![0x41, 0x62, 0x33]);

        let result = unicode_string.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_unicode_to_bytes_2() {
        let unicode_string = CryptoVec::Unicode(String::from("Aü你"));
        let expected_result = CryptoVec::Bytes(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);

        let result = unicode_string.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_hex_to_bytes_1() {
        let hex_string = CryptoVec::Hexadecimal(String::from("41c3bce4bda0"));
        let expected_result = CryptoVec::Bytes(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);

        let result = hex_string.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_hex_to_bytes_2() {
        let hex_string = CryptoVec::Hexadecimal(String::from("21A3DCF4DBA1"));
        let expected_result = CryptoVec::Bytes(vec![0x21, 0xa3, 0xdc, 0xf4, 0xdb, 0xa1]);

        let result = hex_string.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_unicode_1() {
        let bytes = CryptoVec::Bytes(vec![0x41, 0x62, 0x33]);
        let expected_result = CryptoVec::Unicode(String::from("Ab3"));

        let result = bytes.to_unicode();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_unicode_2() {
        let bytes = CryptoVec::Bytes(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);
        let expected_result = CryptoVec::Unicode(String::from("Aü你"));

        let result = bytes.to_unicode();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_hex() {
        let bytes = CryptoVec::Bytes(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);
        let expected_result = CryptoVec::Hexadecimal(String::from("41c3bce4bda0"));

        let result = bytes.to_hex();

        assert_eq!(result, expected_result);
    }

    // contains complete base64 alphabet
    const BASE64_COMPLETE_ALPHABET: &str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const BASE64_COMPLETE_ALPHABET_HEX: &str = "00108310518720928b30d38f41149351559761969b71d79f8218a39259a7a29aabb2dbafc31cb3d35db7e39ebbf3dfbf";

    fn get_base64_complete_alphabet_as_bytes() -> CryptoVec {
        CryptoVec::Bytes(vec![
            0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8b, 0x30, 0xd3, 0x8f, 0x41, 0x14,
            0x93, 0x51, 0x55, 0x97, 0x61, 0x96, 0x9b, 0x71, 0xd7, 0x9f, 0x82, 0x18, 0xa3, 0x92,
            0x59, 0xa7, 0xa2, 0x9a, 0xab, 0xb2, 0xdb, 0xaf, 0xc3, 0x1c, 0xb3, 0xd3, 0x5d, 0xb7,
            0xe3, 0x9e, 0xbb, 0xf3, 0xdf, 0xbf,
        ])
    }

    #[test]
    fn unit_conversion_bytes_to_base64() {
        let bytes = get_base64_complete_alphabet_as_bytes();
        let expected_result = CryptoVec::Base64(String::from(BASE64_COMPLETE_ALPHABET));

        let result = bytes.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_bytes() {
        let base64_bytes = CryptoVec::Base64(String::from(BASE64_COMPLETE_ALPHABET));
        let expected_result = get_base64_complete_alphabet_as_bytes();

        let result = base64_bytes.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_hex_to_base64() {
        let hex_string = CryptoVec::Hexadecimal(String::from(BASE64_COMPLETE_ALPHABET_HEX));
        let expected_result = CryptoVec::Base64(String::from(BASE64_COMPLETE_ALPHABET));

        let result = hex_string.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_hex_to_base64_padding_1() {
        let hex_string = CryptoVec::Hexadecimal(format!("{BASE64_COMPLETE_ALPHABET_HEX}0011"));
        let expected_result = CryptoVec::Base64(format!("{BASE64_COMPLETE_ALPHABET}ABE="));

        let result = hex_string.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_hex_to_base64_padding_2() {
        let hex_string = CryptoVec::Hexadecimal(format!("{BASE64_COMPLETE_ALPHABET_HEX}00"));
        let expected_result = CryptoVec::Base64(format!("{BASE64_COMPLETE_ALPHABET}AA=="));

        let result = hex_string.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_hex() {
        let base64_string = CryptoVec::Base64(String::from(BASE64_COMPLETE_ALPHABET));
        let expected_result = CryptoVec::Hexadecimal(String::from(BASE64_COMPLETE_ALPHABET_HEX));

        let result = base64_string.to_hex();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_hex_padding_1() {
        let base64_string = CryptoVec::Base64(format!("{BASE64_COMPLETE_ALPHABET}ABE="));
        let expected_result = CryptoVec::Hexadecimal(format!("{BASE64_COMPLETE_ALPHABET_HEX}0011"));

        let result = base64_string.to_hex();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_hex_padding_2() {
        let base64_string = CryptoVec::Base64(format!("{BASE64_COMPLETE_ALPHABET}AA=="));
        let expected_result = CryptoVec::Hexadecimal(format!("{BASE64_COMPLETE_ALPHABET_HEX}00"));

        let result = base64_string.to_hex();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_unicode_to_base64() {
        let unicode_string = CryptoVec::Unicode(String::from("Hi. Servus. Grüezi. 你好."));
        let expected_result =
            CryptoVec::Base64(String::from("SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg=="));

        let result = unicode_string.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_unicode() {
        let base64_string =
            CryptoVec::Base64(String::from("SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg=="));
        let expected_result = CryptoVec::Unicode(String::from("Hi. Servus. Grüezi. 你好."));

        let result = base64_string.to_unicode();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_get_bytes() {
        let cryptovec_bytes = CryptoVec::Bytes(vec![0x51, 0x55, 0x97, 0x61, 0x96]);
        let expected_result: Vec<u8> = vec![0x51, 0x55, 0x97, 0x61, 0x96];

        let result = cryptovec_bytes.get_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_get_hex() {
        let cryptovec_hex = CryptoVec::Hexadecimal(String::from("a01bc5ef"));
        let expected_result = String::from("a01bc5ef");

        let result = cryptovec_hex.get_hex();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_get_base64() {
        let cryptovec_base64 = CryptoVec::Base64(String::from("HUIfTQ"));
        let expected_result = String::from("HUIfTQ");

        let result = cryptovec_base64.get_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_get_unicode() {
        let cryptovec_unicode = CryptoVec::Unicode(String::from("Hi. Servus. Grüezi. 你好."));
        let expected_result = String::from("Hi. Servus. Grüezi. 你好.");

        let result = cryptovec_unicode.get_unicode();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_get_iso_8859_1_01() {
        let bytes = CryptoVec::Bytes(vec![0x41, 0x62, 0x33]);
        let expected_result = String::from("Ab3");

        let result = bytes.get_iso_8859_1();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_get_iso_8859_1_02() {
        let bytes = CryptoVec::Bytes(vec![0x46, 0x72, 0xc3, 0xbc, 0x68, 0x6a, 0x61, 0x68, 0x72]);
        let expected_result = String::from("FrÃ¼hjahr");

        let result = bytes.get_iso_8859_1();

        assert_eq!(result, expected_result);
    }
}
