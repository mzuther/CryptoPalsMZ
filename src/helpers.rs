pub fn unicode_to_bytes(string_unicode: &str) -> Vec<u8> {
    Vec::from(string_unicode)
}

pub fn hex_to_bytes(string_hex: &str) -> Vec<u8> {
    hex::decode(string_hex).expect("Broken conversion")
}

pub fn bytes_to_unicode(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("invalid UTF-8 string")
}

pub fn bytes_to_ascii(bytes: &[u8]) -> String {
    let mut bytes_as_string = String::new();

    for &byte in bytes {
        let ascii_character = byte as char;
        bytes_as_string.push(ascii_character);
    }

    bytes_as_string
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn unicode_to_base64(string_unicode: &str) -> String {
    let bytes = crate::helpers::unicode_to_bytes(&string_unicode);
    let encoded_bytes = bytes_to_base64(&bytes);

    bytes_to_ascii(&encoded_bytes)
}

pub fn hex_to_base64(string_hex: &str) -> String {
    let bytes = crate::helpers::hex_to_bytes(&string_hex);
    let encoded_bytes = bytes_to_base64(&bytes);

    bytes_to_ascii(&encoded_bytes)
}

pub fn bytes_to_base64(bytes_raw: &[u8]) -> Vec<u8> {
    let segments_to_encode = crate::helpers::split_bytes_into_segments(bytes_raw, 6);

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

    encoded_bytes
}

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

pub fn base64_to_unicode(string_base64: &str) -> String {
    let bytes = crate::helpers::unicode_to_bytes(&string_base64);
    let decoded_bytes = base64_to_bytes(&bytes);

    bytes_to_unicode(&decoded_bytes)
}

pub fn base64_to_hex(string_base64: &str) -> String {
    let bytes = crate::helpers::unicode_to_bytes(&string_base64);
    let decoded_bytes = base64_to_bytes(&bytes);

    bytes_to_hex(&decoded_bytes)
}

pub fn base64_to_bytes(bytes_base64: &[u8]) -> Vec<u8> {
    let mut decoded_bytes = Vec::new();

    for &char_int in bytes_base64 {
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

    assemble_bytes_from_segments(&decoded_bytes, 6)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_conversion_unicode_to_bytes_1() {
        let unicode_string = "Ab3";
        let expected_result = vec![0x41, 0x62, 0x33];

        let result = unicode_to_bytes(&unicode_string);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_unicode_to_bytes_2() {
        let unicode_string = "Aü你";
        let expected_result = vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0];

        let result = unicode_to_bytes(&unicode_string);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_hex_to_bytes_1() {
        let hex_string = "41c3bce4bda0";
        let expected_result = vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0];

        let result = hex_to_bytes(&hex_string);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_hex_to_bytes_2() {
        let hex_string = "21A3DCF4DBA1";
        let expected_result = vec![0x21, 0xa3, 0xdc, 0xf4, 0xdb, 0xa1];

        let result = hex_to_bytes(&hex_string);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_unicode_1() {
        let bytes = vec![0x41, 0x62, 0x33];
        let expected_result = "Ab3";

        let result = bytes_to_unicode(&bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_unicode_2() {
        let bytes = vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0];
        let expected_result = "Aü你";

        let result = bytes_to_unicode(&bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_ascii_1() {
        let bytes = vec![0x41, 0x62, 0x33];
        let expected_result = "Ab3";

        let result = bytes_to_ascii(&bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_ascii_2() {
        let bytes = vec![0x46, 0x72, 0xc3, 0xbc, 0x68, 0x6a, 0x61, 0x68, 0x72];
        let expected_result = "FrÃ¼hjahr";

        let result = bytes_to_ascii(&bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_bytes_to_hex() {
        let bytes = vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0];
        let expected_result = "41c3bce4bda0";

        let result = bytes_to_hex(&bytes);

        assert_eq!(result, expected_result);
    }

    // contains complete base64 alphabet
    const BASE64_COMPLETE_ALPHABET: &str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const BASE64_COMPLETE_ALPHABET_HEX: &str = "00108310518720928b30d38f41149351559761969b71d79f8218a39259a7a29aabb2dbafc31cb3d35db7e39ebbf3dfbf";

    #[test]
    fn unit_conversion_bytes_to_base64() {
        let plain_bytes = hex_to_bytes(&BASE64_COMPLETE_ALPHABET_HEX);
        let expected_result = unicode_to_bytes(&BASE64_COMPLETE_ALPHABET);

        let result = bytes_to_base64(&plain_bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_bytes() {
        let base64_bytes = unicode_to_bytes(&BASE64_COMPLETE_ALPHABET);
        let expected_result = hex_to_bytes(&BASE64_COMPLETE_ALPHABET_HEX);

        let result = base64_to_bytes(&base64_bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_hex_to_base64() {
        let hex_string = BASE64_COMPLETE_ALPHABET_HEX;
        let expected_result = BASE64_COMPLETE_ALPHABET;

        let result = hex_to_base64(&hex_string);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_hex_to_base64_padding_1() {
        let hex_string = format!("{BASE64_COMPLETE_ALPHABET_HEX}0011");
        let expected_result = format!("{BASE64_COMPLETE_ALPHABET}ABE=");

        let result = hex_to_base64(&hex_string);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_hex_to_base64_padding_2() {
        let hex_string = format!("{BASE64_COMPLETE_ALPHABET_HEX}00");
        let expected_result = format!("{BASE64_COMPLETE_ALPHABET}AA==");

        let result = hex_to_base64(&hex_string);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_hex() {
        let base64_string = BASE64_COMPLETE_ALPHABET;
        let expected_result = BASE64_COMPLETE_ALPHABET_HEX;

        let result = base64_to_hex(&base64_string);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_hex_padding_1() {
        let base64_string = format!("{BASE64_COMPLETE_ALPHABET}ABE=");
        let expected_result = format!("{BASE64_COMPLETE_ALPHABET_HEX}0011");

        let result = base64_to_hex(&base64_string);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_hex_padding_2() {
        let base64_string = format!("{BASE64_COMPLETE_ALPHABET}AA==");
        let expected_result = format!("{BASE64_COMPLETE_ALPHABET_HEX}00");

        let result = base64_to_hex(&base64_string);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_unicode_to_base64() {
        let unicode_string = "Hi. Servus. Grüezi. 你好.";
        let expected_result = "SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg==";

        let result = unicode_to_base64(&unicode_string);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_conversion_base64_to_unicode() {
        let base64_string = "SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg==";
        let expected_result = "Hi. Servus. Grüezi. 你好.";

        let result = base64_to_unicode(&base64_string);

        assert_eq!(result, expected_result);
    }
}
