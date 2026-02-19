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
    let (mut segments_to_encode, bits_with_value, remainder) =
        crate::helpers::split_bytes_into_segments(bytes_raw, 6);

    // add padding character
    if bits_with_value > 0 {
        segments_to_encode.push(remainder);
        segments_to_encode.push(0xff);

        if bits_with_value == 6 {
            segments_to_encode.push(0xff);
        }
    }

    let mut encoded_bytes = Vec::new();

    for segment in &segments_to_encode {
        let mut char_int = *segment;

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
        // padding character (=)
        } else if char_int == 0xff {
            char_int = 61
        // digit
        } else {
            char_int -= 4
        }

        encoded_bytes.push(char_int);
    }

    encoded_bytes
}

fn split_bytes_into_segments(bytes: &[u8], bits_per_segment: u8) -> (Vec<u8>, u8, u8) {
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

        segments_to_encode.push(value);

        if bits_with_value == (bits_per_byte - bits_per_segment) {
            bits_with_value = (bits_with_value + bits_per_segment) % bits_per_byte;

            segments_to_encode.push(remainder);
            remainder = 0;
        }
    }

    (segments_to_encode, bits_with_value, remainder)
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

    for &byte_base64 in bytes_base64 {
        let mut char_int = byte_base64;

        // plus
        if char_int == 43 {
            char_int = 62
        // slash
        } else if char_int == 47 {
            char_int = 63
        // padding character (=)
        } else if char_int == 61 {
            char_int = 0xff
        // digit
        } else if char_int <= 57 {
            char_int += 4
        // upper case letter
        } else if char_int <= 90 {
            char_int -= 65
        // lower case letter
        } else {
            char_int -= 71
        }

        decoded_bytes.push(char_int);
    }

    assemble_bytes_from_segments(&decoded_bytes, 6)
}

fn assemble_bytes_from_segments(bytes: &[u8], bits_per_segment: u8) -> Vec<u8> {
    let mut assembled_segments = Vec::new();

    let bits_per_byte = 8;
    let mut inverted_bit_output = 0;
    let mut byte_in_progress = 0;

    for &byte_input in bytes {
        // padding
        if byte_input == 0xff {
            return assembled_segments;
        }

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
    fn conversion_unicode_to_bytes_1() {
        let unicode_string = "Ab3";
        let expected_result = vec![0x41, 0x62, 0x33];

        let result = unicode_to_bytes(&unicode_string);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn conversion_unicode_to_bytes_2() {
        let unicode_string = "Aü你";
        let expected_result = vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0];

        let result = unicode_to_bytes(&unicode_string);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn conversion_hex_to_bytes_1() {
        let hex_string = "41c3bce4bda0";
        let expected_result = vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0];

        let result = hex_to_bytes(&hex_string);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn conversion_hex_to_bytes_2() {
        let hex_string = "21A3DCF4DBA1";
        let expected_result = vec![0x21, 0xa3, 0xdc, 0xf4, 0xdb, 0xa1];

        let result = hex_to_bytes(&hex_string);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn conversion_bytes_to_unicode_1() {
        let bytes = vec![0x41, 0x62, 0x33];
        let expected_result = "Ab3";

        let result = bytes_to_unicode(&bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn conversion_bytes_to_unicode_2() {
        let bytes = vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0];
        let expected_result = "Aü你";

        let result = bytes_to_unicode(&bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn conversion_bytes_to_ascii() {
        let bytes = vec![0x41, 0x62, 0x33];
        let expected_result = "Ab3";

        let result = bytes_to_ascii(&bytes);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn conversion_bytes_to_hex() {
        let bytes = vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0];
        let expected_result = "41c3bce4bda0";

        let result = bytes_to_hex(&bytes);

        assert_eq!(result, expected_result);
    }
}
