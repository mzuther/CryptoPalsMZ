pub fn unicode_to_bytes(string_unicode: &str) -> Vec<u8> {
    Vec::from(string_unicode)
}

pub fn hex_to_bytes(string_hex: &str) -> Vec<u8> {
    hex::decode(string_hex).expect("Broken conversion")
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn bytes_to_ascii(bytes: &[u8]) -> String {
    let mut bytes_as_string = String::new();

    for &byte in bytes {
        let ascii_character = byte as char;
        bytes_as_string.push(ascii_character);
    }

    bytes_as_string
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
