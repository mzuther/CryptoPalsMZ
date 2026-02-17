pub fn string_to_base64(string_input: &str, is_hex_string: bool) -> String {
    let string_bytes = crate::helpers::string_to_bytes(string_input, is_hex_string);
    let encoded_bytes = bytes_to_base64(&string_bytes);

    let encoded_string = bytes_to_ascii(&encoded_bytes);

    encoded_string
}

pub fn bytes_to_base64(string_bytes: &Vec<u8>) -> Vec<u8> {
    let (mut segments_to_encode, bits_with_value, remainder) =
        crate::helpers::split_bytes_into_segments(string_bytes, 6);

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

        if char_int < 26 {
            char_int += 65
        } else if char_int < 52 {
            char_int += 71
        // padding character (=)
        } else if char_int == 0xff {
            char_int = 61
        } else {
            char_int -= 4
        }

        encoded_bytes.push(char_int);
    }

    encoded_bytes
}

pub fn bytes_to_hex(bytes: &Vec<u8>) -> String {
    hex::encode(bytes)
}

pub fn bytes_to_ascii(bytes: &Vec<u8>) -> String {
    let mut bytes_as_string = String::new();

    for &byte in bytes {
        let ascii_character = byte as char;
        bytes_as_string.push(ascii_character);
    }

    bytes_as_string
}

pub fn string_to_bytes(string_input: &str, is_hex_string: bool) -> Vec<u8> {
    let string_bytes;

    if is_hex_string {
        string_bytes = hex::decode(string_input).expect("Broken conversion");
    } else {
        string_bytes = Vec::from(string_input);
    }

    string_bytes
}

pub fn split_bytes_into_segments(
    string_bytes: &Vec<u8>,
    bits_per_segment: u8,
) -> (Vec<u8>, u8, u8) {
    let mut segments_to_encode = Vec::new();

    let bits_per_byte = 8;
    let mut bits_with_value = 0;
    let mut remainder = 0;

    for &string_byte in string_bytes {
        bits_with_value = (bits_with_value + bits_per_segment) % bits_per_byte;
        let bits_with_remainder = bits_per_byte - bits_with_value;

        let mask_remainder = (1 << bits_with_remainder) - 1;
        let mask_value = 0xff - mask_remainder;

        let value = ((string_byte & mask_value) >> bits_with_remainder) + remainder;
        remainder = (string_byte & mask_remainder) << (bits_per_segment - bits_with_remainder);

        segments_to_encode.push(value);

        if bits_with_value == (bits_per_byte - bits_per_segment) {
            bits_with_value = (bits_with_value + bits_per_segment) % bits_per_byte;

            segments_to_encode.push(remainder);
            remainder = 0;
        }
    }

    (segments_to_encode, bits_with_value, remainder)
}
