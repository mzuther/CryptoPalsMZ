use hex;

fn main() {
    let string_plain = "I'm killing your brain like a poisonous mushroom";
    let string_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

    let encoded_string = hex_string_to_base64(string_hex);
    println!("{encoded_string}");

    let encoded_string = string_to_base64(string_plain);
    println!("{encoded_string}");
}

fn string_to_bytes(string_input: &str, is_hex_string: bool) -> Vec<u8> {
    let string_bytes;

    if is_hex_string {
        string_bytes = hex::decode(string_input).expect("Broken conversion");
    } else {
        string_bytes = Vec::from(string_input);
    }

    string_bytes
}

fn hex_string_to_base64(string_hex: &str) -> String {
    _string_to_base64(string_hex, true)
}

fn string_to_base64(string_plain: &str) -> String {
    _string_to_base64(string_plain, false)
}

fn _string_to_base64(string_input: &str, is_hex_string: bool) -> String {
    let string_bytes = string_to_bytes(string_input, is_hex_string);
    let segments_to_encode = _base64_split_segments(string_bytes);
    let encoded_string = _base64_encode_segments(segments_to_encode);

    encoded_string
}

fn _split_into_segments(string_bytes: Vec<u8>, bits_per_segment: u8) -> (Vec<u8>, u8, u8) {
    let mut segments_to_encode = Vec::new();

    let bits_per_byte = 8;
    let mut bits_with_value = 0;
    let mut remainder = 0;

    for string_byte in string_bytes {
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

fn _base64_split_segments(string_bytes: Vec<u8>) -> Vec<u8> {
    let (mut segments_to_encode, bits_with_value, remainder) =
        _split_into_segments(string_bytes, 6);

    if bits_with_value > 0 {
        segments_to_encode.push(remainder);
        segments_to_encode.push(0xff);
        if bits_with_value == 6 {
            segments_to_encode.push(0xff);
        }
    }

    segments_to_encode
}

fn _base64_encode_segments(segments_to_encode: Vec<u8>) -> String {
    let mut encoded_string = String::new();

    for segment in segments_to_encode {
        let mut char_int = segment;

        if char_int < 26 {
            char_int = char_int + 65
        } else if char_int < 52 {
            char_int = char_int + 71
        // padding character (=)
        } else if char_int == 0xff {
            char_int = 61
        } else {
            char_int = char_int - 4
        }

        let encoded_character = char_int as char;
        encoded_string.push(encoded_character);
    }

    encoded_string
}
