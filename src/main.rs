use hex;

fn main() {
    let string_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let encoded_string = string_to_base64(string_hex, true);
    println!("{encoded_string}");

    let string_hex_1 = "1c0111001f010100061a024b53535009181c";
    let string_hex_2 = "686974207468652062756c6c277320657965";

    let bytes_1 = string_to_bytes(string_hex_1, true);
    let bytes_2 = string_to_bytes(string_hex_2, true);

    let bytes_xor = fixed_xor(&bytes_1, &bytes_2);
    println!("{}", bytes_to_string(&bytes_xor, true));
}

fn bytes_to_string(bytes_input: &Vec<u8>, is_hex_string: bool) -> String {
    let bytes_as_string;

    if is_hex_string {
        bytes_as_string = hex::encode(bytes_input);
    } else {
        unsafe { bytes_as_string = String::from_utf8_unchecked(bytes_input.clone()) }
    }

    bytes_as_string
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

fn split_bytes_into_segments(string_bytes: Vec<u8>, bits_per_segment: u8) -> (Vec<u8>, u8, u8) {
    let mut segments_to_encode = Vec::new();

    let bits_per_byte = 8;
    let mut bits_with_value = 0;
    let mut remainder = 0;

    for string_byte in &string_bytes {
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

fn string_to_base64(string_input: &str, is_hex_string: bool) -> String {
    let string_bytes = string_to_bytes(string_input, is_hex_string);

    let (mut segments_to_encode, bits_with_value, remainder) =
        split_bytes_into_segments(string_bytes, 6);

    // add padding character
    if bits_with_value > 0 {
        segments_to_encode.push(remainder);
        segments_to_encode.push(0xff);

        if bits_with_value == 6 {
            segments_to_encode.push(0xff);
        }
    }

    let mut encoded_string = String::new();

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

        let encoded_character = char_int as char;
        encoded_string.push(encoded_character);
    }

    encoded_string
}

fn fixed_xor(bytes_1: &Vec<u8>, bytes_2: &Vec<u8>) -> Vec<u8> {
    assert_eq!(bytes_1.len(), bytes_2.len());

    let mut bytes_xor = Vec::new();

    for n in 0..bytes_1.len() {
        let byte_1 = &bytes_1[n];
        let byte_2 = &bytes_2[n];

        let byte_xor = (byte_1 | byte_2) & !(byte_1 & byte_2);
        bytes_xor.push(byte_xor);
    }

    bytes_xor
}
