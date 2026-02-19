use std::fs;

#[test]
fn integration_challenge_01() {
    let string_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected_result = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let result = cryptopals::helpers::hex_to_base64(&string_hex);

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_01_reverse() {
    let string_encoded = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    let expected_result = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

    let result = cryptopals::helpers::base64_to_hex(&string_encoded);

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_02() {
    let string_hex_1 = "1c0111001f010100061a024b53535009181c";
    let string_hex_2 = "686974207468652062756c6c277320657965";
    let expected_result = "746865206b696420646f6e277420706c6179";

    let bytes_xor = cryptopals::fixed_xor_bytes(
        &cryptopals::helpers::hex_to_bytes(string_hex_1),
        &cryptopals::helpers::hex_to_bytes(string_hex_2),
    );

    let result = cryptopals::helpers::bytes_to_hex(&bytes_xor);

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_03() {
    let string_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let expected_result = "Cooking MC's like a pound of bacon";

    let keys_range_bytes = 0x00..0x80;
    let scores = cryptopals::find_lowest_score_xor_bytes(
        &cryptopals::helpers::hex_to_bytes(&string_hex),
        keys_range_bytes,
    );

    let score = scores.first().expect("there should always be one element");
    let result = cryptopals::helpers::bytes_to_ascii(&score.decoded);

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_04() {
    let all_strings_hex: String =
        fs::read_to_string("original/4.txt").expect("could not read file");

    let expected_result = "Now that the party is jumping\n";

    let mut best_score = cryptopals::constants::ScoreXOR {
        score: 1000.0,
        key: 0xff,
        decoded: Vec::new(),
    };

    for string_hex in all_strings_hex.lines() {
        let keys_range_bytes = 0x00..0x80;
        let mut scores = cryptopals::find_lowest_score_xor_bytes(
            &cryptopals::helpers::hex_to_bytes(&string_hex),
            keys_range_bytes,
        );
        scores.reverse();
        let score = scores.pop().expect("there should always be one element");

        if score.score < best_score.score {
            best_score = score;
        }
    }

    let result = cryptopals::helpers::bytes_to_ascii(&best_score.decoded);

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_05() {
    let plain_text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE";
    let expected_result = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    let encoded_bytes = cryptopals::fixed_xor_unicode(&plain_text, &key);
    let result = cryptopals::helpers::bytes_to_hex(&encoded_bytes);

    assert_eq!(result, expected_result);
}
