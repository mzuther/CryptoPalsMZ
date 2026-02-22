use cryptopals::crypto_vecs::{self, ToBytes};
use std::fs;

#[test]
fn integration_challenge_01() {
    let hexadecimal = crypto_vecs::Hexadecimal::from(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
    );
    let expected_result = crypto_vecs::Base64::from(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
    );

    let result = crypto_vecs::Base64::from(hexadecimal.to_bytes());

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_01_reverse() {
    let base64 = crypto_vecs::Base64::from(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
    );
    let expected_result = crypto_vecs::Hexadecimal::from(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
    );

    let result = crypto_vecs::Hexadecimal::from(base64.to_bytes());

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_02() {
    let hexadecimal_plain = crypto_vecs::Hexadecimal::from("1c0111001f010100061a024b53535009181c");
    let hexadecimal_key = crypto_vecs::Hexadecimal::from("686974207468652062756c6c277320657965");
    let expected_result = crypto_vecs::Hexadecimal::from("746865206b696420646f6e277420706c6179");

    let bytes_xor = cryptopals::fixed_xor_cryptovecs(&hexadecimal_plain, &hexadecimal_key);

    let result = crypto_vecs::Hexadecimal::from(bytes_xor);

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_03() {
    let hexadecimal_cypher = crypto_vecs::Hexadecimal::from(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
    );
    let expected_result = crypto_vecs::Unicode::from("Cooking MC's like a pound of bacon");

    let keys_range_bytes = 0x00..0x80;
    let scores =
        cryptopals::find_lowest_score_xor_cryptovecs(&hexadecimal_cypher, &keys_range_bytes);

    let score = scores.first().expect("there should always be one element");
    let result = crypto_vecs::Unicode::from(score.plain_text.clone());

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_04() {
    let all_strings_hex: String =
        fs::read_to_string("original/4.txt").expect("could not read file");

    let expected_result = crypto_vecs::Unicode::from("Now that the party is jumping\n");

    let mut best_score = cryptopals::constants::ScoreXOR {
        score: 1000.0,
        key: crypto_vecs::Bytes::from(0xff),
        plain_text: crypto_vecs::Bytes::new(),
    };

    for string_hex in all_strings_hex.lines() {
        let keys_range_bytes = 0x00..0x80;
        let hexadecimal_cypher = crypto_vecs::Hexadecimal::from(string_hex);

        let mut scores =
            cryptopals::find_lowest_score_xor_cryptovecs(&hexadecimal_cypher, &keys_range_bytes);
        scores.reverse();
        let score = scores.pop().expect("there should always be one element");

        if score.score < best_score.score {
            best_score = score;
        }
    }

    let result = crypto_vecs::Unicode::from(best_score.plain_text);

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_05() {
    let unicode_plain = crypto_vecs::Unicode::from(
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
    );
    let unicode_key = crypto_vecs::Unicode::from("ICE");
    let expected_result = crypto_vecs::Hexadecimal::from(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
    );

    let encoded_bytes = cryptopals::fixed_xor_cryptovecs(&unicode_plain, &unicode_key);
    let result = crypto_vecs::Hexadecimal::from(encoded_bytes);

    assert_eq!(result, expected_result);
}
