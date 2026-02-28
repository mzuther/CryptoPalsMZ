use cryptopals::constants;
use cryptopals::crypto_vecs::{self, ToBytes};

use std::{collections::HashMap, fs};

#[test]
fn integration_challenge_01() {
    let hexadecimal = crypto_vecs::Bytes::from_hex_literal(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
    );

    let expected_result = crypto_vecs::Base64::from(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
    );

    let result = hexadecimal.to_base64();

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_01_reverse() {
    let base64 = crypto_vecs::Bytes::from_base64_literal(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
    );

    let expected_result = crypto_vecs::Hexadecimal::from(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
    );

    let result = base64.to_hexadecimal();

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_02() {
    let plain = crypto_vecs::Bytes::from_hex_literal("1c0111001f010100061a024b53535009181c");
    let key = crypto_vecs::Bytes::from_hex_literal("686974207468652062756c6c277320657965");

    let expected_result = crypto_vecs::Hexadecimal::from("746865206b696420646f6e277420706c6179");

    let bytes_xor = plain.fixed_xor(&key);
    let result = bytes_xor.to_hexadecimal();

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_03() {
    let cypher = crypto_vecs::Bytes::from_hex_literal(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
    );

    let expected_result =
        crypto_vecs::Bytes::from_unicode_literal("Cooking MC's like a pound of bacon");

    let mut scores = cryptopals::find_lowest_score_xor(&cypher);

    // sort by score, resulting in highest score first (to get lowest score with "pop()")
    scores.sort_by(|a, b| b.partial_cmp(&a).unwrap());

    let score = scores.pop().expect("there should always be one element");
    let result = score.plain_text;

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_04() {
    let all_strings_hex: String =
        fs::read_to_string("original/4.txt").expect("could not read file");

    let expected_result =
        crypto_vecs::Bytes::from_unicode_literal("Now that the party is jumping\n");

    let mut best_score = cryptopals::constants::ScoreXOR {
        score: 1000.0,
        key: crypto_vecs::Bytes::from(0xff),
        plain_text: crypto_vecs::Bytes::new(),
    };

    for string_hex in all_strings_hex.lines() {
        let cypher = crypto_vecs::Bytes::from_hex_literal(string_hex);
        let mut scores = cryptopals::find_lowest_score_xor(&cypher);

        // sort by score, resulting in highest score first (to get lowest score with "pop()")
        scores.sort_by(|a, b| b.partial_cmp(&a).unwrap());

        let score = scores.pop().expect("there should always be one element");

        if score.score < best_score.score {
            best_score = score;
        }
    }

    let result = best_score.plain_text;

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_05() {
    let plain = crypto_vecs::Bytes::from_unicode_literal(
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
    );
    let key = crypto_vecs::Bytes::from_unicode_literal("ICE");

    let expected_result = crypto_vecs::Hexadecimal::from(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
    );

    let encoded_bytes = plain.fixed_xor(&key);
    let result = encoded_bytes.to_hexadecimal();

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_06() {
    let cypher_string: String = fs::read_to_string("original/6.txt").expect("could not read file");
    let cypher = crypto_vecs::Bytes::from_base64_literal(&cypher_string);

    let expected_result = crypto_vecs::Bytes::from_unicode_literal("Terminator X: Bring the noise");

    let keysize_range = 2..41;
    let samples_hamming_distance = 10;

    let mut edit_sizes = cryptopals::guess_keysize_from_hamming_distance(
        &cypher,
        &keysize_range,
        samples_hamming_distance,
    );

    // sort by score, resulting in highest score first (to get lowest score with "pop()")
    edit_sizes.sort_by(|a, b| b.partial_cmp(&a).unwrap());

    let best_edit_size = edit_sizes
        .pop()
        .expect("there should always be a few elements");

    let transposed_vecs = cypher.transpose(best_edit_size.keysize);

    let result_key = transposed_vecs
        .iter()
        .fold(crypto_vecs::Bytes::new(), |mut acc, block| {
            let mut block_scores = cryptopals::find_lowest_score_xor(block);

            // sort by score, resulting in highest score first (to get lowest score with "pop()")
            block_scores.sort_by(|a, b| b.partial_cmp(&a).unwrap());

            let best_block_score = block_scores
                .pop()
                .expect("there should always be one element");

            acc.extend(best_block_score.key.as_slice());
            acc
        });

    assert_eq!(result_key, expected_result);
}

#[test]
fn integration_challenge_07() {
    let cypher_string: String = fs::read_to_string("original/7.txt").expect("could not read file");

    let cypher = crypto_vecs::Bytes::from_base64_literal(&cypher_string);
    let key = crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE");

    let plain = cypher.aes_128_ecb_decrypt(&key).unwrap();

    let expected_result_start =
        crypto_vecs::Bytes::from_unicode_literal("I'm back and I'm ringin' the bell");
    let result_start = plain.first_n(33).unwrap();

    assert_eq!(result_start, expected_result_start);

    let expected_result_end = crypto_vecs::Bytes::from_unicode_literal("Play that funky music \n");
    let result_end = plain.last_n(23).unwrap();

    assert_eq!(result_end, expected_result_end);
}

#[test]
fn integration_challenge_08() {
    let all_strings_hex: String =
        fs::read_to_string("original/8.txt").expect("could not read file");

    let duplicate_block = crypto_vecs::Bytes::from_hex_literal("08649af70dc06f4fd5d2d69c744cd283");

    let mut expected_result = HashMap::new();
    expected_result.insert(132, vec![duplicate_block; 3]);

    let result = all_strings_hex.lines().enumerate().fold(
        HashMap::new(),
        |mut cyphers_with_duplicates: HashMap<usize, _>, (index, string_hex)| {
            let cypher = crypto_vecs::Bytes::from_hex_literal(string_hex);

            let duplicate_blocks = cypher.find_duplicate_blocks(constants::AES_128_BYTES_IN_KEY);

            if duplicate_blocks.len() > 0 {
                cyphers_with_duplicates.insert(index, duplicate_blocks);
            }

            cyphers_with_duplicates
        },
    );

    assert_eq!(result, expected_result);
}
