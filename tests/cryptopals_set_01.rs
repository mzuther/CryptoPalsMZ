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

    let result = hexadecimal.to_base64();

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

    let result = base64.to_hexadecimal();

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_02() {
    let hexadecimal_plain = crypto_vecs::Hexadecimal::from("1c0111001f010100061a024b53535009181c");
    let hexadecimal_key = crypto_vecs::Hexadecimal::from("686974207468652062756c6c277320657965");
    let expected_result = crypto_vecs::Hexadecimal::from("746865206b696420646f6e277420706c6179");

    let plain = hexadecimal_plain.to_bytes();
    let key = hexadecimal_key.to_bytes();

    let bytes_xor = plain.fixed_xor(&key);

    let result = bytes_xor.to_hexadecimal();

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_03() {
    let hexadecimal_cypher = crypto_vecs::Hexadecimal::from(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
    );
    let cypher = hexadecimal_cypher.to_bytes();
    let expected_result = crypto_vecs::Unicode::from("Cooking MC's like a pound of bacon");

    let mut scores = cryptopals::find_lowest_score_xor(&cypher);

    // sort by score, resulting in highest score first (to get lowest score with "pop()")
    scores.sort_by(|a, b| b.partial_cmp(&a).unwrap());

    let score = scores.pop().expect("there should always be one element");
    let result = score.plain_text.to_unicode();

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
        let hexadecimal_cypher = crypto_vecs::Hexadecimal::from(string_hex);
        let cypher = hexadecimal_cypher.to_bytes();

        let mut scores = cryptopals::find_lowest_score_xor(&cypher);

        // sort by score, resulting in highest score first (to get lowest score with "pop()")
        scores.sort_by(|a, b| b.partial_cmp(&a).unwrap());

        let score = scores.pop().expect("there should always be one element");

        if score.score < best_score.score {
            best_score = score;
        }
    }

    let result = best_score.plain_text.to_unicode();

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

    let plain = unicode_plain.to_bytes();
    let key = unicode_key.to_bytes();

    let encoded_bytes = plain.fixed_xor(&key);
    let result = encoded_bytes.to_hexadecimal();

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_06() {
    let cypher_string: String = fs::read_to_string("original/6.txt").expect("could not read file");
    let cypher_base64 = crypto_vecs::Base64::from(cypher_string);
    let cypher = cypher_base64.to_bytes();

    let manual_key = crypto_vecs::Unicode::from("Terminator X: Bring the noise");
    let expected_result = manual_key.to_bytes();

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

    let transposed_vecs = cypher.transpose_bytes(best_edit_size.keysize);

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

    let cypher_base64 = crypto_vecs::Base64::from(cypher_string);
    let cypher = cypher_base64.to_bytes();

    let key_string = crypto_vecs::Unicode::from("YELLOW SUBMARINE");
    let key = key_string.to_bytes();

    let plain = cypher.aes128_ecb_decode(&key);

    let expected_result_start = crypto_vecs::Unicode::from("I'm back and I'm ringin' the bell");
    let result_start = plain.first_n(33).to_unicode();

    assert_eq!(result_start, expected_result_start);

    let expected_result_end =
        crypto_vecs::Unicode::from("Play that funky music \n");
    let result_end = plain.last_n(23).to_unicode();

    assert_eq!(result_end, expected_result_end);
}
