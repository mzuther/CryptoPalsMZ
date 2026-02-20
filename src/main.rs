#![allow(unused)]

use cryptopals;
use std::fs;

fn main() {
    println!("");

    challenge_06();

    println!("");
}

fn challenge_06() {
    let cypher_text_base64: String =
        fs::read_to_string("original/6.txt").expect("could not read file");

    let cypher_text_bytes = cryptopals::helpers::base64_to_bytes(
        &cryptopals::helpers::unicode_to_bytes(&cypher_text_base64),
    );

    let (cypher_text_start, _) = cypher_text_bytes.split_at(8);
    assert_eq!(
        cryptopals::helpers::bytes_to_hex(&cypher_text_start),
        "1d421f4d0b0f021f"
    );

    let keysize = 2;
    let edit_size_2 =
        cryptopals::hamming_distance_bits_bytes(&cypher_text_bytes[0..2], &cypher_text_bytes[2..4]);
    let edit_size_2_normalized = (edit_size_2 as f64) / (keysize as f64);
    assert_eq!(edit_size_2_normalized, 2.5);

    let keysize = 3;
    let edit_size_2 =
        cryptopals::hamming_distance_bits_bytes(&cypher_text_bytes[0..3], &cypher_text_bytes[3..6]);
    let edit_size_2_normalized = (edit_size_2 as f64) / (keysize as f64);
    assert_eq!(edit_size_2_normalized, 2.0);

    let keysize = 5;
    let edit_size_2 = cryptopals::hamming_distance_bits_bytes(
        &cypher_text_bytes[0..5],
        &cypher_text_bytes[5..10],
    );
    let edit_size_2_normalized = (edit_size_2 as f64) / (keysize as f64);
    assert_eq!(edit_size_2_normalized, 1.2);

    let keysize = 2;
    let transposed_vecs = cryptopals::transpose_bytes(&cypher_text_bytes, keysize);
    let (cypher_start_1, _) = transposed_vecs[0].split_at(4);
    let (cypher_start_2, _) = transposed_vecs[1].split_at(4);
    assert_eq!(
        cryptopals::helpers::bytes_to_hex(&cypher_start_1),
        "1d1f0b02"
    );
    assert_eq!(
        cryptopals::helpers::bytes_to_hex(&cypher_start_2),
        "424d0f1f"
    );

    let keysize = 3;
    let transposed_vecs = cryptopals::transpose_bytes(&cypher_text_bytes, keysize);
    let (cypher_start_1, _) = transposed_vecs[0].split_at(3);
    let (cypher_start_2, _) = transposed_vecs[1].split_at(3);
    let (cypher_start_3, _) = transposed_vecs[2].split_at(2);
    assert_eq!(cryptopals::helpers::bytes_to_hex(&cypher_start_1), "1d4d02");
    assert_eq!(cryptopals::helpers::bytes_to_hex(&cypher_start_2), "420b1f");
    assert_eq!(cryptopals::helpers::bytes_to_hex(&cypher_start_3), "1f0f");

    let keysize = 5;
    let transposed_vecs = cryptopals::transpose_bytes(&cypher_text_bytes, keysize);
    let (cypher_start_1, _) = transposed_vecs[0].split_at(2);
    let (cypher_start_2, _) = transposed_vecs[1].split_at(2);
    let (cypher_start_3, _) = transposed_vecs[2].split_at(2);
    let (cypher_start_4, _) = transposed_vecs[3].split_at(1);
    let (cypher_start_5, _) = transposed_vecs[4].split_at(1);
    assert_eq!(cryptopals::helpers::bytes_to_hex(&cypher_start_1), "1d0f");
    assert_eq!(cryptopals::helpers::bytes_to_hex(&cypher_start_2), "4202");
    assert_eq!(cryptopals::helpers::bytes_to_hex(&cypher_start_3), "1f1f");
    assert_eq!(cryptopals::helpers::bytes_to_hex(&cypher_start_4), "4d");
    assert_eq!(cryptopals::helpers::bytes_to_hex(&cypher_start_5), "0b");

    let keysize_range = 2..41;
    let scores = cryptopals::guess_keysize_from_hamming_distance(&cypher_text_bytes, keysize_range);

    println!("[keysizes]");
    for score in scores.get(0..5).unwrap() {
        println!("{}: {}", score.keysize, score.score);
    }
    println!("");

    let take_xth_score = 0;
    let score = scores
        .get(take_xth_score)
        .expect("there should always be a few elements");

    let transposed_vecs = cryptopals::transpose_bytes(&cypher_text_bytes, score.keysize);
    let mut proposed_key = Vec::new();

    for block in 0..transposed_vecs.len() {
        let keys_range_bytes = 0x00..0xff;
        let mut scores =
            cryptopals::find_lowest_score_xor_bytes(&transposed_vecs[block], keys_range_bytes);

        println!("[block {}/{}]", block + 1, score.keysize);
        scores.sort_by_key(|a| a.key);
        for score in &scores {
            println!(
                "{}: {} -> {}",
                score.key,
                score.score,
                cryptopals::helpers::bytes_to_ascii(score.decoded.get(0..30).unwrap())
            );

            cryptopals::print_histogram(&vec![score.key], &score.decoded, 0.01, 4);
        }
        println!("");

        let score = scores.first().expect("there should always be one element");
        proposed_key.push(score.key);
    }

    let result_bytes = cryptopals::fixed_xor_bytes(&cypher_text_bytes, &proposed_key);
    let result = cryptopals::helpers::bytes_to_ascii(&result_bytes);

    println!("{result}");
    println!("");

    // assert_eq!(result, expected_result);
}

fn challenge_04() {
    let all_strings_hex: String =
        fs::read_to_string("original/4.txt").expect("could not read file");

    let mut best_score = cryptopals::constants::ScoreXOR {
        score: 1000.0,
        key: 0xff,
        decoded: Vec::new(),
    };

    let lines = all_strings_hex.lines();
    for line_hex in lines {
        println!("\n[{line_hex}]\n");
        let keys_range_bytes = 0x00..0x80;
        let mut scores = cryptopals::find_lowest_score_xor_bytes(
            &cryptopals::helpers::hex_to_bytes(&line_hex),
            keys_range_bytes,
        );
        scores.sort_by_key(|a| a.key);

        for score in &scores {
            cryptopals::print_histogram(&vec![score.key], &score.decoded, 0.05, 5);
        }
    }
}

fn challenge_03() {
    let string_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    let keys_range_bytes = 0x00..0x80;
    let mut scores = cryptopals::find_lowest_score_xor_bytes(
        &cryptopals::helpers::hex_to_bytes(&string_hex),
        keys_range_bytes,
    );
    scores.sort_by_key(|a| a.key);

    for score in &scores {
        cryptopals::print_histogram(&vec![score.key], &score.decoded, 0.025, 5);
    }
}

fn play_with_xor() {
    let plain_text = "einawsdlijjjeinalsdkjlkjeinpe;lrfeinasdjo;nein";
    let plain_text_bytes = cryptopals::helpers::unicode_to_bytes(&plain_text);
    let plain_text_hex = cryptopals::helpers::bytes_to_hex(&plain_text_bytes);
    let plain_text_base64 = cryptopals::helpers::unicode_to_base64(&plain_text);

    let key = "ESWAREINMAL";
    let key_bytes = cryptopals::helpers::unicode_to_bytes(&key);

    let bytes_encoded = cryptopals::fixed_xor_bytes(&plain_text_bytes, &key_bytes);
    let string_encoded = cryptopals::helpers::bytes_to_hex(&bytes_encoded);
    let bytes_encoded_base64 = cryptopals::helpers::bytes_to_base64(&bytes_encoded);
    let encoded_text_base64 = cryptopals::helpers::bytes_to_ascii(&bytes_encoded_base64);

    println!("");
    println!("TXT: {plain_text}");
    println!("Hex: {plain_text_hex}");
    println!("B64: {plain_text_base64}\n");

    println!("Key: {key}");

    println!("Hex: {string_encoded}");
    println!("B64: {encoded_text_base64}");
}
