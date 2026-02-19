#![allow(unused)]

use cryptopals;
use std::fs;

fn main() {
    println!("");

    let cypher_text_base64: String =
        fs::read_to_string("original/6.txt").expect("could not read file");

    let cypher_text_bytes = cryptopals::helpers::base64_to_bytes(
        &cryptopals::helpers::unicode_to_bytes(&cypher_text_base64),
    );

    let scores = cryptopals::guess_keysize_from_hamming_distance(&cypher_text_bytes);

    println!("[keysizes]");
    for score in scores.get(0..5).unwrap() {
        println!("{}: {}", score.keysize, score.score);
    }
    println!("");

    let xth_score = 0;
    let score = scores
        .get(xth_score)
        .expect("there should always be a few elements");

    let transposed_vecs = cryptopals::transpose_bytes(&cypher_text_bytes, score.keysize);
    let mut proposed_key = Vec::new();

    for block in 0..transposed_vecs.len() {
        let keys_range_bytes = 0x00..0x80;
        let scores =
            cryptopals::find_lowest_score_xor_bytes(&transposed_vecs[block], keys_range_bytes);

        println!("[block {}/{}]", block + 1, score.keysize);
        for score in scores.get(0..10).unwrap() {
            println!(
                "{}: {} -> {}",
                score.key,
                score.score,
                cryptopals::helpers::bytes_to_ascii(score.decoded.get(0..30).unwrap())
            );
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
