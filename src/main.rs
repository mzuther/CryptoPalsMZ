#![allow(unused)]

// ----------------

use rayon::prelude::*;
use std::fs;

use cryptopals::crypto_vecs::traits::{InternalDataVec, ToBytes};
use cryptopals::crypto_vecs::{self, BlockBytes, BytesType, UnicodeType};

// ================

fn main() {
    challenge_11();
}

// An ECB/CBC detection oracle
fn challenge_11() {
    let iterations = 10_000;
    let notify_after_iterations = 1_000;

    let block_size_bits = 128;
    let plain_unicode = UnicodeType::from("Detect the block".repeat(3));
    let plain = plain_unicode.to_bytes();

    let result = (1..=iterations)
        .into_par_iter()
        .fold(
            || Vec::default(),
            |mut acc, n| {
                let (encryption_mode, cypher) =
                    cryptopals::aes_encryption_oracle(&plain, block_size_bits);
                let detected_mode = cryptopals::detect_aes_mode(&cypher);

                if encryption_mode != detected_mode {
                    let error_message = format!("{:?} != {:?}", encryption_mode, detected_mode);

                    println!("{}", error_message);
                    acc.push(error_message);
                }

                if n % notify_after_iterations == 0 {
                    println!("{}", n);
                }

                acc
            },
        )
        .reduce(
            || Default::default(),
            |mut a, b| {
                a.extend(b);
                a
            },
        );
}

// ----------------

// Break repeating-key XOR
fn challenge_06() {
    let mut base64_string: String =
        fs::read_to_string("original/6.txt").expect("could not read file");

    // fix incorrect last character before padding
    base64_string = UnicodeType::replace_suffix(&base64_string, "M=\n", "A=");

    let cypher = BytesType::from_base64_literal(&base64_string);

    let keysize_range = 2..41;
    let mut scores = cryptopals::guess_keysize_from_hamming_distance(&cypher, &keysize_range, 10);

    // order by score, with lowest score first
    scores.sort_by(|a, b| a.partial_cmp(b).unwrap());

    println!("[keysizes]");
    for score in scores.get(0..5).expect("all keysizes should be processed") {
        println!("{}: {}", score.keysize, score.score);
    }
    println!();

    let take_xth_score = 0;
    let score = scores
        .get(take_xth_score)
        .expect("there should always be a few elements");

    let keysize = score.keysize;
    let transposed_blocks = cypher.transpose(keysize);
    let mut proposed_key = BytesType::default();

    for (index, block) in transposed_blocks.iter().enumerate() {
        let mut scores = cryptopals::find_lowest_score_xor(block);

        println!("[block {}/{}]", index + 1, keysize);
        scores.sort_by(|a, b| a.key.cmp(&b.key));
        for score in &scores {
            cryptopals::print_histogram(&score.key, &score.plain_text, 0.22, 235.0, true, 0.005, 5);
        }
        println!();

        // sort by score, resulting in lowest score first
        scores.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let score = scores.first().expect("there should always be one element");
        proposed_key.extend(score.key.clone());
    }

    let manual_key =
        BytesType::from_hex_literal("5465726d696e61746f7220583a204272696e6720746865206e6f697365");

    assert_eq!(manual_key, proposed_key);

    let plain = cypher.fixed_xor(&manual_key);
    let result_ascii = plain.to_codepage_1252();

    println!("{result_ascii}");
    println!();

    // assert_eq!(result, expected_result);
}

// ----------------

fn play_with_xor() {
    let plain = BytesType::from_unicode_literal("einawsdlijjjeinalsdkjlkjeinpe;lrfeinasdjo;nein");
    let key = BytesType::from_unicode_literal("ESWAREINMAL");

    let cypher = plain.fixed_xor(&key);

    println!("\n[Plain]");
    println!("{}", plain.to_hexadecimal());
    println!("{}", plain.to_base64());

    println!("\n[Key]");
    println!("{}", key.to_hexadecimal());
    println!("{}", key.to_base64());

    println!("\n[Cypher]");
    println!("{}", cypher.to_hexadecimal());
    println!("{}", cypher.to_base64());

    println!();
}
