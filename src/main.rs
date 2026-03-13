#![allow(unused)]

// ----------------

use rand::prelude::*;
use std::fs;

use cryptopals::crypto_vecs::traits::{InternalDataVec, ToBytes};
use cryptopals::crypto_vecs::{self, BlockBytes, BytesType, UnicodeType};

// ================

fn main() {
    challenge_11();
}

// An ECB/CBC detection oracle
fn challenge_11() {
    let block_size_bits = 128;

    let plain_unicode = UnicodeType::from(concat!(
        "Detect the block cipher mode the function is using each time. ",
        "You should end up with a piece of code that, pointed at a black ",
        "box that might be encrypting ECB or CBC, tells you which one is happening."
    ));
    let plain = plain_unicode.to_bytes();

    for _ in 0..10 {
        let (encryption_mode, cypher) = encryption_oracle(&plain, block_size_bits);
        let detected_mode = if is_ebc_mode(&cypher, block_size_bits) {
            "ECB"
        } else {
            "CBC"
        };

        println!(
            "{}  {} -> {}",
            if encryption_mode == detected_mode {
                "correct:  "
            } else {
                "incorrect:"
            },
            encryption_mode,
            detected_mode
        );
    }
}

fn is_ebc_mode(cypher: &BytesType, block_size_bits: usize) -> bool {
    let block_size = crypto_vecs::bits_to_bytes(block_size_bits);

    for skipped_bytes in 0..block_size {
        let cypher_skipped = cypher
            .skip_n_as_collection(skipped_bytes)
            .unwrap_or(BytesType::default())
            .to_blocks_bits(block_size_bits);

        let duplicate_blocks = cypher_skipped.find_duplicate_blocks();

        if duplicate_blocks.len() > 0 {
            return true;
        }
    }

    false
}

fn get_duplicate_blocks(cypher: &BytesType, block_size_bits: usize) -> BlockBytes {
    cypher
        .to_blocks_bits(block_size_bits)
        .find_duplicate_blocks()
}

fn encryption_oracle(plain: &BytesType, block_size_bits: usize) -> (&str, BytesType) {
    let mut rng = rand::rng();

    let plain_extended = plain.affix_garbage(rng.random_range(5..=10), rng.random_range(5..=10));
    let plain_blocks = plain_extended.to_blocks_bits(block_size_bits);

    let key = BytesType::create_random_key_bits(block_size_bits);

    if rng.random() {
        let cypher_blocks = plain_blocks.aes_ecb_encrypt(&key).unwrap();

        ("ECB", cypher_blocks.to_bytes())
    } else {
        let initialization_vector = BytesType::create_random_key_bits(block_size_bits);

        let cypher_blocks = plain_blocks
            .aes_cbc_encrypt(&key, &initialization_vector)
            .unwrap();

        ("CBC", cypher_blocks.to_bytes())
    }
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
