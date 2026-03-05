#![allow(unused)]

// ----------------

use std::fs;

use cryptopals::crypto_vecs::BytesType;
use cryptopals::crypto_vecs::traits::ToBytes;

// ----------------

fn main() {
    challenge_06();
}

fn challenge_06() {
    let cypher_string: String = fs::read_to_string("original/6.txt").expect("could not read file");
    let cypher = BytesType::from_base64_literal(&cypher_string);

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
    let mut proposed_key = BytesType::new();

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
        proposed_key.extend(score.key.as_slice());
    }

    let manual_key =
        BytesType::from_hex_literal("5465726d696e61746f7220583a204272696e6720746865206e6f697365");

    assert_eq!(manual_key, proposed_key);

    let plain = cypher.fixed_xor(&manual_key);
    let result_iso = plain.to_iso_8859_1();

    println!("{result_iso}");
    println!();

    // assert_eq!(result, expected_result);
}

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
