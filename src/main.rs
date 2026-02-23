#![allow(unused)]

use cryptopals;
use cryptopals::crypto_vecs::{self, ToBytes};
use std::fs;

fn main() {
    challenge_06();
}

// 2
// 0x65/0x20  0x41/0x44/0x45
// 0x54/0x74  0x20/0x27/0x31/0x45

// 3
// 0x20/0x65  0x31/0x35/0x40/0x45/0x54/0x61/0x74
// 0x20/0x54  0x00/0x41/0x45/0x61/0x65/0x74
// 0x20  0x00/0x04/0x31/0x41/0x45/0x54/0x61/0x74

// 5
// 0x20/0x65  0x41/0x45
// 0x20/0x45/0x65/0x74  0x00/0x41/0x54/0x61
// 0x20  0x45
// 0x54  0x61/0x74
// 0x00/0x20  0x11/0x15/0x31/0x65/0x74

fn challenge_06() {
    let cypher_text_string: String =
        fs::read_to_string("original/6.txt").expect("could not read file");

    let cypher_base64 = crypto_vecs::Base64::from(cypher_text_string);
    let cypher = cypher_base64.to_bytes();

    let cypher_vec = cypher.to_vec();
    let (cypher_start_vec, _) = cypher_vec.split_at(8);
    let cypher_start = crypto_vecs::Bytes::from(cypher_start_vec);

    assert_eq!(
        cypher_base64.to_hexadecimal(),
        cypher.to_hexadecimal()
    );

    assert_eq!(
        cypher_base64.to_hexadecimal(),
        cypher.to_base64().to_hexadecimal()
    );

    assert_eq!(
        cypher_start.to_hexadecimal(),
        crypto_vecs::Hexadecimal::from("1d421f4d0b0f021f")
    );

    let keysize = 2;
    let bytes = crypto_vecs::Bytes::from(&cypher_vec[0..keysize]);
    let other = crypto_vecs::Bytes::from(&cypher_vec[keysize..keysize * 2]);

    let edit_size = bytes.hamming_distance_bits(&other);
    let edit_size_normalized = (edit_size as f64) / (keysize as f64);

    assert_eq!(edit_size_normalized, 2.5);

    let keysize = 3;
    let bytes = crypto_vecs::Bytes::from(&cypher_vec[0..keysize]);
    let other = crypto_vecs::Bytes::from(&cypher_vec[keysize..keysize * 2]);

    let edit_size = bytes.hamming_distance_bits(&other);
    let edit_size_normalized = (edit_size as f64) / (keysize as f64);

    assert_eq!(edit_size_normalized, 2.0);

    let keysize = 5;
    let bytes = crypto_vecs::Bytes::from(&cypher_vec[0..keysize]);
    let other = crypto_vecs::Bytes::from(&cypher_vec[keysize..keysize * 2]);

    let edit_size = bytes.hamming_distance_bits(&other);
    let edit_size_normalized = (edit_size as f64) / (keysize as f64);

    assert_eq!(edit_size_normalized, 1.2);

    let keysize = 2;
    let transposed_vecs = cypher.transpose_bytes(keysize);

    let cypher_vec_1 = transposed_vecs[0].to_vec();
    let cypher_vec_2 = transposed_vecs[1].to_vec();

    let (cypher_start_1, _) = cypher_vec_1.split_at(4);
    let (cypher_start_2, _) = cypher_vec_2.split_at(4);

    assert_eq!(
        crypto_vecs::Bytes::from(cypher_start_1).to_hexadecimal(),
        crypto_vecs::Hexadecimal::from("1d1f0b02")
    );
    assert_eq!(
        crypto_vecs::Bytes::from(cypher_start_2).to_hexadecimal(),
        crypto_vecs::Hexadecimal::from("424d0f1f")
    );

    let keysize = 3;
    let transposed_vecs = cypher.transpose_bytes(keysize);

    let cypher_vec_1 = transposed_vecs[0].to_vec();
    let cypher_vec_2 = transposed_vecs[1].to_vec();
    let cypher_vec_3 = transposed_vecs[2].to_vec();

    let (cypher_start_1, _) = cypher_vec_1.split_at(3);
    let (cypher_start_2, _) = cypher_vec_2.split_at(3);
    let (cypher_start_3, _) = cypher_vec_3.split_at(2);

    assert_eq!(
        crypto_vecs::Bytes::from(cypher_start_1).to_hexadecimal(),
        crypto_vecs::Hexadecimal::from("1d4d02")
    );
    assert_eq!(
        crypto_vecs::Bytes::from(cypher_start_2).to_hexadecimal(),
        crypto_vecs::Hexadecimal::from("420b1f")
    );
    assert_eq!(
        crypto_vecs::Bytes::from(cypher_start_3).to_hexadecimal(),
        crypto_vecs::Hexadecimal::from("1f0f")
    );

    let keysize = 5;
    let transposed_vecs = cypher.transpose_bytes(keysize);

    let cypher_vec_1 = transposed_vecs[0].to_vec();
    let cypher_vec_2 = transposed_vecs[1].to_vec();
    let cypher_vec_3 = transposed_vecs[2].to_vec();
    let cypher_vec_4 = transposed_vecs[3].to_vec();
    let cypher_vec_5 = transposed_vecs[4].to_vec();

    let (cypher_start_1, _) = cypher_vec_1.split_at(2);
    let (cypher_start_2, _) = cypher_vec_2.split_at(2);
    let (cypher_start_3, _) = cypher_vec_3.split_at(2);
    let (cypher_start_4, _) = cypher_vec_4.split_at(1);
    let (cypher_start_5, _) = cypher_vec_5.split_at(1);

    assert_eq!(
        crypto_vecs::Bytes::from(cypher_start_1).to_hexadecimal(),
        crypto_vecs::Hexadecimal::from("1d0f")
    );
    assert_eq!(
        crypto_vecs::Bytes::from(cypher_start_2).to_hexadecimal(),
        crypto_vecs::Hexadecimal::from("4202")
    );
    assert_eq!(
        crypto_vecs::Bytes::from(cypher_start_3).to_hexadecimal(),
        crypto_vecs::Hexadecimal::from("1f1f")
    );
    assert_eq!(
        crypto_vecs::Bytes::from(cypher_start_4).to_hexadecimal(),
        crypto_vecs::Hexadecimal::from("4d")
    );
    assert_eq!(
        crypto_vecs::Bytes::from(cypher_start_5).to_hexadecimal(),
        crypto_vecs::Hexadecimal::from("0b")
    );

    let keysize_range = 2..41;
    let mut scores = cryptopals::guess_keysize_from_hamming_distance(&cypher, &keysize_range, 3);

    // order by score, with lowest score first
    scores.sort_by(|a, b| a.partial_cmp(&b).unwrap());

    // println!("[keysizes]");
    // for score in scores.get(0..5).unwrap() {
    //     println!("{}: {}", score.keysize, score.score);
    // }
    // println!("");

    let take_xth_score = 0;
    let score = scores
        .get(take_xth_score)
        .expect("there should always be a few elements");

    let keysize = score.keysize;
    let transposed_vecs = cypher.transpose_bytes(keysize);
    let mut proposed_key = crypto_vecs::Bytes::new();

    for (index, block) in transposed_vecs.iter().enumerate() {
        let keys_range_bytes = 0x00..0xff;
        let mut scores = cryptopals::find_lowest_score_xor(&block, &keys_range_bytes);

        println!("[block {}/{}]", index + 1, keysize);
        scores.sort_by(|a, b| a.key.cmp(&b.key));
        for score in &scores {
            // println!(
            //     "{}: {} -> {}",
            //     score.key,
            //     score.score,
            //     crypto_vecs::Unicode::from(&score.plain_text).to_string().get(0..30).unwrap()
            // );

            cryptopals::print_histogram(&score.key, &score.plain_text, 0.22, 235.0, true, 0.005, 5);
        }
        println!("");

        // sort by score, resulting in lowest score first
        scores.sort_by(|a, b| a.partial_cmp(&b).unwrap());

        let score = scores.first().expect("there should always be one element");
        proposed_key.extend(score.key.to_vec());
    }

    let plain_text = cypher.fixed_xor(&proposed_key);
    let result = plain_text.to_iso_8859_1();

    println!("{result}");
    println!("");

    // assert_eq!(result, expected_result);
}

fn challenge_04() {
    let all_strings_hex: String =
        fs::read_to_string("original/4.txt").expect("could not read file");

    let mut best_score = cryptopals::constants::ScoreXOR {
        score: 1000.0,
        key: crypto_vecs::Bytes::from(0xff),
        plain_text: crypto_vecs::Bytes::new(),
    };

    let cypher_lines_hex = all_strings_hex.lines();
    for cypher_line_hex in cypher_lines_hex {
        let hexadecimal_cypher = crypto_vecs::Hexadecimal::from(cypher_line_hex);
        let keys_range_bytes = 0x00..0x80;
        let mut scores =
            cryptopals::find_lowest_score_xor_cryptovecs(&hexadecimal_cypher, &keys_range_bytes);
        scores.sort_by(|a, b| a.key.cmp(&b.key));

        // println!("\n[{line_hex}]\n");

        for score in &scores {
            cryptopals::print_histogram(&score.key, &score.plain_text, 0.22, 235.0, true, 0.05, 7);
        }
    }
}

fn challenge_03() {
    let hexadecimal_cypher = crypto_vecs::Hexadecimal::from(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
    );

    let keys_range_bytes = 0x00..0x80;
    let mut scores =
        cryptopals::find_lowest_score_xor_cryptovecs(&hexadecimal_cypher, &keys_range_bytes);
    scores.sort_by(|a, b| a.key.cmp(&b.key));

    for score in &scores {
        cryptopals::print_histogram(&score.key, &score.plain_text, 0.22, 235.0, true, 0.025, 5);
    }
}

fn play_with_xor() {
    let unicode_plain_text =
        crypto_vecs::Unicode::from("einawsdlijjjeinalsdkjlkjeinpe;lrfeinasdjo;nein");
    let unicode_key = crypto_vecs::Unicode::from("ESWAREINMAL");
    let cypher = cryptopals::fixed_xor_cryptovecs(&unicode_plain_text, &unicode_key);

    println!("\n[Plain]");
    println!("{}", unicode_plain_text);
    println!("{}", unicode_plain_text.to_hexadecimal());
    println!("{}", unicode_plain_text.to_base64());

    println!("\n[Key]");
    println!("{}", unicode_key);
    println!("{}", unicode_key.to_hexadecimal());
    println!("{}", unicode_key.to_base64());

    println!("\n[Cypher]");
    println!("{}", cypher.to_hexadecimal());
    println!("{}", cypher.to_base64());

    println!("");
}
