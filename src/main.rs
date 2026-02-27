#![allow(unused)]

use cryptopals::constants;

use cryptopals;
use cryptopals::crypto_vecs::{self, ToBytes};
use std::fs;

fn main() {
    challenge_08();
}

fn challenge_08() {
    let all_strings_hex: String =
        fs::read_to_string("original/8.txt").expect("could not read file");

    for (index, string_hex) in all_strings_hex.lines().enumerate() {
        let hexadecimal_cypher = crypto_vecs::Hexadecimal::from(string_hex);
        let cypher = hexadecimal_cypher.to_bytes();

        let mut chunks = cypher.chunks(constants::AES_128_BYTES_IN_KEY);
        chunks.sort();

        let duplicates = chunks.iter().zip(chunks.iter().skip(1)).fold(
            Vec::new(),
            |mut acc, (chunk, next_chunk)| {
                if chunk == next_chunk {
                    acc.push(chunk);
                }

                acc
            },
        );

        if duplicates.len() > 0 {
            println!("[{}]", index);

            for duplicate_chunk in duplicates {
                println!("{}", duplicate_chunk);
            }
        }
    }

    // assert_eq!(result, expected_result);
}

fn challenge_06() {
    let cypher_string: String = fs::read_to_string("original/6.txt").expect("could not read file");

    let cypher_base64 = crypto_vecs::Base64::from(cypher_string);
    let cypher = cypher_base64.to_bytes();

    let cypher_vec = cypher.to_vec();
    let (cypher_start_vec, _) = cypher_vec.split_at(8);
    let cypher_start = crypto_vecs::Bytes::from(cypher_start_vec);

    assert_eq!(cypher_base64.to_hexadecimal(), cypher.to_hexadecimal());

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
    let mut scores = cryptopals::guess_keysize_from_hamming_distance(&cypher, &keysize_range, 10);

    // order by score, with lowest score first
    scores.sort_by(|a, b| a.partial_cmp(&b).unwrap());

    println!("[keysizes]");
    for score in scores.get(0..5).expect("all keysizes should be processed") {
        println!("{}: {}", score.keysize, score.score);
    }
    println!("");

    let take_xth_score = 0;
    let score = scores
        .get(take_xth_score)
        .expect("there should always be a few elements");

    let keysize = score.keysize;
    let transposed_vecs = cypher.transpose_bytes(keysize);
    let mut proposed_key = crypto_vecs::Bytes::new();

    for (index, block) in transposed_vecs.iter().enumerate() {
        let mut scores = cryptopals::find_lowest_score_xor(&block);

        println!("[block {}/{}]", index + 1, keysize);
        scores.sort_by(|a, b| a.key.cmp(&b.key));
        for score in &scores {
            cryptopals::print_histogram(&score.key, &score.plain_text, 0.22, 235.0, true, 0.005, 5);
        }
        println!("");

        // sort by score, resulting in lowest score first
        scores.sort_by(|a, b| a.partial_cmp(&b).unwrap());

        let score = scores.first().expect("there should always be one element");
        proposed_key.extend(score.key.as_slice());
    }

    let manual_key_hex = crypto_vecs::Hexadecimal::from(
        "5465726d696e61746f7220583a204272696e6720746865206e6f697365",
    );
    let manual_key = manual_key_hex.to_bytes();

    assert_eq!(manual_key, proposed_key);

    let plain = cypher.fixed_xor(&manual_key);
    let result_iso = plain.to_iso_8859_1();

    println!("{result_iso}");
    println!("");

    // assert_eq!(result, expected_result);
}

fn play_with_xor() {
    let unicode_plain =
        crypto_vecs::Unicode::from("einawsdlijjjeinalsdkjlkjeinpe;lrfeinasdjo;nein");
    let plain = unicode_plain.to_bytes();

    let unicode_key = crypto_vecs::Unicode::from("ESWAREINMAL");
    let key = unicode_key.to_bytes();

    let cypher = plain.fixed_xor(&key);

    println!("\n[Plain]");
    println!("{}", unicode_plain);
    println!("{}", plain.to_hexadecimal());
    println!("{}", plain.to_base64());

    println!("\n[Key]");
    println!("{}", unicode_key);
    println!("{}", key.to_hexadecimal());
    println!("{}", key.to_base64());

    println!("\n[Cypher]");
    println!("{}", cypher.to_hexadecimal());
    println!("{}", cypher.to_base64());

    println!("");
}
