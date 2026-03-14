#![allow(unused)]

// ----------------

use std::{fs, usize};

use cryptopals::constants;
use cryptopals::crypto_vecs::traits::{
    FromBytes, InternalData, InternalDataVec, InternalDataVecMut, LenBytes, ToBytes,
};
use cryptopals::crypto_vecs::{self, Base64Type, BlockBytes, BytesType, UnicodeType};
use rand::rand_core::block;
use rayon::str::Bytes;

// ================

fn main() {
    challenge_12();
}

// ----------------

// Byte-at-a-time ECB decryption (Simple)
fn challenge_12() {
    let padding_until_next_block = find_padding_to_next_block_using_encryption_oracle(0).unwrap();
    let block_size =
        find_padding_to_next_block_using_encryption_oracle(padding_until_next_block).unwrap();

    let ecb_probe = BytesType::from_unicode_literal(&"Detector".repeat(6));
    let aes_mode = cryptopals::detect_aes_mode(&ecb_probe.to_blocks(block_size));

    assert_eq!(aes_mode, constants::AesMode::ECB);

    println!();
    println!("Detected padding:     {}", padding_until_next_block);
    println!("Detected block size:  {}", block_size);
    println!("Detected AES mode:    {}", aes_mode);

    let cypher_without_probe = aes_encryption_oracle_new(&Default::default());

    println!();
    println!("Decrypting using oracle ...");
    println!();

    let plain = (0..cypher_without_probe.number_of_blocks()).fold(
        BytesType::default(),
        |mut acc, block_index| {
            acc.extend(decypher_block_using_encryption_oracle(
                block_index,
                block_size,
            ));

            acc
        },
    );
}

fn find_padding_to_next_block_using_encryption_oracle(padding_size: usize) -> Option<usize> {
    let mut probe = BytesType::default();

    if padding_size > 0 {
        probe.extend(vec!['A' as u8; padding_size]);
    }

    let cypher_length_original = aes_encryption_oracle_new(&probe).len_bytes();

    for padding_length in (1..) {
        probe.push('A' as u8);

        let cypher_length_with_probe = aes_encryption_oracle_new(&probe).len_bytes();

        if cypher_length_with_probe > cypher_length_original {
            return Some(padding_length);
        }
    }

    None
}

fn decypher_block_using_encryption_oracle(block_index: usize, block_size: usize) -> BytesType {
    println!("  -----");

    let skipped_bytes = block_index * block_size;

    let plain_part = (0..block_size)
        .map(|x| x + 1)
        .fold(BytesType::default(), |mut acc, n| {
            assert_eq!(
                acc.len_bytes(),
                n - 1,
                "accumulator has wrong size (previous letter not found)"
            );
            let current_key_size = block_size - n;

            let probe_last_byte = BytesType::from_unicode_literal(&"A".repeat(current_key_size));
            let first_block_cypher_minus_one = aes_encryption_oracle_new(&probe_last_byte)
                .to_bytes()
                .skip_n_as_collection(skipped_bytes)
                .unwrap()
                .take_n_as_collection(block_size)
                .unwrap();

            for last_byte in (0x00..=0xff) {
                let mut probe = probe_last_byte.clone();
                probe.extend(&acc);
                probe.push(last_byte);

                assert_eq!(probe.len_bytes(), block_size, "block has wrong size");

                let cypher = aes_encryption_oracle_new(&probe);
                let first_block_cypher = cypher
                    .to_bytes()
                    .skip_n_as_collection(skipped_bytes)
                    .unwrap()
                    .take_n_as_collection(block_size)
                    .unwrap();

                if first_block_cypher == first_block_cypher_minus_one {
                    acc.push(last_byte);
                    assert_eq!(acc.len_bytes(), n);
                    println!("  {:02}/{:02}  {}", block_index, n, acc.to_codepage_1252());

                    break;
                }
            }

            acc
        });

    plain_part
}

fn aes_encryption_oracle_new(plain: &BytesType) -> BlockBytes {
    let block_size_bits = 128;

    // this is not efficient, but well hidden, and that is the main point here
    let plain_secret = BytesType::from_base64_literal(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
        YnkK",
    );

    let mut plain_appended = plain.clone();
    plain_appended.extend(plain_secret);

    let plain_appended_blocks = plain_appended.to_blocks_bits(block_size_bits);
    let key = BytesType::from_hex_literal("90405f56 52d48857 e932db66 8b526fd2");

    plain_appended_blocks.aes_ecb_encrypt(&key).unwrap()
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
