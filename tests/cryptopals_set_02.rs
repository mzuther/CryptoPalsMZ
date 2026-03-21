use rayon::prelude::*;
use std::fs;

use cryptopals::crypto_vecs::traits::{EncryptionOracle, InternalData, ToBytes};
use cryptopals::crypto_vecs::{BytesType, UnicodeType};
use cryptopals::oracles;

// ================

// Implement PKCS#7 padding
#[test]
fn integration_challenge_09() {
    let block_size = 20;

    let plain = BytesType::from_unicode_literal("YELLOW SUBMARINE");
    let plain_blocks = plain.to_blocks(block_size);

    let expected_result =
        BytesType::from_unicode_literal("YELLOW SUBMARINE\x04\x04\x04\x04");

    let padded_blocks = plain_blocks.pad_pkcs7();
    let result = padded_blocks.to_bytes();

    assert_eq!(result, expected_result);
}

// ----------------

// Implement CBC mode
#[test]
fn integration_challenge_10() {
    let block_size_bits = 128;

    let cypher_string: String =
        fs::read_to_string("original/10.txt").expect("could not read file");

    let cypher = BytesType::from_base64_literal(&cypher_string);
    let cypher_blocks = cypher.to_blocks_bits(block_size_bits);
    let key = BytesType::from_unicode_literal("YELLOW SUBMARINE");
    let initialization_vector = BytesType::new_from(vec![0x00; 16]);

    let plain_blocks = cypher_blocks
        .aes_cbc_decrypt(&key, &initialization_vector)
        .unwrap();
    let plain = plain_blocks.to_bytes();

    let expected_result_start =
        BytesType::from_unicode_literal("I'm back and I'm ringin' the bell");
    let result_start = plain.take_n_as_collection(33).unwrap();

    assert_eq!(result_start, expected_result_start);

    let expected_result_end = BytesType::from_unicode_literal("Play that funky music \n");
    let result_end = plain.rtake_n_as_collection(23).unwrap();

    assert_eq!(result_end, expected_result_end);
}

// ----------------

// An ECB/CBC detection oracle
#[test]
fn integration_challenge_11() {
    let iterations = 1_000;

    let block_size_bits = 128;
    let plain_unicode = UnicodeType::from_literal(&"Detector".repeat(6));
    let plain = plain_unicode.to_bytes();

    let result = (1..=iterations)
        .into_par_iter()
        .fold(
            || String::default(),
            |mut acc, _| {
                // create oracle with new key for every iteration
                let oracle_response = oracles::AesEcbDetection::new_bits(block_size_bits)
                    .encrypt(plain.clone());

                let cypher = oracle_response.unwrap();
                let encryption_mode = oracle_response.unwrap_hint();
                let detected_mode = cryptopals::detect_aes_mode(&cypher);

                if *encryption_mode != detected_mode {
                    let error_message =
                        format!("* {} != {}\n", encryption_mode, detected_mode);

                    acc.push_str(&error_message);
                }

                acc
            },
        )
        .reduce(
            || Default::default(),
            |mut a, b| {
                a.push_str(&b);
                a
            },
        );

    assert_eq!(result.len(), 0, "{}", result);
}

// ----------------

// Byte-at-a-time ECB decryption (Simple)
#[test]
fn integration_challenge_12() {
    let oracle = oracles::AesEcbSuffix::new_bits(
        128,
        BytesType::from_base64_literal(
            "\
            Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
            aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
            dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
            YnkK",
        ),
    );

    let expected_result = BytesType::from_unicode_literal(
        "Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say hi
Did you stop? No, I just drove by\n",
    );

    let result = cryptopals::decypher_aes_ecb_via_oracle(&oracle)
        .unpad_pkcs7()
        .unwrap()
        .to_bytes();

    assert_eq!(result, expected_result);
}
