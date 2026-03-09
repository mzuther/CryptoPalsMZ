use std::fs;

use cryptopals::crypto_vecs::BytesType;
use cryptopals::crypto_vecs::traits::ToBytes;

// ----------------

#[test]
fn integration_challenge_09() {
    let block_size = 20;

    let plain = BytesType::from_unicode_literal("YELLOW SUBMARINE");
    let plain_blocks = plain.to_blocks(block_size);

    let expected_result = BytesType::from_unicode_literal("YELLOW SUBMARINE\x04\x04\x04\x04");

    let padded_blocks = plain_blocks.pad_pkcs7();
    let result = padded_blocks.to_bytes();

    assert_eq!(result, expected_result);
}

#[test]
fn integration_challenge_10() {
    let block_size_bits = 128;

    let cypher_string: String = fs::read_to_string("original/10.txt").expect("could not read file");

    let cypher = BytesType::from_base64_literal(&cypher_string);
    let cypher_blocks = cypher.to_blocks_bits(block_size_bits);
    let key = BytesType::from_unicode_literal("YELLOW SUBMARINE");
    let initialization_vector = BytesType::from(vec![0x00; 16]);

    let plain_blocks = cypher_blocks
        .aes_cbc_decrypt(&key, &initialization_vector)
        .unwrap();
    let plain = plain_blocks.to_bytes();

    let expected_result_start =
        BytesType::from_unicode_literal("I'm back and I'm ringin' the bell");
    let result_start = plain.first_n_as_collection(33).unwrap();

    assert_eq!(result_start, expected_result_start);

    let expected_result_end = BytesType::from_unicode_literal("Play that funky music \n");
    let result_end = plain.last_n_as_collection(23).unwrap();

    assert_eq!(result_end, expected_result_end);
}
