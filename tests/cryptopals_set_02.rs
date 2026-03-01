use cryptopals::crypto_vecs::{self, ToBytes};

// ----------------

#[test]
fn integration_challenge_09() {
    let block_size = 20;

    let plain = crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE");
    let plain_blocks = plain.to_blocks(block_size);

    let expected_result =
        crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE\x04\x04\x04\x04");

    let padded_blocks = plain_blocks.pad_pkcs7();
    let result = padded_blocks.to_bytes();

    assert_eq!(result, expected_result);
}
