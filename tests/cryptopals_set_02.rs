use cryptopals::crypto_vecs;

// ----------------

#[test]
fn integration_challenge_09() {
    let plain = crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE");
    let block_size = 20;

    let expected_result =
        crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE\x04\x04\x04\x04");

    let result = plain.pad_pkcs7(block_size);

    assert_eq!(result, expected_result);
}
