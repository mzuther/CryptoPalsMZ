#![allow(unused)]

// ----------------

use std::fs;

use cryptopals::crypto_vecs::traits::{
    AutoProbe, CryptoVec, CryptoVecMut, DecryptionOracle, EncryptionOracle, LenBytes,
    ToBytes,
};
use cryptopals::crypto_vecs::{self, Base64, ByteBlocks, Bytes, Unicode};
use cryptopals::{constants, oracles};
use rand::rand_core::block;

// ================

fn main() {
    challenge_13();
}

// ----------------

// ECB cut-and-paste
fn challenge_13() {
    // 1. find block size and probe (email) length needed to create new block
    //
    //    missing bytes:  9
    //    block size:     16

    let oracle = oracles::AesEcbCookieCutter::from_key(Bytes::from_hex_literal(
        "7442f9fc 87041483 6ae3dbbe a79dccea",
    ));

    let (bytes_to_new_block, detected_block_size) = oracle.detect_block_size().unwrap();

    println!();
    println!("bytes to new block:  {}", bytes_to_new_block);
    println!("block size:          {}", detected_block_size);

    // 2. find length of prefix before email address
    //
    //    -> compare encryption of probe AAAAAAAAAAAAAAAAfoo@bar.com
    //                          to probe AAAAAAAAAxyAAAAAfoo@bar.com (move "xy")
    //    -> *two* blocks change when "xy" is split between two blocks
    //
    //    splitting point:  10
    //    prefix length:    (16 - splitting point) % 16 = 6

    let email_suffix = Bytes::from_unicode_literal("foo@bar.com");

    let mut probe_prefix = Bytes::from_unicode_literal("AAAAAAAAAAAAAAAAA");
    probe_prefix.extend(&email_suffix);

    let cypher_prefix = oracle.encrypt(probe_prefix);

    let mut block_after_prefix = 0;
    let mut prefix_size = 0;

    for (index, mut email_prefix_probe) in Bytes::new_auto_probe_mover(
        Bytes::from_unicode_literal("AAAAAAAAAAAAAAA"),
        Bytes::from_unicode_literal("xy"),
    )
    .enumerate()
    {
        email_prefix_probe.extend(&email_suffix);

        let probe = oracle.encrypt(email_prefix_probe);
        let changed_blocks = cypher_prefix.unwrap().find_changed_blocks(probe.unwrap());

        if changed_blocks.len() == 2 {
            let splitting_point = index + 1;

            block_after_prefix = changed_blocks[1];
            prefix_size = block_after_prefix * detected_block_size - splitting_point;

            break;
        }
    }

    println!("prefix size:         {}", prefix_size);

    // 3. create probe to encrypt ["user" in bytes + 12 * 0x12]
    //
    //    probe length:  missing bytes to new block (9) + length of "user" (4) = 13
    //    probe:         12foo@bar.com
    //    cypher:        2ddc9547 da54a918 e36a3af3 50f05d46
    //                   f61352a4 294fefc0 95b74da4 d51404e4
    //                   22d1e11c 327d7d74 5f00d637 d2a6cde2
    //    last block:    22d1e11c 327d7d74 5f00d637 d2a6cde2

    let mut probe_user_block =
        Bytes::new_from(vec![
            b'A';
            detected_block_size + bytes_to_new_block + 4
                - (email_suffix.len_bytes() % detected_block_size)
        ]);
    probe_user_block.extend(&email_suffix);

    let cypher_user_block = oracle.encrypt(probe_user_block);
    let user_block = cypher_user_block.unwrap().get_last_block();

    println!();
    println!("user block:          {}", user_block);

    // 4. create last block for admin user
    //
    //    probe:         [(16 - 6 = 10 * digit because of prefix) + ("admin" + 11 * 0x0B) + "@bar.com"]
    //                   1234567890admin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B@bar.com
    //    second block:  33c0df83 dbe10178 98360f25 51a9a23c

    let mut probe_admin_block = Bytes::new_from(vec![
        b'A';
        detected_block_size
            - (prefix_size
                % detected_block_size)
    ]);
    probe_admin_block.extend(Bytes::from_unicode_literal("admin"));
    probe_admin_block.extend(Bytes::new_from(vec![11; 11]));
    probe_admin_block.extend(&email_suffix);

    let cypher_admin_block = oracle.encrypt(probe_admin_block);

    let admin_block = cypher_admin_block
        .unwrap()
        .get_nth_block(block_after_prefix)
        .unwrap();

    println!("admin block:         {}", admin_block);

    // 5. use cypher from (3), but change last to block to second block of (4)
    //
    //    -> email length: 25 - 4 = 21
    //
    //    cypher:        2ddc9547 da54a918 e36a3af3 50f05d46
    //                   f61352a4 294fefc0 95b74da4 d51404e4
    //                   33c0df83 dbe10178 98360f25 51a9a23c !!!

    let mut cypher_faked_cookie = cypher_user_block.unwrap().clone();

    cypher_faked_cookie.pop();
    cypher_faked_cookie.push(admin_block.clone());

    let plain = oracle.decrypt(&cypher_faked_cookie.to_bytes());

    println!();
    println!(
        "cookie faked:        {}",
        plain.unwrap().to_bytes().to_codepage_1252()
    );

    println!();
}

// ----------------

// Break repeating-key XOR
fn challenge_06() {
    let mut base64_string: String =
        fs::read_to_string("original/6.txt").expect("could not read file");

    // fix incorrect last character before padding
    base64_string = Unicode::replace_suffix(&base64_string, "M=\n", "A=");

    let cypher = Bytes::from_base64_literal(&base64_string);

    let keysize_range = 2..41;
    let mut scores =
        cryptopals::guess_keysize_from_hamming_distance(&cypher, &keysize_range, 10);

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
    let mut proposed_key = Bytes::default();

    for (index, block) in transposed_blocks.iter().enumerate() {
        let mut scores = cryptopals::find_lowest_score_xor(block);

        println!("[block {}/{}]", index + 1, keysize);
        scores.sort_by(|a, b| a.key.cmp(&b.key));
        for score in &scores {
            cryptopals::print_histogram(
                &score.key,
                &score.plain_text,
                0.22,
                235.0,
                true,
                0.005,
                5,
            );
        }
        println!();

        // sort by score, resulting in lowest score first
        scores.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let score = scores.first().expect("there should always be one element");
        proposed_key.extend(score.key.clone());
    }

    let manual_key = Bytes::from_hex_literal(
        "5465726d696e61746f7220583a204272696e6720746865206e6f697365",
    );

    assert_eq!(manual_key, proposed_key);

    let plain = cypher.fixed_xor(&manual_key);
    let result_ascii = plain.to_codepage_1252();

    println!("{result_ascii}");
    println!();

    // assert_eq!(result, expected_result);
}

// ----------------

fn play_with_xor() {
    let plain =
        Bytes::from_unicode_literal("einawsdlijjjeinalsdkjlkjeinpe;lrfeinasdjo;nein");
    let key = Bytes::from_unicode_literal("ESWAREINMAL");

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
