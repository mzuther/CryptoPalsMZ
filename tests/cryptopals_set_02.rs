/* ----------------------------------------------------------------------------

   CryptoPalsMZ
   ============
   My take on https://cryptopals.com/

   Copyright (c) 2026 Martin Zuther (http://www.mzuther.de/)

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

   Thank you for using free software!

---------------------------------------------------------------------------- */

use rayon::prelude::*;
use std::fs;

use cryptopals::crypto_vecs::traits::{
    AutoProbe, CryptoVec, DecryptionOracle, EncryptionOracle, LenBytes, ToBytes,
};
use cryptopals::crypto_vecs::{Bytes, Unicode};
use cryptopals::oracles;

// ================

// Implement PKCS#7 padding
#[test]
fn integration_challenge_09() {
    let block_size = 20;

    let plain = Bytes::from_unicode_literal("YELLOW SUBMARINE");
    let plain_blocks = plain.to_blocks(block_size);

    let expected_result = Bytes::from_unicode_literal("YELLOW SUBMARINE\x04\x04\x04\x04");

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

    let cypher = Bytes::from_base64_literal(&cypher_string);
    let cypher_blocks = cypher.to_blocks_bits(block_size_bits);
    let key = Bytes::from_unicode_literal("YELLOW SUBMARINE");
    let initialization_vector = Bytes::new_from(vec![0x00; 16]);

    let plain_blocks = cypher_blocks
        .aes_cbc_decrypt(&key, &initialization_vector)
        .unwrap();
    let plain = plain_blocks.to_bytes();

    let expected_result_start =
        Bytes::from_unicode_literal("I'm back and I'm ringin' the bell");
    let result_start = plain.take_n_as_collection(33).unwrap();

    assert_eq!(result_start, expected_result_start);

    let expected_result_end = Bytes::from_unicode_literal("Play that funky music \n");
    let result_end = plain.rtake_n_as_collection(23).unwrap();

    assert_eq!(result_end, expected_result_end);
}

// ----------------

// An ECB/CBC detection oracle
#[test]
fn integration_challenge_11() {
    let iterations = 1_000;

    let block_size_bits = 128;
    let plain_unicode = Unicode::from_literal(&"Detector".repeat(6));
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
        Bytes::from_base64_literal(
            "\
            Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
            aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
            dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
            YnkK",
        ),
    );

    let expected_result = Bytes::from_unicode_literal(
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

// ----------------

// ECB cut-and-paste
#[test]
fn integration_challenge_13() {
    // 1. find block size and probe length needed to create new block
    let oracle = oracles::AesEcbCookieCutter::from_key(Bytes::from_hex_literal(
        "7442f9fc 87041483 6ae3dbbe a79dccea",
    ));

    let (block_size, unused_bytes_in_block) = oracle.detect_block_size().unwrap();

    assert_eq!(block_size, 16);
    assert_eq!(unused_bytes_in_block, 9);

    // 2. find length of content before email address
    //
    // always use a "valid" email address
    let valid_email_suffix = Bytes::from_unicode_literal("foo@bar.com");

    // block size *plus one* handles preceding content that is a multiple of
    // the block size (and empty content as well)
    let autoprobe_length = block_size + 1;

    let mut fixed_email_probe =
        Bytes::from_unicode_literal(&"A".repeat(autoprobe_length));
    fixed_email_probe.extend(&valid_email_suffix);
    let cypher_fixed_email_probe = oracle.encrypt(fixed_email_probe);

    // when "xy" (*two* bytes) is split into two blocks, *two* blocks change
    // instead of just one
    let moving_part = Bytes::from_unicode_literal("xy");

    let email_autoprobe = Bytes::new_auto_probe_mover(
        Bytes::from_unicode_literal(
            &"A".repeat(autoprobe_length - moving_part.len_bytes()),
        ),
        moving_part,
    );

    let mut preceding_content_size = 0;
    let mut block_id_after_preceding_content = 0;

    // compare encryption of probe "AAAAAA...foo@bar.com"
    //                    to probe "AAxyAA...foo@bar.com" (and move "xy")
    for (index, mut email_autoprobe) in email_autoprobe.enumerate() {
        email_autoprobe.extend(&valid_email_suffix);

        let cypher_autoprobe = oracle.encrypt(email_autoprobe);
        let changed_block_ids = cypher_fixed_email_probe
            .unwrap()
            .find_changed_blocks(cypher_autoprobe.unwrap());

        if changed_block_ids.len() == 2 {
            // add one: new block starts after "x" of moving block
            let splitting_point = index + 1;

            block_id_after_preceding_content = changed_block_ids[1];
            preceding_content_size =
                block_id_after_preceding_content * block_size - splitting_point;

            break;
        }
    }

    assert_eq!(preceding_content_size, 6);

    // 3. create probe to shift string "user" to new block and then encrypt
    //    ["user" (in bytes) + PKCS#7 padding (12 * 0x12)]

    // "user" = 4 bytes
    let probe_user_block_size = unused_bytes_in_block + 4;

    // ensure that padding is not negative
    let user_block_padding_size = block_size + probe_user_block_size
        - (valid_email_suffix.len_bytes() % block_size);

    let mut probe_user_block = Bytes::new_from(vec![b'A'; user_block_padding_size]);
    probe_user_block.extend(&valid_email_suffix);

    let cypher_user_block = oracle.encrypt(probe_user_block);

    assert_eq!(user_block_padding_size, 18);

    // 4. create padding to start new block and then encode admin user block
    //    ["admin" (in bytes) + PKCS#7 padding (11 * 0x11)]
    //    by inserting it into email address

    // ensure that padding is not negative
    let admin_block_padding_size = block_size - (preceding_content_size % block_size);
    let mut probe_admin_block = Bytes::new_from(vec![b'A'; admin_block_padding_size]);

    // admin block: user name
    probe_admin_block.extend(Bytes::from_unicode_literal("admin"));

    // admin block: PKCS#7 padding
    probe_admin_block.extend(Bytes::new_from(vec![11; 11]));

    // finalize probe
    probe_admin_block.extend(&valid_email_suffix);

    let cypher_admin_block = oracle.encrypt(probe_admin_block);

    let admin_block = cypher_admin_block
        .unwrap()
        .get_nth_block(block_id_after_preceding_content)
        .unwrap();

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
    let plain_cookie = plain.unwrap().to_bytes().to_codepage_1252();

    println!();
    println!("cookie faked:        {}", plain_cookie);

    assert!(plain_cookie.ends_with("&role=admin"));

    println!();
}
