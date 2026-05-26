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
    challenge_06();
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
