#![allow(unused)]

use cryptopals;

fn main() {
    println!("\n[Cryptopals]\n");

    set_01::challenge_01_1();
    set_01::challenge_01_2();
    set_01::challenge_01_3();
    set_01::challenge_02();
    set_01::challenge_03();
    set_01::challenge_04();
    set_01::challenge_05();
    set_01::challenge_06_1();
    set_01::challenge_06_2();

    // play_with_xor();

    println!("");
}

fn print_header(set: u64, challenge: f64) {
    print!("Set {set}, challenge {challenge} ...  ")
}

fn play_with_xor() {
    let plain_text = "einawsdlijjjeinalsdkjlkjeinpe;lrfeinasdjo;nein";
    let plain_text_bytes = cryptopals::helpers::unicode_to_bytes(&plain_text);
    let plain_text_hex = cryptopals::helpers::bytes_to_hex(&plain_text_bytes);
    let plain_text_base64 = cryptopals::helpers::unicode_to_base64(&plain_text);

    let key = "ESWAREINMAL";
    let key_bytes = cryptopals::helpers::unicode_to_bytes(&key);

    let bytes_encoded = cryptopals::fixed_xor_bytes(&plain_text_bytes, &key_bytes);
    let string_encoded = cryptopals::helpers::bytes_to_hex(&bytes_encoded);
    let bytes_encoded_base64 = cryptopals::helpers::bytes_to_base64(&bytes_encoded);
    let encoded_text_base64 = cryptopals::helpers::bytes_to_ascii(&bytes_encoded_base64);

    println!("");
    println!("TXT: {plain_text}");
    println!("Hex: {plain_text_hex}");
    println!("B64: {plain_text_base64}\n");

    println!("Key: {key}");

    println!("Hex: {string_encoded}");
    println!("B64: {encoded_text_base64}");
}

pub mod set_01 {
    use std::fs;

    pub fn challenge_01_1() {
        super::print_header(1, 1.1);
        let expected_result = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let string_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let result = cryptopals::helpers::hex_to_base64(string_hex);

        assert_eq!(result, expected_result);

        let string_encoded = expected_result;
        let expected_result_back = string_hex;
        let result_back = cryptopals::helpers::base64_to_hex(&string_encoded);

        assert_eq!(result_back, expected_result_back);
        println!("ok");
    }

    pub fn challenge_01_2() {
        super::print_header(1, 1.2);
        let expected_result =
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29tLi4=";

        let string_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d2e2e";
        let result = cryptopals::helpers::hex_to_base64(string_hex);

        assert_eq!(result, expected_result);

        let string_encoded = expected_result;
        let expected_result_back = string_hex;
        let result_back = cryptopals::helpers::base64_to_hex(&string_encoded);

        assert_eq!(result_back, expected_result_back);
        println!("ok");
    }

    pub fn challenge_01_3() {
        super::print_header(1, 1.3);
        let expected_result = "SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg==";

        let plain_text = "Hi. Servus. Grüezi. 你好.";
        let result = cryptopals::helpers::unicode_to_base64(plain_text);

        assert_eq!(result, expected_result);

        let string_encoded = expected_result;
        let expected_result_back = plain_text;
        let result_back = cryptopals::helpers::base64_to_unicode(&string_encoded);

        assert_eq!(result_back, expected_result_back);
        println!("ok");
    }

    pub fn challenge_02() {
        super::print_header(1, 2.0);
        let expected_result = "746865206b696420646f6e277420706c6179";

        let string_hex_1 = "1c0111001f010100061a024b53535009181c";
        let string_hex_2 = "686974207468652062756c6c277320657965";

        let bytes_xor = cryptopals::fixed_xor_bytes(
            &cryptopals::helpers::hex_to_bytes(string_hex_1),
            &cryptopals::helpers::hex_to_bytes(string_hex_2),
        );

        let result = cryptopals::helpers::bytes_to_hex(&bytes_xor);

        assert_eq!(result, expected_result);
        println!("ok");
    }

    pub fn challenge_03() {
        super::print_header(1, 3.0);
        let expected_result = "Cooking MC's like a pound of bacon";

        let string_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let keys_range_bytes = 0x00..0x80;
        let scores = cryptopals::find_lowest_score_xor_bytes(
            &cryptopals::helpers::hex_to_bytes(&string_hex),
            keys_range_bytes,
        );
        let score = scores.first().expect("there should always be one element");

        let result = cryptopals::helpers::bytes_to_ascii(&score.decoded);

        assert_eq!(result, expected_result);
        println!("ok");
    }

    pub fn challenge_04() {
        super::print_header(1, 4.0);
        let expected_result = "Now that the party is jumping\n";

        let all_strings_hex: String =
            fs::read_to_string("original/4.txt").expect("could not read file");

        let mut best_score = cryptopals::constants::ScoreXOR {
            score: 1000.0,
            key: 0xff,
            decoded: Vec::new(),
        };

        for string_hex in all_strings_hex.lines() {
            let keys_range_bytes = 0x00..0x80;
            let mut scores = cryptopals::find_lowest_score_xor_bytes(
                &cryptopals::helpers::hex_to_bytes(&string_hex),
                keys_range_bytes,
            );
            scores.reverse();
            let score = scores.pop().expect("there should always be one element");

            if score.score < best_score.score {
                best_score = score;
            }
        }

        let result = cryptopals::helpers::bytes_to_ascii(&best_score.decoded);

        assert_eq!(result, expected_result);
        println!("ok");
    }

    pub fn challenge_05() {
        super::print_header(1, 5.0);
        let expected_result = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

        let plain_text =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = "ICE";

        let encoded_bytes = cryptopals::fixed_xor_unicode(&plain_text, &key);
        let result = cryptopals::helpers::bytes_to_hex(&encoded_bytes);

        assert_eq!(result, expected_result);
        println!("ok");
    }

    pub fn challenge_06_1() {
        super::print_header(1, 6.1);
        let expected_result = 37;

        let text_1 = "this is a test";
        let text_2 = "wokka wokka!!!";

        let result = cryptopals::hamming_distance_bits(text_1, text_2);

        assert_eq!(result, expected_result);
        println!("ok");
    }

    pub fn challenge_06_2() {
        super::print_header(1, 6.2);
        println!("???\n");

        let cypher_text_base64: String =
            fs::read_to_string("original/6.txt").expect("could not read file");

        let cypher_text_bytes = cryptopals::helpers::base64_to_bytes(
            &cryptopals::helpers::unicode_to_bytes(&cypher_text_base64),
        );

        let scores = cryptopals::guess_keysize_from_hamming_distance(&cypher_text_bytes);

        println!("[keysizes]");
        for score in scores.get(0..5).unwrap() {
            println!("{}: {}", score.keysize, score.score);
        }
        println!("");

        let xth_score = 0;
        let score = scores.get(xth_score).expect("there should always be a few elements");

        let transposed_vecs = cryptopals::transpose_bytes(&cypher_text_bytes, score.keysize);
        let mut proposed_key = Vec::new();

        for block in 0..transposed_vecs.len() {
            let keys_range_bytes = 0x00..0x80;
            let scores =
                cryptopals::find_lowest_score_xor_bytes(&transposed_vecs[block], keys_range_bytes);

            println!("[block {}/{}]", block + 1, score.keysize);
            for score in scores.get(0..10).unwrap() {
                println!(
                    "{}: {} -> {}",
                    score.key,
                    score.score,
                    cryptopals::helpers::bytes_to_ascii(score.decoded.get(0..30).unwrap())
                );
            }
            println!("");

            let score = scores.first().expect("there should always be one element");
            proposed_key.push(score.key);
        }

        let result_bytes = cryptopals::fixed_xor_bytes(&cypher_text_bytes, &proposed_key);
        let result = cryptopals::helpers::bytes_to_ascii(&result_bytes);
        println!("{result}");

        // assert_eq!(result, expected_result);
    }
}
