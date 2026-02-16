#![allow(unused)]

use cryptopals;

fn main() {
    println!("\n[Cryptopals]\n");

    set_01::challenge_01();
    set_01::challenge_02();
    set_01::challenge_03();
    set_01::challenge_04();
    set_01::challenge_05();
    set_01::challenge_06_1();

    println!("");
}

fn print_header(set: u64, challenge: f64) {
    print!("Set {set}, challenge {challenge} ...  ")
}

pub mod set_01 {
    use std::fs;

    pub fn challenge_01() {
        super::print_header(1, 1.0);
        let expected_result = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let string_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let result = cryptopals::helpers::string_to_base64(string_hex, true);

        assert_eq!(result, expected_result);
        println!("ok");
    }

    pub fn challenge_02() {
        super::print_header(1, 2.0);
        let expected_result = "746865206b696420646f6e277420706c6179";

        let string_hex_1 = "1c0111001f010100061a024b53535009181c";
        let string_hex_2 = "686974207468652062756c6c277320657965";

        let bytes_xor = cryptopals::fixed_xor(
            &cryptopals::helpers::string_to_bytes(string_hex_1, true),
            &cryptopals::helpers::string_to_bytes(string_hex_2, true),
        );

        let result = cryptopals::helpers::bytes_to_string(&bytes_xor, true);

        assert_eq!(result, expected_result);
        println!("ok");
    }

    pub fn challenge_03() {
        super::print_header(1, 3.0);
        let expected_result = "Cooking MC's like a pound of bacon";

        let string_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let (_, _, result) = cryptopals::find_lowest_score_xor(string_hex, 0x00..0x80);

        assert_eq!(result, expected_result);
        println!("ok");
    }

    pub fn challenge_04() {
        super::print_header(1, 4.0);
        let expected_result = "Now that the party is jumping\n";

        let all_strings_hex: String =
            fs::read_to_string("original/4.txt").expect("could not read file");

        let mut best_score = 1000.0;
        let mut best_result = String::new();

        for string_hex in all_strings_hex.lines() {
            let (_, score, result) = cryptopals::find_lowest_score_xor(string_hex, 0x00..0x80);

            if score < best_score {
                best_score = score;
                best_result = result;
            }
        }

        assert_eq!(best_result, expected_result);
        println!("ok");
    }

    pub fn challenge_05() {
        super::print_header(1, 5.0);
        let expected_result = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

        let plain_text =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = "ICE";

        let result = cryptopals::repeating_key_xor(&plain_text, &key);

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
}
