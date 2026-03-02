use crate::crypto_vecs;

use std::{fmt, slice};

// ----------------

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlockBytes {
    blocks: Vec<crypto_vecs::Bytes>,
    block_size: usize,
    strict_filling: bool,
}

impl fmt::Display for self::BlockBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let formatted_blocks: Vec<String> = self.iter().map(|x| x.to_string()).collect();

        write!(
            f,
            "BlockBytes[{}{}] {{\n    {}\n}}",
            self.block_size,
            if self.uses_strict_filling() {
                ", strict"
            } else {
                ""
            },
            formatted_blocks.join("\n    ")
        )
    }
}

impl fmt::Debug for self::BlockBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string(),)
    }
}

impl crypto_vecs::ToBytes for self::BlockBytes {
    fn to_bytes(&self) -> crypto_vecs::Bytes {
        self.iter()
            .fold(crypto_vecs::Bytes::new(), |mut acc, block| {
                acc.extend(block.to_vec());
                acc
            })
    }
}

impl self::BlockBytes {
    pub fn new(block_size: usize) -> Self {
        assert!(block_size > 0);

        Self {
            blocks: Vec::new(),
            block_size: block_size,
            strict_filling: true,
        }
    }

    pub fn new_with_lax_filling(block_size: usize) -> Self {
        assert!(block_size > 0);

        Self {
            blocks: Vec::new(),
            block_size: block_size,
            strict_filling: false,
        }
    }

    pub const fn get_block_size(&self) -> usize {
        self.block_size
    }

    pub const fn uses_strict_filling(&self) -> bool {
        self.strict_filling
    }

    // number of blocks
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    // total number of bytes in all blocks
    pub fn len_bytes(&self) -> usize {
        self.iter().fold(0, |acc, buffer| acc + buffer.len())
    }

    // total number of bits in all blocks
    pub fn len_bits(&self) -> usize {
        self.len_bytes() * 8
    }

    // ----------------

    pub fn iter(&self) -> slice::Iter<'_, crypto_vecs::Bytes> {
        self.blocks.iter()
    }

    pub fn iter_mut(&mut self) -> slice::IterMut<'_, crypto_vecs::Bytes> {
        self.blocks.iter_mut()
    }

    pub fn to_vec(&self) -> Vec<crypto_vecs::Bytes> {
        self.blocks.to_vec()
    }

    fn get_last_block(&self) -> &crypto_vecs::Bytes {
        self.iter().last().expect("BlockBytes must not be empty")
    }

    fn get_last_block_mut(&mut self) -> &mut crypto_vecs::Bytes {
        self.iter_mut()
            .last()
            .expect("BlockBytes must not be empty")
    }

    pub fn get_last_block_size(&self) -> usize {
        self.get_last_block().len()
    }

    // ----------------

    pub fn push(&mut self, block: crypto_vecs::Bytes) {
        let block_size = self.get_block_size();

        assert!(
            block.len() <= block_size,
            "block is too big, {} bytes > {} bytes",
            block.len(),
            block_size
        );

        if self.blocks.len() > 0 && self.uses_strict_filling() {
            let last_block_size = self.get_last_block_size();

            assert_eq!(
                last_block_size, block_size,
                "last block is not full, has only {} bytes",
                last_block_size
            );
        }

        self.blocks.push(block);
    }

    fn pop(&mut self) -> Option<crypto_vecs::Bytes> {
        self.blocks.pop()
    }

    pub fn extend_last_block<T>(&mut self, bytes: T)
    where
        T: Into<Vec<u8>>,
    {
        self.get_last_block_mut().extend(bytes.into());

        let block_size = self.get_block_size();
        let last_block_size = self.get_last_block_size();

        assert!(
            last_block_size <= block_size,
            "last block is too big, {} bytes > {} bytes",
            last_block_size,
            block_size
        );
    }

    pub fn drop_from_last_block(&mut self, number_of_bytes: usize) {
        let last_block_size = self.get_last_block_size();

        assert!(
            number_of_bytes < last_block_size,
            "cannot drop {} bytes, has only {} bytes",
            number_of_bytes,
            last_block_size
        );

        let last_block = self.get_last_block_mut();

        *last_block = last_block
            .first_n(last_block_size - number_of_bytes)
            .expect("block length has been asserted above");
    }

    // ----------------

    pub fn sort(&mut self) {
        self.blocks.sort();
    }

    // ----------------

    pub fn find_duplicate_blocks(&self) -> Self {
        let block_size = self.get_block_size();

        assert!(block_size > 0);

        let mut blocks = self.to_vec();
        blocks.sort();

        let current_block_iter = blocks.iter();
        let next_block_iter = current_block_iter.clone().skip(1);

        // compare successive blocks and keep duplicates
        let duplicate_blocks = current_block_iter.zip(next_block_iter).fold(
            Self::new(block_size),
            |mut duplicates, (current_block, next_block)| {
                if current_block == next_block {
                    duplicates.push(current_block.clone());
                }

                duplicates
            },
        );

        duplicate_blocks
    }

    // ----------------

    #[inline]
    fn is_padded_pkcs7_internal(&self) -> Result<usize, usize> {
        let block_size = self.get_block_size();
        let last_block_size = self.get_last_block_size();
        let number_of_missing_bytes = block_size - last_block_size;

        // block is not full
        if last_block_size < block_size {
            return Err(number_of_missing_bytes);
        }

        // get padding length from last byte
        let last_block_vec = self.get_last_block().to_vec();
        let padding_length = *last_block_vec.last().expect("block size is non-zero") as usize;

        // last byte does not designate length of padding
        if padding_length > block_size {
            return Err(number_of_missing_bytes);
        }

        let padding = last_block_vec
            .rchunks(padding_length)
            .next()
            .expect("chunk size is less than block size");
        let padding_is_correct = padding.iter().all(|x| *x == padding_length as u8);

        if padding_is_correct {
            Ok(padding_length)
        } else {
            Err(number_of_missing_bytes)
        }
    }

    pub fn is_padded_pkcs7(&self) -> Result<usize, usize> {
        match self.is_padded_pkcs7_internal() {
            Ok(padding_length) => Ok(padding_length),
            Err(number_of_missing_bytes) => {
                if number_of_missing_bytes == 0 {
                    Err(self.get_block_size())
                } else {
                    Err(number_of_missing_bytes)
                }
            }
        }
    }

    pub fn pad_pkcs7(&self) -> Self {
        match self.is_padded_pkcs7() {
            Ok(_) => self.clone(),
            Err(number_of_missing_bytes) => {
                let block_padding = vec![number_of_missing_bytes as u8; number_of_missing_bytes];
                let mut padded = self.clone();

                if number_of_missing_bytes == self.get_block_size() {
                    let new_block = crypto_vecs::Bytes::from(block_padding);
                    padded.push(new_block);
                } else {
                    padded.extend_last_block(block_padding);
                }

                padded
            }
        }
    }

    pub fn unpad_pkcs7(&self) -> Result<Self, String> {
        match self.is_padded_pkcs7() {
            Ok(padding_length) => {
                let mut unpadded = self.clone();

                if padding_length == self.get_block_size() {
                    unpadded.pop();
                } else {
                    unpadded.drop_from_last_block(padding_length);
                }

                Ok(unpadded)
            }
            Err(_) => Err(String::from("invalid PKCS#7 padding")),
        }
    }

    // ----------------

    pub fn aes_128_ecb_encrypt(&self, key: &crypto_vecs::Bytes) -> Result<Self, String> {
        let mut cypher = self::BlockBytes::new(self.get_block_size());

        let padded_plain = self.pad_pkcs7();

        for plain_block in padded_plain.iter() {
            let cypher_block = plain_block.aes_128_ecb_encrypt_block(key, self.get_block_size())?;

            cypher.push(cypher_block);
        }

        Ok(cypher)
    }

    pub fn aes_128_ecb_decrypt(&self, key: &crypto_vecs::Bytes) -> Result<Self, String> {
        let mut padded_cypher = self::BlockBytes::new(self.get_block_size());

        for block in self.iter() {
            let plain_block = block.aes_128_ecb_decrypt_block(key, self.get_block_size())?;

            padded_cypher.push(plain_block);
        }

        padded_cypher.unpad_pkcs7()
    }
}

// ----------------

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{constants, crypto_vecs::ToBytes};

    #[test]
    fn unit_bytes_find_duplicate_blocks_blocksize_1() {
        let block_size = 1;

        let bytes = crypto_vecs::Bytes::from_hex_literal(
            "3a 1b d4 cb d0 aa 25 f2 66 db b8 fe 16 6e d4 cb 25 f3",
        );
        let block_bytes = bytes.to_blocks(block_size);

        let mut expected_result = self::BlockBytes::new(block_size);
        expected_result.push(crypto_vecs::Bytes::from_hex_literal("25"));
        expected_result.push(crypto_vecs::Bytes::from_hex_literal("cb"));
        expected_result.push(crypto_vecs::Bytes::from_hex_literal("d4"));

        let result = block_bytes.find_duplicate_blocks();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_find_duplicate_blocks_blocksize_2() {
        let block_size = 2;

        let bytes = crypto_vecs::Bytes::from_hex_literal(
            "3a1b 7e49 d4cb d0aa 25f2 66db b8fe 166e d4cb 7e49 db25 d4cb",
        );
        let block_bytes = bytes.to_blocks(block_size);

        let mut expected_result = self::BlockBytes::new(block_size);
        expected_result.push(crypto_vecs::Bytes::from_hex_literal("7e49"));
        expected_result.push(crypto_vecs::Bytes::from_hex_literal("d4cb"));
        expected_result.push(crypto_vecs::Bytes::from_hex_literal("d4cb"));

        let result = block_bytes.find_duplicate_blocks();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_find_duplicate_blocks_blocksize_3() {
        let block_size = 3;

        let bytes = crypto_vecs::Bytes::from_hex_literal(
            "3a1b7e 49d4cb d0aa25 f266db b8fe16 6ed4cb d0aadb 25f266",
        );
        let block_bytes = bytes.to_blocks(block_size);

        let expected_result = self::BlockBytes::new(block_size);

        let result = block_bytes.find_duplicate_blocks();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_find_duplicate_blocks_blocksize_4() {
        let block_size = 4;

        let bytes = crypto_vecs::Bytes::from_hex_literal(
            "3a1b7e49 d4cbd0aa 25f266db 3a1b7e49 d4cbd0aa db25f266",
        );
        let block_bytes = bytes.to_blocks(block_size);

        let mut expected_result = self::BlockBytes::new(block_size);
        expected_result.push(crypto_vecs::Bytes::from_hex_literal("3a1b7e49"));
        expected_result.push(crypto_vecs::Bytes::from_hex_literal("d4cbd0aa"));

        let result = block_bytes.find_duplicate_blocks();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_find_duplicate_blocks_blocksize_4_dangling_end() {
        let block_size = 4;

        let bytes =
            crypto_vecs::Bytes::from_hex_literal("3a1b7e49 d4cbd0aa 25f266db 3a1b7e49 d4cbd0aa db");
        let block_bytes = bytes.to_blocks(block_size);

        let mut expected_result = self::BlockBytes::new(block_size);
        expected_result.push(crypto_vecs::Bytes::from_hex_literal("3a1b7e49"));
        expected_result.push(crypto_vecs::Bytes::from_hex_literal("d4cbd0aa"));

        let result = block_bytes.find_duplicate_blocks();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_find_duplicate_blocks_blocksize_8() {
        let block_size = 8;

        let bytes = crypto_vecs::Bytes::from_hex_literal(
            "3a1b7e49 d4cbd0aa 25f266db 3a1b7e49 d4cbd0aa db25f266",
        );
        let block_bytes = bytes.to_blocks(block_size);

        let expected_result = self::BlockBytes::new(block_size);

        let result = block_bytes.find_duplicate_blocks();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_is_padded_pkcs7_single_block_incomplete() {
        let block_size = 4;
        let blocks = crypto_vecs::Bytes::from_hex_literal("db25f2").to_blocks(block_size);

        let expected_result = Err(1);

        let result = blocks.is_padded_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_is_padded_pkcs7_single_block_unpadded() {
        let block_size = 4;
        let bytes = crypto_vecs::Bytes::from_hex_literal("db25f266").to_blocks(block_size);

        let expected_result = Err(4);

        let result = bytes.is_padded_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_is_padded_pkcs7_single_block_correctly_padded() {
        let block_size = 4;
        let bytes = crypto_vecs::Bytes::from_hex_literal("db250202").to_blocks(block_size);

        let expected_result = Ok(2);

        let result = bytes.is_padded_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_is_padded_pkcs7_single_block_incorrectly_padded() {
        let block_size = 4;
        let bytes = crypto_vecs::Bytes::from_hex_literal("db25ff02").to_blocks(block_size);

        let expected_result = Err(4);

        let result = bytes.is_padded_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_is_padded_pkcs7_two_blocks_incomplete() {
        let block_size = 4;
        let bytes = crypto_vecs::Bytes::from_hex_literal("3a1b7e49 db").to_blocks(block_size);

        let expected_result = Err(3);

        let result = bytes.is_padded_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_pad_pkcs7_single_block() {
        let block_size = 20;
        let unpadded =
            crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE").to_blocks(block_size);

        let expected_result =
            crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE\x04\x04\x04\x04");

        let result = unpadded.pad_pkcs7().to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_pad_pkcs7_two_blocks() {
        let block_size = 6;
        let unpadded =
            crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE").to_blocks(block_size);

        let expected_result = crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE\x02\x02");

        let result = unpadded.pad_pkcs7().to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_pad_pkcs7_full_block_unpadded() {
        let block_size = 8;
        let unpadded =
            crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE").to_blocks(block_size);

        let expected_result = crypto_vecs::Bytes::from_unicode_literal(
            "YELLOW SUBMARINE\x08\x08\x08\x08\x08\x08\x08\x08",
        );

        let result = unpadded.pad_pkcs7().to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_pad_pkcs7_full_block_correctly_padded() {
        let block_size = 8;
        let unpadded =
            crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARIN\x01").to_blocks(block_size);

        let expected_result = crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARIN\x01");

        let result = unpadded.pad_pkcs7().to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_pad_pkcs7_full_block_incorrectly_padded() {
        let block_size = 8;
        let unpadded = crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARI\x01\x02")
            .to_blocks(block_size);

        let expected_result = crypto_vecs::Bytes::from_unicode_literal(
            "YELLOW SUBMARI\x01\x02\x08\x08\x08\x08\x08\x08\x08\x08",
        );

        let result = unpadded.pad_pkcs7().to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_unpad_pkcs7_single_block_four_bytes() {
        let block_size = 20;
        let padded = crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE\x04\x04\x04\x04")
            .to_blocks(block_size);

        let expected_result =
            Ok(crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE").to_blocks(block_size));

        let result = padded.unpad_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_unpad_pkcs7_two_blocks_single_byte() {
        let block_size = 8;
        let padded =
            crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARIN\x01").to_blocks(block_size);

        let expected_result =
            Ok(crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARIN").to_blocks(block_size));

        let result = padded.unpad_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_unpad_pkcs7_two_blocks_padded_two_bytes() {
        let block_size = 6;
        let padded = crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE\x02\x02")
            .to_blocks(block_size);

        let expected_result =
            Ok(crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE").to_blocks(block_size));

        let result = padded.unpad_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_unpad_pkcs7_full_block_padding() {
        let block_size = 8;
        let padded = crypto_vecs::Bytes::from_unicode_literal(
            "YELLOW SUBMARINE\x08\x08\x08\x08\x08\x08\x08\x08",
        )
        .to_blocks(block_size);

        let expected_result =
            Ok(crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE").to_blocks(block_size));

        let result = padded.unpad_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_unpad_pkcs7_no_padding() {
        let block_size = 8;
        let padded =
            crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE").to_blocks(block_size);

        let expected_result = Err(String::from("invalid PKCS#7 padding"));

        let result = padded.unpad_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_unpad_pkcs7_incorrect_padding_wrong_byte() {
        let block_size = 8;
        let padded = crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARI\x01\x02")
            .to_blocks(block_size);

        let expected_result = Err(String::from("invalid PKCS#7 padding"));

        let result = padded.unpad_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_unpad_pkcs7_incorrect_padding_overhanging_bytes() {
        let block_size = 8;
        let padded = crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE\x02\x02")
            .to_blocks(block_size);

        let expected_result = Err(String::from("invalid PKCS#7 padding"));

        let result = padded.unpad_pkcs7();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_aes_128_ecb_encrypt_unpadded() {
        let block_size = 128;

        let plain = crypto_vecs::Bytes::from_unicode_literal(
            "Mary had a little lamb whose fleece was white as snow.",
        )
        .to_blocks(constants::AES_128_BYTES_IN_KEY);
        let key = crypto_vecs::Bytes::from_unicode_literal("Little Test 1234");

        // echo -n "Mary had a little lamb whose fleece was white as snow..." | \
        // openssl enc \
        //     -aes-128-ecb \
        //     -nosalt \
        //     -K "4c6974746c6520546573742031323334" \
        //     -out cypher.hex
        let expected_result = crypto_vecs::Bytes::from_hex_literal(
            "3a1b7e49 d4cbd0aa 25f266db b8fe166e
                 06556a04 f1ba7f64 991d619d e146b609
                 6298d2f8 ef0fceb7 969e88b0 569eb873
                 adc5da56 80f7ecb3 ebbb2030 6b4af841",
        )
        .to_blocks(constants::AES_128_BYTES_IN_KEY);

        let result = plain.aes_128_ecb_encrypt(&key).unwrap();

        assert_eq!(result, expected_result);

        // padding is needed
        assert_ne!(plain.len_bits() % block_size, 0);

        // padding was added
        assert_eq!(result.len_bits() % block_size, 0);
    }

    #[test]
    fn unit_bytes_aes_128_ecb_encrypt_padded() {
        let block_size = 128;

        let plain = crypto_vecs::Bytes::from_unicode_literal(
            "Mary had a little lamb whose fleece was white as snow.\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a",
        ).to_blocks(constants::AES_128_BYTES_IN_KEY);
        let key = crypto_vecs::Bytes::from_unicode_literal("Little Test 1234");

        // echo -n "Mary had a little lamb whose fleece was white as snow..." | \
        // openssl enc \
        //     -aes-128-ecb \
        //     -nosalt \
        //     -K "4c6974746c6520546573742031323334" \
        //     -out cypher.hex
        let expected_result = crypto_vecs::Bytes::from_hex_literal(
            "3a1b7e49 d4cbd0aa 25f266db b8fe166e
                 06556a04 f1ba7f64 991d619d e146b609
                 6298d2f8 ef0fceb7 969e88b0 569eb873
                 adc5da56 80f7ecb3 ebbb2030 6b4af841",
        )
        .to_blocks(constants::AES_128_BYTES_IN_KEY);

        let result = plain.aes_128_ecb_encrypt(&key).unwrap();

        assert_eq!(result, expected_result);

        // padding not needed
        assert_eq!(plain.len_bits() % block_size, 0);

        // padding was added
        assert_eq!(result.len_bits() % block_size, 0);
    }

    #[test]
    fn unit_bytes_aes_128_ecb_decrypt() {
        let cypher = crypto_vecs::Bytes::from_hex_literal(
            "3a1b7e49 d4cbd0aa 25f266db b8fe166e
                 06556a04 f1ba7f64 991d619d e146b609
                 6298d2f8 ef0fceb7 969e88b0 569eb873
                 adc5da56 80f7ecb3 ebbb2030 6b4af841",
        )
        .to_blocks(constants::AES_128_BYTES_IN_KEY);
        let key = crypto_vecs::Bytes::from_unicode_literal("Little Test 1234");

        let expected_result = crypto_vecs::Bytes::from_unicode_literal(
            "Mary had a little lamb whose fleece was white as snow.",
        );

        let result = cypher.aes_128_ecb_decrypt(&key).unwrap().to_bytes();

        assert_eq!(result, expected_result);
    }
}
