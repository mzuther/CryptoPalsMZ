use crate::crypto_vecs;

use std::{fmt, slice};

// ----------------

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlockBytes {
    blocks: Vec<crypto_vecs::Bytes>,
    block_size: usize,
}

impl fmt::Display for self::BlockBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let formatted_blocks: Vec<String> = self.iter().map(|x| x.to_string()).collect();

        write!(
            f,
            "BlockBytes[{}] {{\n    {}\n}}",
            self.block_size,
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
        }
    }

    pub const fn get_block_size(&self) -> usize {
        self.block_size
    }

    pub fn len(&self) -> usize {
        (self.blocks.len() - 1) * self.block_size + self.get_last_block_size()
    }

    // ----------------

    pub fn iter(&self) -> slice::Iter<'_, crypto_vecs::Bytes> {
        self.blocks.iter()
    }

    pub fn iter_mut(&mut self) -> slice::IterMut<'_, crypto_vecs::Bytes> {
        self.blocks.iter_mut()
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
        if self.blocks.len() > 0 {
            assert_eq!(
                self.get_last_block_size(),
                self.get_block_size(),
                "last block is not full, has only {} bytes",
                self.get_last_block_size()
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

        assert!(
            self.get_last_block_size() <= self.get_block_size(),
            "last block is too big, {} bytes > {} bytes",
            self.get_last_block_size(),
            self.get_block_size()
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
                println!("block_padding: {:?}", block_padding);

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
                    println!("last_block_size: {}", unpadded.get_last_block_size());
                    unpadded.drop_from_last_block(padding_length);
                    println!("last_block_size: {}", unpadded.get_last_block_size());
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
        );

        let result = plain.aes_128_ecb_encrypt(&key).unwrap().to_bytes();

        assert_eq!(result, expected_result);

        // padding is needed
        assert_ne!(plain.len() % constants::AES_128_BYTES_IN_KEY, 0);

        // padding was added
        assert_eq!(result.len() % constants::AES_128_BYTES_IN_KEY, 0);
    }

    #[test]
    fn unit_bytes_aes_128_ecb_encrypt_padded() {
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
        );

        let result = plain.aes_128_ecb_encrypt(&key).unwrap().to_bytes();

        assert_eq!(result, expected_result);

        // padding not needed
        assert_eq!(plain.len() % constants::AES_128_BYTES_IN_KEY, 0);

        // padding was added
        assert_eq!(result.len() % constants::AES_128_BYTES_IN_KEY, 0);
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
