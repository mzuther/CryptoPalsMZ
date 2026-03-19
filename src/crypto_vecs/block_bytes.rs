use std::{convert, fmt, iter, slice, vec};

use crate::crypto_vecs::traits::{InternalDataVec, LenBytes, ToBytes};
use crate::crypto_vecs::{self, Bytes, BytesType};

// ================

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlockBytes {
    blocks: Vec<BytesType>,
    block_size: usize,
    strict_filling: bool,
}

// ================

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
        write!(f, "{}", self)
    }
}

// ----------------

// uses lax filling to maximize usefulness
impl convert::From<Vec<BytesType>> for self::BlockBytes {
    fn from(blocks: Vec<BytesType>) -> Self {
        assert!(!blocks.is_empty());

        let block_sizes = blocks.iter().map(|block| block.len_bytes());
        let max_block_size = block_sizes.max().unwrap();

        Self {
            blocks,
            block_size: max_block_size,
            strict_filling: false,
        }
    }
}

impl ToBytes for self::BlockBytes {
    fn to_bytes_raw(&self) -> Bytes {
        self.iter().fold(Default::default(), |mut acc, block| {
            acc.extend(block);
            acc
        })
    }
}

impl LenBytes for self::BlockBytes {
    // total number of bytes in all blocks
    fn len_bytes(&self) -> usize {
        self.iter().fold(0, |acc, buffer| acc + buffer.len_bytes())
    }
}

// ----------------

impl self::BlockBytes {
    pub fn new(block_size: usize) -> Self {
        assert!(block_size > 0);

        Self {
            blocks: Default::default(),
            block_size,
            strict_filling: true,
        }
    }

    pub fn new_bits(block_size_bits: usize) -> Self {
        let bytes = crypto_vecs::bits_to_bytes(block_size_bits);

        Self::new(bytes)
    }

    pub fn new_with_lax_filling(block_size: usize) -> Self {
        assert!(block_size > 0);

        Self {
            blocks: Default::default(),
            block_size,
            strict_filling: false,
        }
    }

    pub fn new_with_lax_filling_bits(block_size_bits: usize) -> Self {
        let bytes = crypto_vecs::bits_to_bytes(block_size_bits);

        Self::new_with_lax_filling(bytes)
    }

    // ----------------

    pub const fn get_block_size(&self) -> usize {
        self.block_size
    }

    pub const fn get_block_size_bits(&self) -> usize {
        self.get_block_size() * 8
    }

    pub const fn uses_strict_filling(&self) -> bool {
        self.strict_filling
    }

    // ----------------

    // number of blocks
    pub fn number_of_blocks(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.number_of_blocks() == 0
    }

    // ----------------

    pub fn iter(&self) -> slice::Iter<'_, BytesType> {
        self.blocks.iter()
    }

    pub fn iter_mut(&mut self) -> slice::IterMut<'_, BytesType> {
        self.blocks.iter_mut()
    }

    pub fn to_vec(&self) -> Vec<BytesType> {
        self.blocks.to_vec()
    }

    fn get_nth_block(&self, n: usize) -> Option<&BytesType> {
        self.blocks.get(n)
    }

    fn get_last_block(&self) -> &BytesType {
        self.iter().last().expect("BlockBytes must not be empty")
    }

    fn get_last_block_mut(&mut self) -> &mut BytesType {
        self.iter_mut()
            .last()
            .expect("BlockBytes must not be empty")
    }

    pub fn get_last_block_size(&self) -> usize {
        self.get_last_block().len_bytes()
    }

    pub fn get_last_block_size_bits(&self) -> usize {
        self.get_last_block_size() * 8
    }

    // ----------------

    pub fn push(&mut self, block: BytesType) {
        let block_size_bytes = self.get_block_size();

        assert!(
            block.len_bytes() <= block_size_bytes,
            "block is too big, {} bytes > {} bytes",
            block.len_bytes(),
            block_size_bytes
        );

        if !self.blocks.is_empty() && self.uses_strict_filling() {
            let last_block_size = self.get_last_block_size();

            assert_eq!(
                last_block_size, block_size_bytes,
                "last block is not full, has only {} bytes",
                last_block_size
            );
        }

        self.blocks.push(block);
    }

    pub fn pop(&mut self) -> Option<BytesType> {
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

    // ----------------

    pub fn take_n_as_collection(&self, length: usize) -> Option<Self> {
        Some(
            self.to_bytes()
                .take_n_as_collection(length)?
                .to_blocks(self.get_block_size()),
        )
    }

    pub fn skip_n_as_collection(&self, length: usize) -> Option<Self> {
        Some(
            self.to_bytes()
                .skip_n_as_collection(length)?
                .to_blocks(self.get_block_size()),
        )
    }

    pub fn rtake_n_as_collection(&mut self, length: usize) -> Option<Self> {
        Some(
            self.to_bytes()
                .rtake_n_as_collection(length)?
                .to_blocks(self.get_block_size()),
        )
    }

    pub fn rskip_n_as_collection(&mut self, length: usize) -> Option<Self> {
        Some(
            self.to_bytes()
                .rskip_n_as_collection(length)?
                .to_blocks(self.get_block_size()),
        )
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
        let next_block_iter = blocks.iter().skip(1);

        // compare successive blocks and keep duplicates
        current_block_iter.zip(next_block_iter).fold(
            Self::new(block_size),
            |mut duplicates, (current_block, next_block)| {
                if current_block == next_block {
                    duplicates.push(current_block.clone());
                }

                duplicates
            },
        )
    }

    pub fn find_changed_blocks(&self, other: &Self) -> Vec<usize> {
        assert_eq!(
            self.get_block_size(),
            other.get_block_size(),
            "block sizes differ: {} and {}",
            self.get_block_size(),
            other.get_block_size()
        );

        let number_of_blocks = self.number_of_blocks().max(other.number_of_blocks());

        (0..number_of_blocks).fold(Vec::default(), |mut acc, index| {
            if self.get_nth_block(index) != other.get_nth_block(index) {
                acc.push(index)
            }

            acc
        })
    }

    // ----------------

    // normalized Hamming distance, averaged by number of calculations
    //
    // 0.0: all bits are identical
    // 1.0: all bits have been inverted
    pub fn hamming_distance_average(&self, number_of_samples: usize) -> f64 {
        assert!(number_of_samples > 0, "at least one sample needed");

        assert!(
            number_of_samples < self.number_of_blocks(),
            "{} blocks needed, found only {}",
            number_of_samples + 1,
            self.number_of_blocks()
        );

        let sum_of_edit_sizes: f64 = self
            .iter()
            .zip(self.iter().skip(1))
            .take(number_of_samples)
            .map(|(current_chunk, next_chunk)| {
                current_chunk.hamming_distance_normalized(next_chunk)
            })
            .sum();

        sum_of_edit_sizes / (number_of_samples as f64)
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
        let padding_length =
            *last_block_vec.last().expect("block size is non-zero") as usize;

        // last byte does not designate length of padding
        if padding_length > block_size {
            return Err(number_of_missing_bytes);
        }

        // incorrect padding, last byte must not be zero
        if padding_length == 0 {
            return Err(0);
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
        assert!(self.uses_strict_filling());

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
        let mut padded = self.clone();

        match self.is_padded_pkcs7() {
            Ok(_) => padded,
            Err(number_of_missing_bytes) => {
                let block_padding =
                    vec![number_of_missing_bytes as u8; number_of_missing_bytes];

                if number_of_missing_bytes == self.get_block_size() {
                    let new_block = BytesType::from(block_padding);
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
                    Ok(unpadded)
                } else {
                    Ok(unpadded
                        .rskip_n_as_collection(padding_length)
                        .expect("validity of padding length checked by match statement"))
                }
            }
            Err(_) => Err(String::from("invalid PKCS#7 padding")),
        }
    }

    // ----------------

    pub fn aes_ecb_encrypt(&self, key: &BytesType) -> Result<Self, String> {
        assert!(self.uses_strict_filling());

        let block_size_bits = self.get_block_size_bits();

        let mut cypher = self::BlockBytes::new_bits(block_size_bits);
        let padded_plain = self.pad_pkcs7();

        for plain_block in padded_plain.iter() {
            let cypher_block = plain_block.aes_ecb_encrypt_block(key, block_size_bits)?;

            cypher.push(cypher_block);
        }

        Ok(cypher)
    }

    pub fn aes_ecb_decrypt(&self, key: &BytesType) -> Result<Self, String> {
        assert!(self.uses_strict_filling());

        let block_size_bits = self.get_block_size_bits();

        let mut padded_cypher = self::BlockBytes::new_bits(block_size_bits);

        for cypher_block in self.iter() {
            let plain_block = cypher_block.aes_ecb_decrypt_block(key, block_size_bits)?;

            padded_cypher.push(plain_block);
        }

        padded_cypher.unpad_pkcs7()
    }

    pub fn aes_cbc_encrypt(
        &self,
        key: &BytesType,
        iv: &BytesType,
    ) -> Result<Self, String> {
        assert!(self.uses_strict_filling());

        let block_size_bits = self.get_block_size_bits();

        assert_eq!(
            iv.len_bits(),
            block_size_bits,
            "IV has {} bits, block has {} bits, ",
            iv.len_bits(),
            block_size_bits,
        );

        let padded_plain = self.pad_pkcs7();

        let mut cypher = self::BlockBytes::new_bits(block_size_bits);
        let mut previous_cypher = iv.clone();

        for plain_block in padded_plain.iter() {
            let plain_block_xor = plain_block.fixed_xor(&previous_cypher);

            let cypher_block =
                plain_block_xor.aes_ecb_encrypt_block(key, block_size_bits)?;
            previous_cypher = cypher_block.clone();

            cypher.push(cypher_block);
        }

        Ok(cypher)
    }

    pub fn aes_cbc_decrypt(
        &self,
        key: &BytesType,
        iv: &BytesType,
    ) -> Result<Self, String> {
        assert!(self.uses_strict_filling());

        let block_size_bits = self.get_block_size_bits();

        assert_eq!(
            iv.len_bits(),
            block_size_bits,
            "IV has {} bits, block has {} bits, ",
            iv.len_bits(),
            block_size_bits,
        );

        let mut padded_cypher = self::BlockBytes::new_bits(block_size_bits);

        let cypher_iter = self.iter();
        let previous_cypher_iter = iter::once(iv).chain(self.iter());

        for (cypher_block, previous_cypher_block) in cypher_iter.zip(previous_cypher_iter)
        {
            let plain_block_xor =
                cypher_block.aes_ecb_decrypt_block(key, block_size_bits)?;
            let plain_block = plain_block_xor.fixed_xor(previous_cypher_block);

            padded_cypher.push(plain_block);
        }

        padded_cypher.unpad_pkcs7()
    }
}

// ================

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------

    #[test]
    fn unit_blockbytes_new_strict() {
        let block_size = 123;
        let block_size_bits = block_size * 8;

        let result = self::BlockBytes::new(block_size);

        assert_eq!(result.get_block_size(), block_size);
        assert_eq!(result.get_block_size_bits(), block_size_bits);
        assert_eq!(result.uses_strict_filling(), true);
    }

    #[test]
    fn unit_blockbytes_new_lax() {
        let block_size = 321;
        let block_size_bits = block_size * 8;

        let result = self::BlockBytes::new_with_lax_filling(block_size);

        assert_eq!(result.get_block_size(), block_size);
        assert_eq!(result.get_block_size_bits(), block_size_bits);
        assert_eq!(result.uses_strict_filling(), false);
    }

    #[test]
    fn unit_blockbytes_new_bits_strict() {
        let block_size = 13;
        let block_size_bits = block_size * 8;

        let result = self::BlockBytes::new_bits(block_size_bits);

        assert_eq!(result.get_block_size(), block_size);
        assert_eq!(result.get_block_size_bits(), block_size_bits);
        assert_eq!(result.uses_strict_filling(), true);
    }

    #[test]
    fn unit_blockbytes_new_bits_lax() {
        let block_size = 42;
        let block_size_bits = block_size * 8;

        let result = self::BlockBytes::new_with_lax_filling_bits(block_size_bits);

        assert_eq!(result.get_block_size(), block_size);
        assert_eq!(result.get_block_size_bits(), block_size_bits);
        assert_eq!(result.uses_strict_filling(), false);
    }

    // ----------------

    #[test]
    fn unit_blockbytes_number_of_blocks_single_block() {
        let block_size = 7;
        let result = BytesType::from_hex_literal("4162f3d3 426f12").to_blocks(block_size);

        assert_eq!(result.number_of_blocks(), 1);
        assert_eq!(result.len_bytes(), 7);
    }

    #[test]
    fn unit_blockbytes_len_two_blocks() {
        let block_size = 6;
        let result =
            BytesType::from_hex_literal("4162f3d3 426f120d ff").to_blocks(block_size);

        assert_eq!(result.number_of_blocks(), 2);
        assert_eq!(result.len_bytes(), 9);
    }

    // ----------------

    #[test]
    fn unit_blockbytes_find_duplicate_blocks_blocksize_1() {
        let block_size = 1;

        let bytes = BytesType::from_hex_literal(
            "3a 1b d4 cb d0 aa 25 f2 66 db b8 fe 16 6e d4 cb 25 f3",
        );
        let block_bytes = bytes.to_blocks(block_size);

        let mut expected_result = self::BlockBytes::new(block_size);
        expected_result.push(BytesType::from_hex_literal("25"));
        expected_result.push(BytesType::from_hex_literal("cb"));
        expected_result.push(BytesType::from_hex_literal("d4"));

        let result = block_bytes.find_duplicate_blocks();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_find_duplicate_blocks_blocksize_2() {
        let block_size = 2;

        let bytes = BytesType::from_hex_literal(
            "3a1b 7e49 d4cb d0aa 25f2 66db b8fe 166e d4cb 7e49 db25 d4cb",
        );
        let block_bytes = bytes.to_blocks(block_size);

        let mut expected_result = self::BlockBytes::new(block_size);
        expected_result.push(BytesType::from_hex_literal("7e49"));
        expected_result.push(BytesType::from_hex_literal("d4cb"));
        expected_result.push(BytesType::from_hex_literal("d4cb"));

        let result = block_bytes.find_duplicate_blocks();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_find_duplicate_blocks_blocksize_3() {
        let block_size = 3;

        let bytes = BytesType::from_hex_literal(
            "3a1b7e 49d4cb d0aa25 f266db b8fe16 6ed4cb d0aadb 25f266",
        );
        let block_bytes = bytes.to_blocks(block_size);

        let expected_result = self::BlockBytes::new(block_size);

        let result = block_bytes.find_duplicate_blocks();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_find_duplicate_blocks_blocksize_4() {
        let block_size = 4;

        let bytes = BytesType::from_hex_literal(
            "3a1b7e49 d4cbd0aa 25f266db 3a1b7e49 d4cbd0aa db25f266",
        );
        let block_bytes = bytes.to_blocks(block_size);

        let mut expected_result = self::BlockBytes::new(block_size);
        expected_result.push(BytesType::from_hex_literal("3a1b7e49"));
        expected_result.push(BytesType::from_hex_literal("d4cbd0aa"));

        let result = block_bytes.find_duplicate_blocks();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_find_duplicate_blocks_blocksize_4_dangling_end() {
        let block_size = 4;

        let bytes = BytesType::from_hex_literal(
            "3a1b7e49 d4cbd0aa 25f266db 3a1b7e49 d4cbd0aa db",
        );
        let block_bytes = bytes.to_blocks(block_size);

        let mut expected_result = self::BlockBytes::new(block_size);
        expected_result.push(BytesType::from_hex_literal("3a1b7e49"));
        expected_result.push(BytesType::from_hex_literal("d4cbd0aa"));

        let result = block_bytes.find_duplicate_blocks();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_find_duplicate_blocks_blocksize_8() {
        let block_size = 8;

        let bytes = BytesType::from_hex_literal(
            "3a1b7e49 d4cbd0aa 25f266db 3a1b7e49 d4cbd0aa db25f266",
        );
        let block_bytes = bytes.to_blocks(block_size);

        let expected_result = self::BlockBytes::new(block_size);

        let result = block_bytes.find_duplicate_blocks();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_blockbytes_find_changed_blocks() {
        let block_size = 4;

        let block_bytes =
            BytesType::from_hex_literal("3a1b7e49 d4cbd0aa 25f266db 3a1b7e49")
                .to_blocks(block_size);
        let block_other =
            BytesType::from_hex_literal("00000000 d4cbd0aa ffffffff 3a1b7e49")
                .to_blocks(block_size);

        let expected_result = vec![0, 2];

        let result = block_bytes.find_changed_blocks(&block_other);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_find_changed_blocks_identical() {
        let block_size = 4;

        let block_bytes =
            BytesType::from_hex_literal("3a1b7e49 d4cbd0aa 25f266db 3a1b7e49")
                .to_blocks(block_size);
        let block_other =
            BytesType::from_hex_literal("3a1b7e49 d4cbd0aa 25f266db 3a1b7e49")
                .to_blocks(block_size);

        let expected_result = Vec::<usize>::default();

        let result = block_bytes.find_changed_blocks(&block_other);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_find_changed_blocks_empty() {
        let block_size = 4;

        let block_bytes = BytesType::default().to_blocks(block_size);
        let block_other = BytesType::default().to_blocks(block_size);

        let expected_result = Vec::<usize>::default();

        let result = block_bytes.find_changed_blocks(&block_other);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_find_changed_blocks_missing_bytes() {
        let block_size = 4;

        let block_bytes =
            BytesType::from_hex_literal("3a1b7e49 d4cbd0aa 25f266db 3a1b7e49")
                .to_blocks(block_size);
        let block_other = BytesType::from_hex_literal("3a1b7e49 d4cbd0aa 25f266db 3a1b")
            .to_blocks(block_size);

        let expected_result = vec![3];

        let result = block_bytes.find_changed_blocks(&block_other);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_find_changed_blocks_longer() {
        let block_size = 4;

        let block_bytes =
            BytesType::from_hex_literal("3a1b7e49 d4cbd0aa 25f266db 3a1b7e49")
                .to_blocks(block_size);
        let block_other =
            BytesType::from_hex_literal("3a1b7e49 d4cbd0aa").to_blocks(block_size);

        let expected_result = vec![2, 3];

        let result = block_bytes.find_changed_blocks(&block_other);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_find_changed_blocks_shorter() {
        let block_size = 4;

        let block_bytes = BytesType::from_hex_literal("3a1b7e49 d4cbd0aa 25f266db")
            .to_blocks(block_size);
        let block_other =
            BytesType::from_hex_literal("3a1b7e49 d4cbd0aa 25f266db 3a1b7e49")
                .to_blocks(block_size);

        let expected_result = vec![3];

        let result = block_bytes.find_changed_blocks(&block_other);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    #[should_panic(expected = "at least one sample needed")]
    fn unit_blockbytes_hamming_distance_no_samples() {
        let block_size = 5;
        let number_of_samples = 0;

        let bytes = BytesType::from_hex_literal("1d421f4d0b 0f021f4f13 4e3f78120a");
        let block_bytes = bytes.to_blocks(block_size);

        let _ = block_bytes.hamming_distance_average(number_of_samples);
    }

    #[test]
    fn unit_blockbytes_hamming_distance_one_sample() {
        let block_size = 5;
        let number_of_samples = 1;

        let bytes = BytesType::from_hex_literal("1d421f4d0b 0f021f4f13 4e3f78120a");
        let block_bytes = bytes.to_blocks(block_size);

        let expected_result = 0.15;

        let result = block_bytes.hamming_distance_average(number_of_samples);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_hamming_distance_two_samples() {
        let block_size = 5;
        let number_of_samples = 2;

        let bytes = BytesType::from_hex_literal("1d421f4d0b 0f021f4f13 4e3f78120a");
        let block_bytes = bytes.to_blocks(block_size);

        let expected_result = 0.325;

        let result = block_bytes.hamming_distance_average(number_of_samples);

        assert_eq!(result, expected_result);
    }

    #[test]
    #[should_panic(expected = "4 blocks needed, found only 3")]
    fn unit_blockbytes_hamming_distance_not_enough_blocks() {
        let block_size = 5;
        let number_of_samples = 3;

        let bytes = BytesType::from_hex_literal("1d421f4d0b 0f021f4f13 4e3f78120a");
        let block_bytes = bytes.to_blocks(block_size);

        let _ = block_bytes.hamming_distance_average(number_of_samples);
    }

    #[test]
    #[should_panic(expected = "size of blocks not equal")]
    fn unit_blockbytes_hamming_distance_unequal_size() {
        let block_size = 6;
        let number_of_samples = 2;

        let bytes = BytesType::from_hex_literal("1d421f4d0b 0f021f4f13 4e3f78120a");
        let block_bytes = bytes.to_blocks(block_size);

        let _ = block_bytes.hamming_distance_average(number_of_samples);
    }

    // ----------------

    #[test]
    fn unit_blockbytes_is_padded_pkcs7_single_block_incomplete() {
        let block_size = 4;
        let blocks = BytesType::from_hex_literal("db25f2").to_blocks(block_size);

        let expected_result = Err(1);

        let result = blocks.is_padded_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_is_padded_pkcs7_single_block_unpadded() {
        let block_size = 4;
        let bytes = BytesType::from_hex_literal("db25f266").to_blocks(block_size);

        let expected_result = Err(4);

        let result = bytes.is_padded_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_is_padded_pkcs7_single_block_correctly_padded() {
        let block_size = 4;
        let bytes = BytesType::from_hex_literal("db250202").to_blocks(block_size);

        let expected_result = Ok(2);

        let result = bytes.is_padded_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_is_padded_pkcs7_single_block_incorrectly_padded() {
        let block_size = 4;
        let bytes = BytesType::from_hex_literal("db25ff02").to_blocks(block_size);

        let expected_result = Err(4);

        let result = bytes.is_padded_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_is_padded_pkcs7_two_blocks_incomplete() {
        let block_size = 4;
        let bytes = BytesType::from_hex_literal("3a1b7e49 db").to_blocks(block_size);

        let expected_result = Err(3);

        let result = bytes.is_padded_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_pad_pkcs7_single_block() {
        let block_size = 20;
        let unpadded =
            BytesType::from_unicode_literal("YELLOW SUBMARINE").to_blocks(block_size);

        let expected_result =
            BytesType::from_unicode_literal("YELLOW SUBMARINE\x04\x04\x04\x04");

        let result = unpadded.pad_pkcs7().to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_pad_pkcs7_two_blocks() {
        let block_size = 6;
        let unpadded =
            BytesType::from_unicode_literal("YELLOW SUBMARINE").to_blocks(block_size);

        let expected_result = BytesType::from_unicode_literal("YELLOW SUBMARINE\x02\x02");

        let result = unpadded.pad_pkcs7().to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_pad_pkcs7_full_block_unpadded() {
        let block_size = 8;
        let unpadded =
            BytesType::from_unicode_literal("YELLOW SUBMARINE").to_blocks(block_size);

        let expected_result = BytesType::from_unicode_literal(
            "YELLOW SUBMARINE\x08\x08\x08\x08\x08\x08\x08\x08",
        );

        let result = unpadded.pad_pkcs7().to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_pad_pkcs7_full_block_correctly_padded() {
        let block_size = 8;
        let unpadded =
            BytesType::from_unicode_literal("YELLOW SUBMARIN\x01").to_blocks(block_size);

        let expected_result = BytesType::from_unicode_literal("YELLOW SUBMARIN\x01");

        let result = unpadded.pad_pkcs7().to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_pad_pkcs7_full_block_incorrectly_padded() {
        let block_size = 8;
        let unpadded = BytesType::from_unicode_literal("YELLOW SUBMARI\x01\x02")
            .to_blocks(block_size);

        let expected_result = BytesType::from_unicode_literal(
            "YELLOW SUBMARI\x01\x02\x08\x08\x08\x08\x08\x08\x08\x08",
        );

        let result = unpadded.pad_pkcs7().to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_unpad_pkcs7_single_block_four_bytes() {
        let block_size = 20;
        let padded = BytesType::from_unicode_literal("YELLOW SUBMARINE\x04\x04\x04\x04")
            .to_blocks(block_size);

        let expected_result =
            Ok(BytesType::from_unicode_literal("YELLOW SUBMARINE").to_blocks(block_size));

        let result = padded.unpad_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_unpad_pkcs7_two_blocks_single_byte() {
        let block_size = 8;
        let padded =
            BytesType::from_unicode_literal("YELLOW SUBMARIN\x01").to_blocks(block_size);

        let expected_result =
            Ok(BytesType::from_unicode_literal("YELLOW SUBMARIN").to_blocks(block_size));

        let result = padded.unpad_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_unpad_pkcs7_two_blocks_padded_two_bytes() {
        let block_size = 6;
        let padded = BytesType::from_unicode_literal("YELLOW SUBMARINE\x02\x02")
            .to_blocks(block_size);

        let expected_result =
            Ok(BytesType::from_unicode_literal("YELLOW SUBMARINE").to_blocks(block_size));

        let result = padded.unpad_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_unpad_pkcs7_full_block_padding() {
        let block_size = 8;
        let padded = BytesType::from_unicode_literal(
            "YELLOW SUBMARINE\x08\x08\x08\x08\x08\x08\x08\x08",
        )
        .to_blocks(block_size);

        let expected_result =
            Ok(BytesType::from_unicode_literal("YELLOW SUBMARINE").to_blocks(block_size));

        let result = padded.unpad_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_unpad_pkcs7_no_padding() {
        let block_size = 8;
        let padded =
            BytesType::from_unicode_literal("YELLOW SUBMARINE").to_blocks(block_size);

        let expected_result = Err(String::from("invalid PKCS#7 padding"));

        let result = padded.unpad_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_unpad_pkcs7_incorrect_padding_wrong_byte() {
        let block_size = 8;
        let padded = BytesType::from_unicode_literal("YELLOW SUBMARI\x01\x02")
            .to_blocks(block_size);

        let expected_result = Err(String::from("invalid PKCS#7 padding"));

        let result = padded.unpad_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_unpad_pkcs7_incorrect_padding_zero_at_end() {
        let block_size = 8;
        let padded =
            BytesType::from_unicode_literal("YELLOW SUBMARIN\x00").to_blocks(block_size);

        let expected_result = Err(String::from("invalid PKCS#7 padding"));

        let result = padded.unpad_pkcs7();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_unpad_pkcs7_incorrect_padding_overhanging_bytes() {
        let block_size = 8;
        let padded = BytesType::from_unicode_literal("YELLOW SUBMARINE\x02\x02")
            .to_blocks(block_size);

        let expected_result = Err(String::from("invalid PKCS#7 padding"));

        let result = padded.unpad_pkcs7();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_blockbytes_aes_128_ecb_encrypt_unpadded() {
        let block_size_bits = 128;

        let plain = BytesType::from_unicode_literal(
            "Mary had a little lamb whose fleece was white as snow.",
        )
        .to_blocks_bits(block_size_bits);
        let key = BytesType::from_unicode_literal("Little Test 1234");

        // echo -n "Mary had a little lamb whose fleece was white as snow." | \
        // openssl enc \
        //     -aes-128-ecb \
        //     -nosalt \
        //     -K "4c6974746c6520546573742031323334" \
        //     -out cypher.hex
        let expected_result = BytesType::from_hex_literal(
            "3a1b7e49 d4cbd0aa 25f266db b8fe166e
                 06556a04 f1ba7f64 991d619d e146b609
                 6298d2f8 ef0fceb7 969e88b0 569eb873
                 adc5da56 80f7ecb3 ebbb2030 6b4af841",
        )
        .to_blocks_bits(block_size_bits);

        let result = plain.aes_ecb_encrypt(&key).unwrap();

        assert_eq!(result, expected_result);

        // padding is needed
        assert_ne!(plain.len_bits() % block_size_bits, 0);

        // padding was added
        assert_eq!(result.len_bits() % block_size_bits, 0);
    }

    #[test]
    fn unit_blockbytes_aes_128_ecb_encrypt_padded() {
        let block_size_bits = 128;

        let plain = BytesType::from_unicode_literal(
            "Mary had a little lamb whose fleece was white as snow.\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a",
        ).to_blocks_bits(block_size_bits);
        let key = BytesType::from_unicode_literal("Little Test 1234");

        let expected_result = BytesType::from_hex_literal(
            "3a1b7e49 d4cbd0aa 25f266db b8fe166e
                 06556a04 f1ba7f64 991d619d e146b609
                 6298d2f8 ef0fceb7 969e88b0 569eb873
                 adc5da56 80f7ecb3 ebbb2030 6b4af841",
        )
        .to_blocks_bits(128);

        let result = plain.aes_ecb_encrypt(&key).unwrap();

        assert_eq!(result, expected_result);

        // padding not needed
        assert_eq!(plain.len_bits() % block_size_bits, 0);

        // padding was added
        assert_eq!(result.len_bits() % block_size_bits, 0);
    }

    #[test]
    fn unit_blockbytes_aes_128_ecb_decrypt() {
        let block_size_bits = 128;

        let cypher = BytesType::from_hex_literal(
            "3a1b7e49 d4cbd0aa 25f266db b8fe166e
                 06556a04 f1ba7f64 991d619d e146b609
                 6298d2f8 ef0fceb7 969e88b0 569eb873
                 adc5da56 80f7ecb3 ebbb2030 6b4af841",
        )
        .to_blocks_bits(block_size_bits);
        let key = BytesType::from_unicode_literal("Little Test 1234");

        let expected_result = BytesType::from_unicode_literal(
            "Mary had a little lamb whose fleece was white as snow.",
        );

        let result = cypher.aes_ecb_decrypt(&key).unwrap().to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_blockbytes_aes_128_cbc_encrypt_unpadded() {
        let block_size_bits = 128;

        let plain = BytesType::from_unicode_literal(
            "Mary had a little lamb whose fleece was white as snow.",
        )
        .to_blocks_bits(block_size_bits);
        let key = BytesType::from_unicode_literal("Little Test 1234");
        let iv = BytesType::from_hex_literal("0fcd542b efac4a80 0a1cbf2e 87ccabfe");

        // echo -n "Mary had a little lamb whose fleece was white as snow." | \
        // openssl enc \
        //     -aes-128-cbc \
        //     -nosalt \
        //     -K "4c6974746c6520546573742031323334" \
        //     -iv "0fcd542befac4a800a1cbf2e87ccabfe" \
        //     -out cypher.hex
        let expected_result = BytesType::from_hex_literal(
            "0a893579 c5a2475b bbb0df78 fb26026c
                 e787e9bd 050f3af2 f43df9cf 3b864a23
                 100ed7dc 1d39c623 5ae5aba4 0a515932
                 128e050c 80c74856 e0aa6510 3f7811d2",
        )
        .to_blocks_bits(block_size_bits);

        let result = plain.aes_cbc_encrypt(&key, &iv).unwrap();

        assert_eq!(result, expected_result);

        // padding is needed
        assert_ne!(plain.len_bits() % block_size_bits, 0);

        // padding was added
        assert_eq!(result.len_bits() % block_size_bits, 0);
    }

    #[test]
    fn unit_blockbytes_aes_128_cbc_encrypt_padded() {
        let block_size_bits = 128;

        let plain = BytesType::from_unicode_literal(
            "Mary had a little lamb whose fleece was white as snow.\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a",
        ).to_blocks_bits(block_size_bits);
        let key = BytesType::from_unicode_literal("Little Test 1234");
        let iv = BytesType::from_hex_literal("0fcd542b efac4a80 0a1cbf2e 87ccabfe");

        let expected_result = BytesType::from_hex_literal(
            "0a893579 c5a2475b bbb0df78 fb26026c
                 e787e9bd 050f3af2 f43df9cf 3b864a23
                 100ed7dc 1d39c623 5ae5aba4 0a515932
                 128e050c 80c74856 e0aa6510 3f7811d2",
        )
        .to_blocks_bits(128);

        let result = plain.aes_cbc_encrypt(&key, &iv).unwrap();

        assert_eq!(result, expected_result);

        // padding not needed
        assert_eq!(plain.len_bits() % block_size_bits, 0);

        // padding was added
        assert_eq!(result.len_bits() % block_size_bits, 0);
    }

    #[test]
    fn unit_blockbytes_aes_128_cbc_decrypt() {
        let block_size_bits = 128;

        let cypher = BytesType::from_hex_literal(
            "0a893579 c5a2475b bbb0df78 fb26026c
                 e787e9bd 050f3af2 f43df9cf 3b864a23
                 100ed7dc 1d39c623 5ae5aba4 0a515932
                 128e050c 80c74856 e0aa6510 3f7811d2",
        )
        .to_blocks_bits(block_size_bits);
        let key = BytesType::from_unicode_literal("Little Test 1234");
        let iv = BytesType::from_hex_literal("0fcd542b efac4a80 0a1cbf2e 87ccabfe");

        let expected_result = BytesType::from_unicode_literal(
            "Mary had a little lamb whose fleece was white as snow.",
        );

        let result = cypher.aes_cbc_decrypt(&key, &iv).unwrap().to_bytes();
        println!("|{}|", result.to_unicode());

        assert_eq!(result, expected_result);
    }
}
