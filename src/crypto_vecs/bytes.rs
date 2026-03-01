use crate::{
    constants,
    crypto_vecs::{self, ToBytes},
};

use openssl::{cipher, cipher_ctx, error};
use std::{convert, fmt, slice, vec};

// ----------------

const LOOKUP_BITS_IN_NIBBLE: [u32; 16] = [0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4];

// ----------------

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct Bytes {
    bytes: Vec<u8>,
}

impl fmt::Display for self::Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Bytes[{}] {{ {} }}",
            self.len(),
            self.to_hexadecimal().get_representation()
        )
    }
}

impl fmt::Debug for self::Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Bytes[{}] {{ {} }}",
            self.len(),
            self.to_hexadecimal().get_representation()
        )
    }
}

impl convert::From<Vec<u8>> for self::Bytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes: bytes }
    }
}

impl convert::From<&[u8]> for self::Bytes {
    fn from(bytes: &[u8]) -> Self {
        Self::from(bytes.to_vec())
    }
}

impl convert::From<u8> for self::Bytes {
    fn from(byte: u8) -> Self {
        Self::from(vec![byte])
    }
}

impl crypto_vecs::ToBytes for self::Bytes {
    // performance: prevent superfluous conversion to Bytes
    fn to_bytes(&self) -> Self {
        self.clone()
    }

    // performance: prevent intermediate conversion to Bytes
    fn to_hexadecimal(&self) -> crypto_vecs::Hexadecimal {
        crypto_vecs::Hexadecimal::from(self)
    }

    // performance: prevent intermediate conversion to Bytes
    fn to_base64(&self) -> crypto_vecs::Base64 {
        crypto_vecs::Base64::from(self)
    }

    // performance: prevent intermediate conversion to Bytes
    fn to_unicode(&self) -> crypto_vecs::Unicode {
        crypto_vecs::Unicode::from(self)
    }
}

impl IntoIterator for self::Bytes {
    type Item = u8;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.bytes.into_iter()
    }
}

impl AsMut<Vec<u8>> for self::Bytes {
    // reference to mutable vec
    fn as_mut(&mut self) -> &mut Vec<u8> {
        self.bytes.as_mut()
    }
}

impl AsRef<Vec<u8>> for self::Bytes {
    // reference to vec
    fn as_ref(&self) -> &Vec<u8> {
        self.bytes.as_ref()
    }
}

impl self::Bytes {
    pub fn new() -> Self {
        Self::from(Vec::new())
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self::from(Vec::with_capacity(capacity))
    }

    pub const fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    // ----------------

    pub fn from_hex_literal(string_literal: &str) -> Self {
        let hexadecimal = crypto_vecs::Hexadecimal::from(string_literal);

        hexadecimal.to_bytes()
    }

    pub fn from_base64_literal(string_literal: &str) -> Self {
        let base64 = crypto_vecs::Base64::from(string_literal);

        base64.to_bytes()
    }

    pub fn from_unicode_literal(string_literal: &str) -> Self {
        let unicode = crypto_vecs::Unicode::from(string_literal);

        unicode.to_bytes()
    }

    // ----------------

    pub fn iter(&self) -> slice::Iter<'_, u8> {
        self.bytes.iter()
    }

    pub fn chunks(&self, chunk_size: usize) -> Vec<Self> {
        assert!(chunk_size > 0, "chunk size must be non-zero");

        self.bytes
            .chunks(chunk_size)
            .fold(Vec::new(), |mut acc, chunk| {
                acc.push(Self::from(chunk));
                acc
            })
    }

    pub fn rchunks(&self, chunk_size: usize) -> Vec<Self> {
        assert!(chunk_size > 0, "chunk size must be non-zero");

        self.bytes
            .rchunks(chunk_size)
            .fold(Vec::new(), |mut acc, chunk| {
                acc.push(Self::from(chunk));
                acc
            })
    }

    // reference to array
    pub const fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    // reference to mutable array
    pub const fn as_mut_slice(&mut self) -> &mut [u8] {
        self.bytes.as_mut_slice()
    }

    // clone of underlying vec
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    pub fn to_iso_8859_1(&self) -> String {
        self.iter()
            .fold(String::new(), |acc, &byte| format!("{acc}{}", byte as char))
    }

    // ----------------

    pub fn first_n(&self, length: usize) -> Option<Self> {
        assert!(length > 0);

        self.chunks(length).get(0).cloned()
    }

    pub fn last_n(&self, length: usize) -> Option<Self> {
        assert!(length > 0);

        self.rchunks(length).get(0).cloned()
    }

    // ----------------

    pub fn push(&mut self, byte: u8) {
        self.bytes.push(byte);
    }

    pub fn extend<T>(&mut self, bytes: T)
    where
        T: Into<Vec<u8>>,
    {
        self.bytes.extend(bytes.into());
    }

    // ----------------

    pub fn fixed_xor(&self, key: &Self) -> Self {
        assert!(key.len() > 0);

        let mut bytes_key_endless = key.iter().cycle();

        self.iter().fold(Self::new(), |mut acc, &byte_plain| {
            let byte_key = bytes_key_endless
                .next()
                .expect("infinite key was finite after all");

            acc.push((byte_plain | byte_key) & !(byte_plain & byte_key));
            acc
        })
    }

    pub fn hamming_distance(&self, other: &Self) -> u32 {
        let bytes_with_differing_bits = self.fixed_xor(&other);

        bytes_with_differing_bits.iter().fold(0, |acc, &byte| {
            let nibble_value_low = byte & 0x0f;
            let nibble_value_high = byte >> 4;

            let differing_bits_low = LOOKUP_BITS_IN_NIBBLE
                .get(nibble_value_low as usize)
                .expect("index must be between 0 and 15")
                .clone();

            let differing_bits_high = LOOKUP_BITS_IN_NIBBLE
                .get(nibble_value_high as usize)
                .expect("index must be between 0 and 15")
                .clone();

            acc + differing_bits_low + differing_bits_high
        })
    }

    // ----------------

    #[inline]
    fn is_padded_pkcs7_internal(&self, block_size: usize) -> Result<usize, usize> {
        assert!(block_size > 0);

        let all_blocks = self.chunks(block_size);
        let last_block = all_blocks.last().expect("block size is non-zero");
        let number_of_missing_bytes = block_size - last_block.len();

        // block is not full
        if last_block.len() < block_size {
            return Err(number_of_missing_bytes);
        }

        // get padding length from last byte
        let last_block_vec = last_block.to_vec();
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

    pub fn is_padded_pkcs7(&self, block_size: usize) -> Result<usize, usize> {
        match self.is_padded_pkcs7_internal(block_size) {
            Ok(padding_length) => Ok(padding_length),
            Err(number_of_missing_bytes) => {
                if number_of_missing_bytes == 0 {
                    Err(block_size)
                } else {
                    Err(number_of_missing_bytes)
                }
            }
        }
    }

    pub fn pad_pkcs7(&self, block_size: usize) -> Self {
        match self.is_padded_pkcs7(block_size) {
            Ok(_) => self.clone(),
            Err(number_of_missing_bytes) => {
                let block_padding = vec![number_of_missing_bytes as u8; number_of_missing_bytes];

                let mut padded = self.clone();
                padded.extend(block_padding);
                padded
            }
        }
    }

    pub fn unpad_pkcs7(&self, block_size: usize) -> Result<Self, &str> {
        match self.is_padded_pkcs7(block_size) {
            Ok(padding_length) => Ok(self
                .first_n(self.len() - padding_length)
                .expect("block length has been asserted in is_padded_pkcs7_internal()")),
            Err(_) => Err("invalid PKCS#7 padding"),
        }
    }

    pub fn aes_128_ecb_encrypt(&self, key: &Self) -> Result<Self, error::ErrorStack> {
        let mut cypher = self::Bytes::new();
        let block_size = constants::AES_128_BYTES_IN_KEY;

        let padded_plain = self.pad_pkcs7(block_size);

        for plain_block in padded_plain.chunks(block_size) {
            let cypher_block = plain_block.aes_128_ecb_encrypt_block(key, block_size)?;

            cypher.extend(cypher_block.to_vec());
        }

        Ok(cypher)
    }

    pub fn aes_128_ecb_encrypt_block(
        &self,
        key: &Self,
        block_size: usize,
    ) -> Result<Self, error::ErrorStack> {
        let mut cipher_context = cipher_ctx::CipherCtx::new()?;

        cipher_context.encrypt_init(
            Some(cipher::Cipher::aes_128_ecb()),
            Some(key.as_slice()),
            Some(Default::default()),
        )?;

        cipher_context.set_padding(false);

        self.process_block_symmetric_key(cipher_context, block_size)
    }

    pub fn aes_128_ecb_decrypt(&self, key: &Self) -> Result<Self, error::ErrorStack> {
        let mut cipher_context = cipher_ctx::CipherCtx::new()?;

        cipher_context.decrypt_init(
            Some(cipher::Cipher::aes_128_ecb()),
            Some(key.as_slice()),
            Some(Default::default()),
        )?;

        self.process_block_symmetric_key(cipher_context, block_size)
    }

    fn process_block_symmetric_key(
        &self,
        mut cipher_context: cipher_ctx::CipherCtx,
        block_size: usize,
    ) -> Result<Self, error::ErrorStack> {
        let mut buffer = Self::new();

        cipher_context.cipher_update_vec(self.as_slice(), buffer.as_mut())?;
        cipher_context.cipher_final_vec(buffer.as_mut())?;

        Ok(buffer)
    }

    // ----------------

    pub fn transpose(&self, number_of_blocks: usize) -> Vec<Self> {
        assert!(number_of_blocks > 0);

        // performance: handle special case
        //
        // may come in useful when automatically processing single-byte keys
        if number_of_blocks == 1 {
            return vec![self.clone()];
        }

        let block_capacity = (self.len() / number_of_blocks) + 1;
        let mut transposed_blocks = vec![Self::with_capacity(block_capacity); number_of_blocks];

        for (index, &byte) in self.iter().enumerate() {
            let block_index = index % number_of_blocks;
            transposed_blocks[block_index].push(byte);
        }

        transposed_blocks
    }

    pub fn find_duplicate_blocks(&self, block_size: usize) -> Vec<Self> {
        assert!(block_size > 0);

        let mut blocks = self.chunks(block_size);
        blocks.sort();

        let current_block_iter = blocks.iter();
        let next_block_iter = current_block_iter.clone().skip(1);

        // compare successive blocks and keep duplicates
        let duplicate_blocks = current_block_iter.zip(next_block_iter).fold(
            Vec::new(),
            |mut duplicates, (current_block, next_block)| {
                if current_block == next_block {
                    duplicates.push(current_block.clone());
                }

                duplicates
            },
        );

        duplicate_blocks
    }
}

// ----------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants;
    use crate::crypto_vecs::base64::{BASE64_COMPLETE_ALPHABET, BASE64_COMPLETE_ALPHABET_BYTES};

    #[test]
    fn unit_bytes_new() {
        let expected_result = self::Bytes::from(Vec::new());

        let result = self::Bytes::new();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_with_capacity_10() {
        let capacity = 10;
        let bytes = self::Bytes::with_capacity(capacity);

        assert!(bytes.capacity() >= capacity);
        assert!(bytes.capacity() < capacity * 10);
    }

    #[test]
    fn unit_bytes_with_capacity_100() {
        let capacity = 100;
        let bytes = self::Bytes::with_capacity(capacity);

        assert!(bytes.capacity() >= capacity);
        assert!(bytes.capacity() < capacity * 10);
    }

    #[test]
    fn unit_bytes_with_capacity_10_000() {
        let capacity = 10_000;
        let bytes = self::Bytes::with_capacity(capacity);

        assert!(bytes.capacity() >= capacity);
        assert!(bytes.capacity() < capacity * 10);
    }

    #[test]
    fn unit_bytes_from_single_byte_vector() {
        // avoid "vec!" macro as this is used by the implementation
        let mut expected_result_vec = Vec::new();
        expected_result_vec.push(0xd3);

        let expected_result = self::Bytes::from(expected_result_vec);

        let result = self::Bytes::from(0xd3);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_from_byte_vector() {
        // avoid "vec!" macro as this is used by the implementation
        let mut expected_result_vec = Vec::new();
        expected_result_vec.push(0x41);
        expected_result_vec.push(0x62);
        expected_result_vec.push(0x33);

        let expected_result = self::Bytes::from(expected_result_vec);

        let result = self::Bytes::from(vec![0x41, 0x62, 0x33]);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_from_hex_literal() {
        let expected_result = self::Bytes::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);

        let result = self::Bytes::from_hex_literal("41c3bce4bda0");

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_from_base64_literal() {
        let expected_result = self::Bytes::from(BASE64_COMPLETE_ALPHABET_BYTES.to_vec());

        let result = self::Bytes::from_base64_literal(BASE64_COMPLETE_ALPHABET);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_from_unicode_literal() {
        let expected_result = crypto_vecs::Bytes::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);

        let result = self::Bytes::from_unicode_literal("Aü你");

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_to_iso_8859_1_ascii() {
        let bytes = self::Bytes::from(vec![0x41, 0x62, 0x33]);
        let expected_result = String::from("Ab3");

        let result = bytes.to_iso_8859_1();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_to_iso_8859_1_unicode() {
        let bytes = self::Bytes::from(vec![0x46, 0x72, 0xc3, 0xbc, 0x68, 0x6a, 0x61, 0x68, 0x72]);
        let expected_result = String::from("FrÃ¼hjahr");

        let result = bytes.to_iso_8859_1();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_len_single_byte() {
        let bytes = self::Bytes::from(0xd3);
        let expected_result = 1;

        let result = bytes.len();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_len_several_bytes() {
        let bytes = self::Bytes::from(vec![0x41, 0x62, 0x33]);
        let expected_result = 3;

        let result = bytes.len();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_chunks() {
        let bytes = self::Bytes::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0xff]);

        let mut expected_result = Vec::new();
        expected_result.push(self::Bytes::from(vec![0x41, 0x62, 0xf3]));
        expected_result.push(self::Bytes::from(vec![0xd3, 0x42, 0x6f]));
        expected_result.push(self::Bytes::from(vec![0x12, 0x0d, 0xff]));

        let result = bytes.chunks(3);

        for (index, result_chunk) in result.iter().enumerate() {
            assert_eq!(result_chunk, expected_result.get(index).unwrap());
        }
    }

    #[test]
    fn unit_bytes_chunks_remainder() {
        let bytes = self::Bytes::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut expected_result = Vec::new();
        expected_result.push(self::Bytes::from(vec![0x41, 0x62, 0xf3]));
        expected_result.push(self::Bytes::from(vec![0xd3, 0x42, 0x6f]));
        expected_result.push(self::Bytes::from(vec![0x12, 0x0d]));

        let result = bytes.chunks(3);

        for (index, result_chunk) in result.iter().enumerate() {
            assert_eq!(result_chunk, expected_result.get(index).unwrap());
        }
    }

    #[test]
    fn unit_bytes_rchunks() {
        let bytes = self::Bytes::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0xff]);

        let mut expected_result = Vec::new();
        expected_result.push(self::Bytes::from(vec![0x12, 0x0d, 0xff]));
        expected_result.push(self::Bytes::from(vec![0xd3, 0x42, 0x6f]));
        expected_result.push(self::Bytes::from(vec![0x41, 0x62, 0xf3]));

        let result = bytes.rchunks(3);

        for (index, result_chunk) in result.iter().enumerate() {
            assert_eq!(result_chunk, expected_result.get(index).unwrap());
        }
    }

    #[test]
    fn unit_bytes_rchunks_remainder() {
        let bytes = self::Bytes::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut expected_result = Vec::new();
        expected_result.push(self::Bytes::from(vec![0x6f, 0x12, 0x0d]));
        expected_result.push(self::Bytes::from(vec![0xf3, 0xd3, 0x42]));
        expected_result.push(self::Bytes::from(vec![0x41, 0x62]));

        let result = bytes.rchunks(3);

        for (index, result_chunk) in result.iter().enumerate() {
            assert_eq!(result_chunk, expected_result.get(index).unwrap());
        }
    }

    #[test]
    fn unit_bytes_first_n() {
        let bytes = self::Bytes::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);
        let expected_result = self::Bytes::from(vec![0x41, 0x62, 0xf3]);

        let result = bytes.first_n(3).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_first_n_longer_than_original() {
        let bytes = self::Bytes::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);
        let expected_result =
            self::Bytes::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);

        let result = bytes.first_n(12).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_last_n() {
        let bytes = self::Bytes::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);
        let expected_result = self::Bytes::from(vec![0x12, 0x0d, 0x1e]);

        let result = bytes.last_n(3).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_last_n_longer_than_original() {
        let bytes = self::Bytes::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);
        let expected_result =
            self::Bytes::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);

        let result = bytes.last_n(12).unwrap();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_push_to_new() {
        let expected_result = self::Bytes::from(vec![0xd3, 0x42, 0x6f]);

        let mut result = self::Bytes::new();
        result.push(0xd3);
        result.push(0x42);
        result.push(0x6f);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_push_to_existing() {
        let expected_result = self::Bytes::from(vec![0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut result = self::Bytes::from(vec![0xd3, 0x42, 0x6f]);
        result.push(0x12);
        result.push(0x0d);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_extend_to_new() {
        let expected_result = self::Bytes::from(vec![0xd3, 0x42, 0x6f]);

        let mut result = self::Bytes::new();
        result.extend(vec![0xd3, 0x42, 0x6f]);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_extend_to_existing() {
        let expected_result = self::Bytes::from(vec![0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut result = self::Bytes::from(vec![0xd3, 0x42, 0x6f]);
        result.extend(vec![0x12, 0x0d]);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_iter() {
        let bytes = self::Bytes::from(vec![0xd3, 0x42, 0x6f]);
        let mut bytes_iter = bytes.iter();

        assert_eq!(bytes_iter.next(), Some(&0xd3));
        assert_eq!(bytes_iter.next(), Some(&0x42));
        assert_eq!(bytes_iter.next(), Some(&0x6f));
        assert_eq!(bytes_iter.next(), None);
    }

    #[test]
    fn unit_bytes_into_iter() {
        let bytes = self::Bytes::from(vec![0xd3, 0x42, 0x6f]);
        let mut bytes_iter = bytes.into_iter();

        assert_eq!(bytes_iter.next(), Some(0xd3));
        assert_eq!(bytes_iter.next(), Some(0x42));
        assert_eq!(bytes_iter.next(), Some(0x6f));
        assert_eq!(bytes_iter.next(), None);
    }

    #[test]
    fn unit_bytes_as_mut_to_switch_byte() {
        let expected_result = self::Bytes::from(vec![0xd3, 0xff, 0x6f]);

        let mut result = self::Bytes::from(vec![0xd3, 0x42, 0x6f]);
        let result_mut = result.as_mut();
        result_mut[1] = 0xff;

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_as_mut_to_extend() {
        let expected_result = self::Bytes::from(vec![0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut result = self::Bytes::from(vec![0xd3, 0x42, 0x6f]);
        let result_mut = result.as_mut();
        result_mut.extend_from_slice(&vec![0x12, 0x0d]);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_as_mut_slice_to_switch_byte() {
        let expected_result = self::Bytes::from(vec![0xd3, 0xff, 0x6f]);

        let mut result = self::Bytes::from(vec![0xd3, 0x42, 0x6f]);
        let result_mut = result.as_mut_slice();
        result_mut[1] = 0xff;

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_to_string_single_byte() {
        let bytes = self::Bytes::from(0xaf);
        let expected_result = String::from("Bytes[1] { af }");

        let result = bytes.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_to_string_byte_vector() {
        let bytes = self::Bytes::from(vec![0x41, 0x62, 0xf3]);
        let expected_result = String::from("Bytes[3] { 4162f3 }");

        let result = bytes.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_to_string_three_blocks() {
        let bytes = self::Bytes::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);
        let expected_result = String::from("Bytes[9] { 4162f3d3 426f120d 1e }");

        let result = bytes.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_to_string_no_space_at_end() {
        let bytes = self::Bytes::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d]);
        let expected_result = String::from("Bytes[8] { 4162f3d3 426f120d }");

        let result = bytes.to_string();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_fixed_xor_single_byte() {
        let plain = self::Bytes::from(0x1c);
        let key = self::Bytes::from(0x74);
        let expected_result = self::Bytes::from(0x68);

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_fixed_xor_single_byte_key() {
        let plain = self::Bytes::from(vec![
            0x1c, 0x01, 0x11, 0x00, 0x1f, 0xa2, 0x4b, 0x53, 0x98, 0xc5,
        ]);
        let key = self::Bytes::from(0x74);
        let expected_result = self::Bytes::from(vec![
            0x68, 0x75, 0x65, 0x74, 0x6b, 0xd6, 0x3f, 0x27, 0xec, 0xb1,
        ]);

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_fixed_xor_full_length_key() {
        let plain = self::Bytes::from(vec![
            0x1c, 0x01, 0x11, 0x00, 0x1f, 0x01, 0x01, 0x00, 0x06, 0x1a, 0x02, 0x4b, 0x53, 0x53,
            0x50, 0x09, 0x18, 0x1c,
        ]);
        let key = self::Bytes::from(vec![
            0x68, 0x69, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x62, 0x75, 0x6c, 0x6c, 0x27, 0x73,
            0x20, 0x65, 0x79, 0x65,
        ]);
        let expected_result = self::Bytes::from(vec![
            0x74, 0x68, 0x65, 0x20, 0x6b, 0x69, 0x64, 0x20, 0x64, 0x6f, 0x6e, 0x27, 0x74, 0x20,
            0x70, 0x6c, 0x61, 0x79,
        ]);

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_fixed_xor_key_too_long() {
        let plain = self::Bytes::from(vec![0x1c, 0x01, 0x11, 0x00]);
        let key = self::Bytes::from(vec![0x68, 0x69, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20]);
        let expected_result = self::Bytes::from(vec![0x74, 0x68, 0x65, 0x20]);

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_hamming_distance_single_byte() {
        // from u8
        let bytes = self::Bytes::from(0x02);
        // from Vec<u8>
        let other = self::Bytes::from(vec![0xa0]);
        let expected_result = 3;

        let result = bytes.hamming_distance(&other);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_hamming_distance_two_bytes_1() {
        let bytes = self::Bytes::from(vec![0x02, 0xb0]);
        let other = self::Bytes::from(vec![0xa0, 0x01]);
        let expected_result = 7;

        let result = bytes.hamming_distance(&other);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_hamming_distance_two_bytes_2() {
        let bytes = self::Bytes::from(vec![0x1d, 0x42]);
        let other = self::Bytes::from(vec![0x1f, 0x4d]);
        let expected_result = 5;

        let result = bytes.hamming_distance(&other);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_hamming_distance_three_bytes() {
        let bytes = self::Bytes::from(vec![0x1d, 0x42, 0x1f]);
        let other = self::Bytes::from(vec![0x4d, 0x0b, 0x0f]);
        let expected_result = 6;

        let result = bytes.hamming_distance(&other);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_hamming_distance_five_bytes() {
        let bytes = self::Bytes::from(vec![0x1d, 0x42, 0x1f, 0x4d, 0x0b]);
        let other = self::Bytes::from(vec![0x0f, 0x02, 0x1f, 0x4f, 0x13]);
        let expected_result = 6;

        let result = bytes.hamming_distance(&other);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_transpose_no_transposition() {
        let bytes = self::Bytes::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let keysize = 1;

        let transposed_vecs = bytes.transpose(keysize);

        assert_eq!(transposed_vecs.len(), keysize);

        assert_eq!(transposed_vecs[0], bytes);
    }

    #[test]
    fn unit_bytes_transpose_equal_distribution() {
        let bytes = self::Bytes::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let keysize = 2;

        let transposed_vecs = bytes.transpose(keysize);

        assert_eq!(transposed_vecs.len(), keysize);

        assert_eq!(transposed_vecs[0], self::Bytes::from(vec![1, 3, 5, 7, 9]));
        assert_eq!(transposed_vecs[1], self::Bytes::from(vec![2, 4, 6, 8, 10]));
    }

    #[test]
    fn unit_bytes_transpose_unequal_distribution() {
        let bytes = self::Bytes::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let keysize = 3;

        let transposed_vecs = bytes.transpose(keysize);

        assert_eq!(transposed_vecs.len(), keysize);

        assert_eq!(transposed_vecs[0], self::Bytes::from(vec![1, 4, 7, 10]));
        assert_eq!(transposed_vecs[1], self::Bytes::from(vec![2, 5, 8]));
        assert_eq!(transposed_vecs[2], self::Bytes::from(vec![3, 6, 9]));
    }

    #[test]
    fn unit_bytes_transpose_not_enough_elements() {
        let bytes = self::Bytes::from(vec![1, 2, 3]);
        let keysize = bytes.len() + 1;

        let transposed_vecs = bytes.transpose(keysize);

        assert_eq!(transposed_vecs.len(), keysize);

        assert_eq!(transposed_vecs[0], self::Bytes::from(1));
        assert_eq!(transposed_vecs[1], self::Bytes::from(2));
        assert_eq!(transposed_vecs[2], self::Bytes::from(3));
        assert_eq!(transposed_vecs[3], self::Bytes::new());
    }

    #[test]
    fn unit_bytes_find_duplicate_blocks_blocksize_1() {
        let bytes = crypto_vecs::Bytes::from_hex_literal(
            "3a 1b d4 cb d0 aa 25 f2 66 db b8 fe 16 6e d4 cb 25 f3",
        );

        let block_size = 1;
        let mut expected_result = Vec::new();

        expected_result.push(crypto_vecs::Bytes::from_hex_literal("25"));

        expected_result.push(crypto_vecs::Bytes::from_hex_literal("cb"));

        let duplicate_block = crypto_vecs::Bytes::from_hex_literal("d4");
        expected_result.push(duplicate_block);

        let result = bytes.find_duplicate_blocks(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_find_duplicate_blocks_blocksize_2() {
        let bytes = crypto_vecs::Bytes::from_hex_literal(
            "3a1b 7e49 d4cb d0aa 25f2 66db b8fe 166e d4cb 7e49 db25 d4cb",
        );

        let block_size = 2;
        let mut expected_result = Vec::new();

        expected_result.push(crypto_vecs::Bytes::from_hex_literal("7e49"));
        expected_result.push(crypto_vecs::Bytes::from_hex_literal("d4cb"));
        expected_result.push(crypto_vecs::Bytes::from_hex_literal("d4cb"));

        let result = bytes.find_duplicate_blocks(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_find_duplicate_blocks_blocksize_3() {
        let bytes = crypto_vecs::Bytes::from_hex_literal(
            "3a1b7e 49d4cb d0aa25 f266db b8fe16 6ed4cb d0aadb 25f266",
        );

        let block_size = 3;
        let expected_result = Vec::new();

        let result = bytes.find_duplicate_blocks(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_find_duplicate_blocks_blocksize_4() {
        let bytes = crypto_vecs::Bytes::from_hex_literal(
            "3a1b7e49 d4cbd0aa 25f266db 3a1b7e49 d4cbd0aa db25f266",
        );

        let block_size = 4;
        let mut expected_result = Vec::new();

        expected_result.push(crypto_vecs::Bytes::from_hex_literal("3a1b7e49"));
        expected_result.push(crypto_vecs::Bytes::from_hex_literal("d4cbd0aa"));

        let result = bytes.find_duplicate_blocks(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_find_duplicate_blocks_blocksize_4_dangling_end() {
        let bytes =
            crypto_vecs::Bytes::from_hex_literal("3a1b7e49 d4cbd0aa 25f266db 3a1b7e49 d4cbd0aa db");

        let block_size = 4;
        let mut expected_result = Vec::new();

        expected_result.push(crypto_vecs::Bytes::from_hex_literal("3a1b7e49"));
        expected_result.push(crypto_vecs::Bytes::from_hex_literal("d4cbd0aa"));

        let result = bytes.find_duplicate_blocks(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_find_duplicate_blocks_blocksize_8() {
        let bytes = crypto_vecs::Bytes::from_hex_literal(
            "3a1b7e49 d4cbd0aa 25f266db 3a1b7e49 d4cbd0aa db25f266",
        );

        let block_size = 8;
        let expected_result = Vec::new();

        let result = bytes.find_duplicate_blocks(block_size);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_is_padded_pkcs7_single_block_incomplete() {
        let bytes = self::Bytes::from_hex_literal("db25f2");
        let block_size = 4;

        let expected_result = Err(1);

        let result = bytes.is_padded_pkcs7(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_is_padded_pkcs7_single_block_unpadded() {
        let bytes = self::Bytes::from_hex_literal("db25f266");
        let block_size = 4;

        let expected_result = Err(4);

        let result = bytes.is_padded_pkcs7(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_is_padded_pkcs7_single_block_correctly_padded() {
        let bytes = self::Bytes::from_hex_literal("db250202");
        let block_size = 4;

        let expected_result = Ok(2);

        let result = bytes.is_padded_pkcs7(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_is_padded_pkcs7_single_block_incorrectly_padded() {
        let bytes = self::Bytes::from_hex_literal("db25ff02");
        let block_size = 4;

        let expected_result = Err(4);

        let result = bytes.is_padded_pkcs7(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_is_padded_pkcs7_two_blocks_incomplete() {
        let bytes = self::Bytes::from_hex_literal("3a1b7e49 db");
        let block_size = 4;

        let expected_result = Err(3);

        let result = bytes.is_padded_pkcs7(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_pad_pkcs7_single_block() {
        let unpadded = self::Bytes::from_unicode_literal("YELLOW SUBMARINE");
        let block_size = 20;

        let expected_result =
            crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE\x04\x04\x04\x04");

        let result = unpadded.pad_pkcs7(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_pad_pkcs7_two_blocks() {
        let unpadded = self::Bytes::from_unicode_literal("YELLOW SUBMARINE");
        let block_size = 6;

        let expected_result = self::Bytes::from_unicode_literal("YELLOW SUBMARINE\x02\x02");

        let result = unpadded.pad_pkcs7(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_pad_pkcs7_full_block_unpadded() {
        let unpadded = self::Bytes::from_unicode_literal("YELLOW SUBMARINE");
        let block_size = 8;

        let expected_result =
            self::Bytes::from_unicode_literal("YELLOW SUBMARINE\x08\x08\x08\x08\x08\x08\x08\x08");

        let result = unpadded.pad_pkcs7(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_pad_pkcs7_full_block_correctly_padded() {
        let unpadded = self::Bytes::from_unicode_literal("YELLOW SUBMARIN\x01");
        let block_size = 8;

        let expected_result = self::Bytes::from_unicode_literal("YELLOW SUBMARIN\x01");

        let result = unpadded.pad_pkcs7(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_pad_pkcs7_full_block_incorrectly_padded() {
        let unpadded = self::Bytes::from_unicode_literal("YELLOW SUBMARI\x01\x02");
        let block_size = 8;

        let expected_result = self::Bytes::from_unicode_literal(
            "YELLOW SUBMARI\x01\x02\x08\x08\x08\x08\x08\x08\x08\x08",
        );

        let result = unpadded.pad_pkcs7(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_unpad_pkcs7_single_block_four_bytes() {
        let padded = self::Bytes::from_unicode_literal("YELLOW SUBMARINE\x04\x04\x04\x04");
        let block_size = 20;

        let expected_result = Ok(crypto_vecs::Bytes::from_unicode_literal("YELLOW SUBMARINE"));

        let result = padded.unpad_pkcs7(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_unpad_pkcs7_two_blocks_single_byte() {
        let padded = self::Bytes::from_unicode_literal("YELLOW SUBMARIN\x01");
        let block_size = 8;

        let expected_result = Ok(self::Bytes::from_unicode_literal("YELLOW SUBMARIN"));

        let result = padded.unpad_pkcs7(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_unpad_pkcs7_two_blocks_padded_two_bytes() {
        let padded = self::Bytes::from_unicode_literal("YELLOW SUBMARINE\x02\x02");
        let block_size = 6;

        let expected_result = Ok(self::Bytes::from_unicode_literal("YELLOW SUBMARINE"));

        let result = padded.unpad_pkcs7(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_unpad_pkcs7_full_block_padding() {
        let padded =
            self::Bytes::from_unicode_literal("YELLOW SUBMARINE\x08\x08\x08\x08\x08\x08\x08\x08");
        let block_size = 8;

        let expected_result = Ok(self::Bytes::from_unicode_literal("YELLOW SUBMARINE"));

        let result = padded.unpad_pkcs7(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_unpad_pkcs7_no_padding() {
        let padded = self::Bytes::from_unicode_literal("YELLOW SUBMARINE");
        let block_size = 8;

        let expected_result = Err("invalid PKCS#7 padding");

        let result = padded.unpad_pkcs7(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_unpad_pkcs7_incorrect_padding_wrong_byte() {
        let padded = self::Bytes::from_unicode_literal("YELLOW SUBMARI\x01\x02");
        let block_size = 8;

        let expected_result = Err("invalid PKCS#7 padding");

        let result = padded.unpad_pkcs7(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_unpad_pkcs7_incorrect_padding_overhanging_bytes() {
        let padded = self::Bytes::from_unicode_literal("YELLOW SUBMARINE\x02\x02");
        let block_size = 8;

        let expected_result = Err("invalid PKCS#7 padding");

        let result = padded.unpad_pkcs7(block_size);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_aes_128_ecb_encrypt_unpadded() {
        let plain = crypto_vecs::Bytes::from_unicode_literal(
            "Mary had a little lamb whose fleece was white as snow.",
        );
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

        let result = plain.aes_128_ecb_encrypt(&key).unwrap();

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
        );
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

        let result = plain.aes_128_ecb_encrypt(&key).unwrap();

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
        );
        let key = crypto_vecs::Bytes::from_unicode_literal("Little Test 1234");

        let expected_result = crypto_vecs::Bytes::from_unicode_literal(
            "Mary had a little lamb whose fleece was white as snow.",
        );

        let result = cypher.aes_128_ecb_decrypt(&key).unwrap();

        assert_eq!(result, expected_result);
    }
}
