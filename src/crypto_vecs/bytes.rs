use openssl::{cipher, cipher_ctx};
use std::{convert, slice, sync, vec};

use crate::crypto_vecs::traits::{
    Elements, FromBytes, InternalDataVec, InternalDataVecMut, LenBytes, Representation, ToBytes,
};
use crate::crypto_vecs::{self, Base64Type, BlockBytes, HexadecimalType, UnicodeType};

// ================

#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Bytes {
    bytes: Vec<u8>,
}

pub type BytesType = crypto_vecs::CryptoVec<Bytes, u8>;

// ================

impl InternalDataVec for Bytes {
    type Element = u8;

    fn new_from(data: Vec<Self::Element>) -> Self {
        match Self::clean_and_validate(data) {
            Ok(data) => Self { bytes: data },
            Err(error) => panic!("{}", error),
        }
    }

    fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    fn clean_and_validate(data: Vec<Self::Element>) -> Result<Vec<Self::Element>, String> {
        Ok(data)
    }

    // ----------------

    fn data(&self) -> &Vec<Self::Element> {
        &self.bytes
    }

    fn chunks(&self, chunk_size: usize) -> slice::Chunks<'_, Self::Element> {
        assert!(chunk_size > 0, "chunk size must be non-zero");

        self.bytes.chunks(chunk_size)
    }

    fn rchunks(&self, chunk_size: usize) -> slice::RChunks<'_, Self::Element> {
        assert!(chunk_size > 0, "chunk size must be non-zero");

        self.bytes.rchunks(chunk_size)
    }

    // ----------------

    fn get(&self, index: usize) -> Option<&Self::Element> {
        self.bytes.get(index)
    }
}

// ----------------

impl InternalDataVecMut for Bytes {
    type Element = u8;

    fn data_mut(&mut self) -> &mut Vec<Self::Element> {
        &mut self.bytes
    }

    fn push(&mut self, value: Self::Element) {
        self.bytes.push(value)
    }
}

// ----------------

// iterate over bytes
impl Elements for Bytes {
    type Element = u8;

    fn elements(&self) -> impl Iterator<Item = Self::Element> {
        self.bytes.iter().copied()
    }
}

// iterate over bytes (by reference)
impl<'a> Elements for &'a Bytes {
    type Element = &'a u8;

    fn elements(&self) -> impl Iterator<Item = Self::Element> {
        self.bytes.iter()
    }
}

// ----------------

impl Representation for Bytes {
    fn representation_name(&self) -> &str {
        "Bytes"
    }

    fn representation(&self) -> String {
        self.to_hexadecimal().representation()
    }
}

// ----------------

impl FromBytes for Bytes {
    fn from_bytes(bytes: &BytesType) -> Self {
        Self {
            bytes: bytes.data().clone(),
        }
    }
}

impl ToBytes for Bytes {
    fn to_bytes(&self) -> BytesType {
        BytesType::new_from(self.bytes.clone())
    }
}

// ----------------

impl LenBytes for Bytes {
    fn len_bytes(&self) -> usize {
        self.len()
    }
}

// ----------------

impl Extend<u8> for Bytes {
    fn extend<A: IntoIterator<Item = u8>>(&mut self, iter: A) {
        self.bytes.extend(iter);
    }
}

// ----------------

impl convert::AsRef<Vec<u8>> for Bytes {
    fn as_ref(&self) -> &Vec<u8> {
        self.bytes.as_ref()
    }
}

impl convert::AsMut<Vec<u8>> for Bytes {
    fn as_mut(&mut self) -> &mut Vec<u8> {
        self.bytes.as_mut()
    }
}

// ----------------

impl IntoIterator for Bytes {
    type Item = u8;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.bytes.into_iter()
    }
}

// ================

static MAPPING_CODEPAGE_1252: sync::LazyLock<Vec<char>> = sync::LazyLock::new(|| {
    concat!(
        "␀␁␂␃␄␅␆␇␈␉␊␋␌␍␎␏",
        "␐␑␒␓␔␕␖␗␘␙␚␛␜␝␞␟",
        " !\"#$%&'()*+,-./",
        "0123456789:;<=>?",
        "@ABCDEFGHIJKLMNO",
        "PQRSTUVWXYZ[\\]^_",
        "`abcdefghijklmno",
        "pqrstuvwxyz{|}~␡",
        "€�‚ƒ„…†‡ˆ‰Š‹Œ�Ž�",
        "�‘’“”•–—˜™š›œ�žŸ",
        "�¡¢£¤¥¦§¨©ª«¬�®¯",
        "°±²³´µ¶·¸¹º»¼½¾¿",
        "ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏ",
        "ÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß",
        "àáâãäåæçèéêëìíîï",
        "ðñòóôõö÷øùúûüýþÿ"
    )
    .chars()
    .collect()
});

// ----------------

impl BytesType {
    const LOOKUP_BITS_IN_NIBBLE: [u32; 16] = [0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4];

    // ----------------

    pub fn from_hex_literal(string_literal: &str) -> Self {
        let hexadecimal = HexadecimalType::from(string_literal);

        hexadecimal.to_bytes()
    }

    pub fn from_base64_literal(string_literal: &str) -> Self {
        let base64 = Base64Type::from(string_literal);

        base64.to_bytes()
    }

    pub fn from_unicode_literal(string_literal: &str) -> Self {
        let unicode = UnicodeType::from(string_literal);

        unicode.to_bytes()
    }

    // ----------------

    pub fn to_blocks(&self, block_size: usize) -> BlockBytes {
        assert!(block_size > 0, "block size must be non-zero");

        self.data()
            .chunks(block_size)
            .fold(BlockBytes::new(block_size), |mut acc, block| {
                acc.push(Self::from(block));
                acc
            })
    }

    pub fn to_blocks_bits(&self, block_size_bits: usize) -> BlockBytes {
        let bytes = crypto_vecs::bits_to_bytes(block_size_bits);

        self.to_blocks(bytes)
    }

    // convert bytes to Windows code page 1252 (with placeholders for special
    // characters); this is very useful for checking decoded strings without
    // "breaking" the terminal
    pub fn to_codepage_1252(&self) -> String {
        self.iter()
            .map(|n: &u8| MAPPING_CODEPAGE_1252[*n as usize])
            .collect()
    }

    // ----------------

    pub fn fixed_xor(&self, key: &Self) -> Self {
        assert!(!key.is_empty());

        let mut bytes_key_endless = key.iter().cycle();

        self.iter()
            .fold(Default::default(), |mut acc, &byte_plain| {
                let byte_key = bytes_key_endless
                    .next()
                    .expect("infinite key was finite after all");

                acc.push((byte_plain | byte_key) & !(byte_plain & byte_key));
                acc
            })
    }

    pub fn hamming_distance(&self, other: &Self) -> u32 {
        let bytes_with_differing_bits = self.fixed_xor(other);

        bytes_with_differing_bits.iter().fold(0, |acc, &byte| {
            let nibble_value_low = byte & 0x0f;
            let nibble_value_high = byte >> 4;

            let differing_bits_low = *BytesType::LOOKUP_BITS_IN_NIBBLE
                .get(nibble_value_low as usize)
                .expect("index must be between 0 and 15");

            let differing_bits_high = *BytesType::LOOKUP_BITS_IN_NIBBLE
                .get(nibble_value_high as usize)
                .expect("index must be between 0 and 15");

            acc + differing_bits_low + differing_bits_high
        })
    }

    // ----------------

    pub fn aes_ecb_encrypt_block(
        &self,
        key: &Self,
        block_size_bits: usize,
    ) -> Result<Self, String> {
        assert_eq!(block_size_bits, 128);

        assert_eq!(
            key.len_bits(),
            block_size_bits,
            "key has {} bits, block has {} bits, ",
            key.len_bits(),
            block_size_bits,
        );

        let mut cipher_context = cipher_ctx::CipherCtx::new().expect("what can go wrong?");

        let encryptor_status = cipher_context.encrypt_init(
            Some(cipher::Cipher::aes_128_ecb()),
            Some(key.as_slice()),
            Some(Default::default()),
        );

        if let Err(error_stack) = encryptor_status {
            return Err(error_stack.to_string());
        };

        cipher_context.set_padding(false);

        self.process_block_symmetric_key(cipher_context, block_size_bits)
    }

    pub fn aes_ecb_decrypt_block(
        &self,
        key: &Self,
        block_size_bits: usize,
    ) -> Result<Self, String> {
        assert_eq!(block_size_bits, 128);

        assert_eq!(
            key.len_bits(),
            block_size_bits,
            "key has {} bits, block has {} bits, ",
            key.len_bits(),
            block_size_bits,
        );

        let mut cipher_context = cipher_ctx::CipherCtx::new().expect("what can go wrong?");

        let decryptor_status = cipher_context.decrypt_init(
            Some(cipher::Cipher::aes_128_ecb()),
            Some(key.as_slice()),
            Some(Default::default()),
        );

        if let Err(error_stack) = decryptor_status {
            return Err(error_stack.to_string());
        };

        cipher_context.set_padding(false);

        self.process_block_symmetric_key(cipher_context, block_size_bits)
    }

    fn process_block_symmetric_key(
        &self,
        mut cipher_context: cipher_ctx::CipherCtx,
        block_size_bits: usize,
    ) -> Result<Self, String> {
        assert_eq!(
            self.len_bits(),
            block_size_bits,
            "block has {} bits, expected are {} bits, ",
            self.len_bits(),
            block_size_bits,
        );

        let mut buffer = Self::default();
        let processing_state = cipher_context.cipher_update_vec(self.as_slice(), buffer.as_mut());

        if let Err(error_stack) = processing_state {
            return Err(error_stack.to_string());
        };

        let finalization_state = cipher_context.cipher_final_vec(buffer.as_mut());

        match finalization_state {
            Err(error_stack) => Err(error_stack.to_string()),
            _ => Ok(buffer),
        }
    }

    // ----------------

    pub fn transpose(&self, number_of_blocks: usize) -> BlockBytes {
        assert!(number_of_blocks > 0);

        let block_size = self.len_bytes().div_ceil(number_of_blocks);
        let mut transposed_blocks = vec![Self::with_capacity(block_size); number_of_blocks];

        transposed_blocks =
            self.iter()
                .enumerate()
                .fold(transposed_blocks, |mut acc, (index, byte)| {
                    let block_index = index % number_of_blocks;

                    acc[block_index].push(*byte);
                    acc
                });

        BlockBytes::from(transposed_blocks)
    }
}

// ================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_vecs::base64::Base64;

    // ----------------

    #[test]
    fn unit_bytes_default() {
        let expected_result = BytesType::from(Vec::default());

        let result = BytesType::default();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_with_capacity_10() {
        let capacity = 10;
        let bytes = BytesType::with_capacity(capacity);

        assert!(
            bytes.capacity() >= capacity,
            "capacity {} >= {}",
            bytes.capacity(),
            capacity
        );

        assert!(
            bytes.capacity() < capacity * 10,
            "capacity {} < {}",
            bytes.capacity(),
            capacity * 10
        );
    }

    #[test]
    fn unit_bytes_with_capacity_100() {
        let capacity = 100;
        let bytes = BytesType::with_capacity(capacity);

        assert!(
            bytes.capacity() >= capacity,
            "capacity {} >= {}",
            bytes.capacity(),
            capacity
        );

        assert!(
            bytes.capacity() < capacity * 10,
            "capacity {} < {}",
            bytes.capacity(),
            capacity * 10
        );
    }

    #[test]
    fn unit_bytes_with_capacity_10_000() {
        let capacity = 10_000;
        let bytes = BytesType::with_capacity(capacity);

        assert!(
            bytes.capacity() >= capacity,
            "capacity {} >= {}",
            bytes.capacity(),
            capacity
        );

        assert!(
            bytes.capacity() < capacity * 10,
            "capacity {} < {}",
            bytes.capacity(),
            capacity * 10
        );
    }

    #[test]
    fn unit_bytes_from_single_byte_vector() {
        // avoid "vec!" macro as this is used by the implementation
        let mut expected_result_vec = Vec::default();
        expected_result_vec.push(0xd3);

        let expected_result = BytesType::from(expected_result_vec);

        let result = BytesType::from(0xd3);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_from_byte_vector() {
        // avoid "vec!" macro as this is used by the implementation
        let mut expected_result_vec = Vec::default();
        expected_result_vec.push(0x41);
        expected_result_vec.push(0x62);
        expected_result_vec.push(0x33);

        let expected_result = BytesType::from(expected_result_vec);

        let result = BytesType::from(vec![0x41, 0x62, 0x33]);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_from_hex_literal() {
        let expected_result = BytesType::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);

        let result = BytesType::from_hex_literal("41c3bce4bda0");

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_from_base64_literal() {
        let expected_result = BytesType::from(Base64::COMPLETE_ALPHABET_BYTES.to_vec());

        let result = BytesType::from_base64_literal(Base64::COMPLETE_ALPHABET);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_from_unicode_literal() {
        let expected_result = BytesType::from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);

        let result = BytesType::from_unicode_literal("Aü你");

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_to_codepage_1252_ascii() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0x33]);
        let expected_result = String::from("Ab3");

        let result = bytes.to_codepage_1252();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_to_codepage_1252_unicode() {
        let bytes = BytesType::from(vec![0x46, 0x72, 0xc3, 0xbc, 0x68, 0x6a, 0x61, 0x68, 0x72]);
        let expected_result = String::from("FrÃ¼hjahr");

        let result = bytes.to_codepage_1252();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_to_codepage_1252_unicode_string() {
        let unicode = UnicodeType::from("\n Hi. Servus. Grüezi. 你好.\t");
        let bytes = unicode.to_bytes();

        let expected_result = String::from("␊ Hi. Servus. GrÃ¼ezi. ä½�å¥½.␉");

        let result = bytes.to_codepage_1252();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_to_codepage_1252_complete_alphabet() {
        let bytes = BytesType::new_from((0x00..=0xff).collect());

        let expected_result = String::from_iter(MAPPING_CODEPAGE_1252.iter());

        let result = bytes.to_codepage_1252();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_len_bytes_single_byte() {
        let bytes = BytesType::from(0xd3);

        let expected_result = 1;

        let result = bytes.len_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_len_bytes_several_bytes() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0x33]);

        let expected_result = 3;

        let result = bytes.len_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_chunks() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0xff]);

        let mut expected_result = Vec::default();
        expected_result.push(vec![0x41, 0x62, 0xf3]);
        expected_result.push(vec![0xd3, 0x42, 0x6f]);
        expected_result.push(vec![0x12, 0x0d, 0xff]);

        let result = bytes.chunks(3);

        for (index, result_chunk) in result.enumerate() {
            assert_eq!(result_chunk, expected_result.get(index).unwrap());
        }
    }

    #[test]
    fn unit_bytes_chunks_remainder() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut expected_result = Vec::default();
        expected_result.push(vec![0x41, 0x62, 0xf3]);
        expected_result.push(vec![0xd3, 0x42, 0x6f]);
        expected_result.push(vec![0x12, 0x0d]);

        let result = bytes.chunks(3);

        for (index, result_chunk) in result.enumerate() {
            assert_eq!(result_chunk, expected_result.get(index).unwrap());
        }
    }

    #[test]
    fn unit_bytes_chunks_as_collection() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0xff]);

        let mut expected_result = Vec::default();
        expected_result.push(BytesType::from(vec![0x41, 0x62, 0xf3]));
        expected_result.push(BytesType::from(vec![0xd3, 0x42, 0x6f]));
        expected_result.push(BytesType::from(vec![0x12, 0x0d, 0xff]));

        let result = bytes.chunks_as_collection(3);

        for (index, result_chunk) in result.iter().enumerate() {
            assert_eq!(result_chunk, expected_result.get(index).unwrap());
        }
    }

    #[test]
    fn unit_bytes_chunks_remainder_as_collection() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut expected_result = Vec::default();
        expected_result.push(BytesType::from(vec![0x41, 0x62, 0xf3]));
        expected_result.push(BytesType::from(vec![0xd3, 0x42, 0x6f]));
        expected_result.push(BytesType::from(vec![0x12, 0x0d]));

        let result = bytes.chunks_as_collection(3);

        for (index, result_chunk) in result.iter().enumerate() {
            assert_eq!(result_chunk, expected_result.get(index).unwrap());
        }
    }

    #[test]
    fn unit_bytes_to_blocks() {
        let bytes = BytesType::from_hex_literal("4162f3 d3426f 120dff");
        let block_size = 3;

        let mut expected_result = BlockBytes::new(block_size);
        expected_result.push(BytesType::from_hex_literal("4162f3"));
        expected_result.push(BytesType::from_hex_literal("d3426f"));
        expected_result.push(BytesType::from_hex_literal("120dff"));

        let result = bytes.to_blocks(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_to_blocks_remainder() {
        let bytes = BytesType::from_hex_literal("4162f3 d3426f 120d");
        let block_size = 3;

        let mut expected_result = BlockBytes::new(block_size);
        expected_result.push(BytesType::from_hex_literal("4162f3"));
        expected_result.push(BytesType::from_hex_literal("d3426f"));
        expected_result.push(BytesType::from_hex_literal("120d"));

        let result = bytes.to_blocks(block_size);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_to_blocks_bits() {
        let bytes = BytesType::from_hex_literal("4162f3 d3426f 120dff");
        let block_size_bits = 24;

        let mut expected_result = BlockBytes::new_bits(block_size_bits);
        expected_result.push(BytesType::from_hex_literal("4162f3"));
        expected_result.push(BytesType::from_hex_literal("d3426f"));
        expected_result.push(BytesType::from_hex_literal("120dff"));

        let result = bytes.to_blocks_bits(block_size_bits);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_to_blocks_bits_remainder() {
        let bytes = BytesType::from_hex_literal("4162f3 d3426f 120d");
        let block_size_bits = 24;

        let mut expected_result = BlockBytes::new_bits(block_size_bits);
        expected_result.push(BytesType::from_hex_literal("4162f3"));
        expected_result.push(BytesType::from_hex_literal("d3426f"));
        expected_result.push(BytesType::from_hex_literal("120d"));

        let result = bytes.to_blocks_bits(block_size_bits);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_rchunks() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0xff]);

        let mut expected_result = Vec::default();
        expected_result.push(vec![0x12, 0x0d, 0xff]);
        expected_result.push(vec![0xd3, 0x42, 0x6f]);
        expected_result.push(vec![0x41, 0x62, 0xf3]);

        let result = bytes.rchunks(3);

        for (index, result_chunk) in result.enumerate() {
            assert_eq!(result_chunk, expected_result.get(index).unwrap());
        }
    }

    #[test]
    fn unit_bytes_rchunks_remainder() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut expected_result = Vec::default();
        expected_result.push(vec![0x6f, 0x12, 0x0d]);
        expected_result.push(vec![0xf3, 0xd3, 0x42]);
        expected_result.push(vec![0x41, 0x62]);

        let result = bytes.rchunks(3);

        for (index, result_chunk) in result.enumerate() {
            assert_eq!(result_chunk, expected_result.get(index).unwrap());
        }
    }

    #[test]
    fn unit_bytes_rchunks_as_collection() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0xff]);

        let mut expected_result = Vec::default();
        expected_result.push(BytesType::from(vec![0x12, 0x0d, 0xff]));
        expected_result.push(BytesType::from(vec![0xd3, 0x42, 0x6f]));
        expected_result.push(BytesType::from(vec![0x41, 0x62, 0xf3]));

        let result = bytes.rchunks_as_collection(3);

        for (index, result_chunk) in result.iter().enumerate() {
            assert_eq!(result_chunk, expected_result.get(index).unwrap());
        }
    }

    #[test]
    fn unit_bytes_rchunks_remainder_as_collection() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut expected_result = Vec::default();
        expected_result.push(BytesType::from(vec![0x6f, 0x12, 0x0d]));
        expected_result.push(BytesType::from(vec![0xf3, 0xd3, 0x42]));
        expected_result.push(BytesType::from(vec![0x41, 0x62]));

        let result = bytes.rchunks_as_collection(3);

        for (index, result_chunk) in result.iter().enumerate() {
            assert_eq!(result_chunk, expected_result.get(index).unwrap());
        }
    }

    #[test]
    fn unit_bytes_first_n() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);
        let expected_result = vec![0x41, 0x62, 0xf3];

        let result = bytes.first_n(3).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_first_n_longer_than_original() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);
        let expected_result = vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e];

        let result = bytes.first_n(12).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_first_n_as_collection() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);
        let expected_result = BytesType::from(vec![0x41, 0x62, 0xf3]);

        let result = bytes.first_n_as_collection(3).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_first_n_as_collection_longer_than_original() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);
        let expected_result =
            BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);

        let result = bytes.first_n_as_collection(12).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_last_n() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);
        let expected_result = vec![0x12, 0x0d, 0x1e];

        let result = bytes.last_n(3).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_last_n_longer_than_original() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);
        let expected_result = vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e];

        let result = bytes.last_n(12).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_last_n_as_collection() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);
        let expected_result = BytesType::from(vec![0x12, 0x0d, 0x1e]);

        let result = bytes.last_n_as_collection(3).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_last_n_as_collection_longer_than_original() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);
        let expected_result =
            BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);

        let result = bytes.last_n_as_collection(12).unwrap();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_push_to_default() {
        let expected_result = BytesType::from(vec![0xd3, 0x42, 0x6f]);

        let mut result = BytesType::default();
        result.push(0xd3);
        result.push(0x42);
        result.push(0x6f);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_push_to_existing() {
        let expected_result = BytesType::from(vec![0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut result = BytesType::from(vec![0xd3, 0x42, 0x6f]);
        result.push(0x12);
        result.push(0x0d);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_extend_to_default() {
        let expected_result = BytesType::from(vec![0xd3, 0x42, 0x6f]);

        let mut result = BytesType::default();
        result.extend(vec![0xd3, 0x42, 0x6f]);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_extend_to_existing() {
        let expected_result = BytesType::from(vec![0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut result = BytesType::from(vec![0xd3, 0x42, 0x6f]);
        result.extend(vec![0x12, 0x0d]);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_iter() {
        let bytes = BytesType::from(vec![0xd3, 0x42, 0x6f]);
        let mut bytes_iter = bytes.iter();

        assert_eq!(bytes_iter.next(), Some(&0xd3));
        assert_eq!(bytes_iter.next(), Some(&0x42));
        assert_eq!(bytes_iter.next(), Some(&0x6f));
        assert_eq!(bytes_iter.next(), None);
    }

    #[test]
    fn unit_bytes_into_iter() {
        let bytes = BytesType::from(vec![0xd3, 0x42, 0x6f]);
        let mut bytes_iter = bytes.into_iter();

        assert_eq!(bytes_iter.next(), Some(0xd3));
        assert_eq!(bytes_iter.next(), Some(0x42));
        assert_eq!(bytes_iter.next(), Some(0x6f));
        assert_eq!(bytes_iter.next(), None);
    }

    #[test]
    fn unit_bytes_as_mut_to_switch_byte() {
        let expected_result = BytesType::from(vec![0xd3, 0xff, 0x6f]);

        let mut result = BytesType::from(vec![0xd3, 0x42, 0x6f]);
        let result_mut = result.as_mut();
        result_mut[1] = 0xff;

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_as_mut_to_extend() {
        let expected_result = BytesType::from(vec![0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut result = BytesType::from(vec![0xd3, 0x42, 0x6f]);
        let result_mut = result.as_mut();
        result_mut.extend_from_slice(&vec![0x12, 0x0d]);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_as_mut_slice_to_switch_byte() {
        let expected_result = BytesType::from(vec![0xd3, 0xff, 0x6f]);

        let mut result = BytesType::from(vec![0xd3, 0x42, 0x6f]);
        let result_mut = result.as_mut_slice();
        result_mut[1] = 0xff;

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_to_string_single_byte() {
        let bytes = BytesType::from(0xaf);
        let expected_result = String::from("Bytes[1] { af }");

        let result = bytes.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_to_string_byte_vector() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3]);
        let expected_result = String::from("Bytes[3] { 4162f3 }");

        let result = bytes.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_to_string_three_blocks() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);
        let expected_result = String::from("Bytes[9] { 4162f3d3 426f120d 1e }");

        let result = bytes.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_to_string_no_space_at_end() {
        let bytes = BytesType::from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d]);
        let expected_result = String::from("Bytes[8] { 4162f3d3 426f120d }");

        let result = bytes.to_string();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_fixed_xor_single_byte() {
        let plain = BytesType::from(0x1c);
        let key = BytesType::from(0x74);
        let expected_result = BytesType::from(0x68);

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_fixed_xor_single_byte_key() {
        let plain = BytesType::from(vec![
            0x1c, 0x01, 0x11, 0x00, 0x1f, 0xa2, 0x4b, 0x53, 0x98, 0xc5,
        ]);
        let key = BytesType::from(0x74);
        let expected_result = BytesType::from(vec![
            0x68, 0x75, 0x65, 0x74, 0x6b, 0xd6, 0x3f, 0x27, 0xec, 0xb1,
        ]);

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_fixed_xor_full_length_key() {
        let plain = BytesType::from(vec![
            0x1c, 0x01, 0x11, 0x00, 0x1f, 0x01, 0x01, 0x00, 0x06, 0x1a, 0x02, 0x4b, 0x53, 0x53,
            0x50, 0x09, 0x18, 0x1c,
        ]);
        let key = BytesType::from(vec![
            0x68, 0x69, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x62, 0x75, 0x6c, 0x6c, 0x27, 0x73,
            0x20, 0x65, 0x79, 0x65,
        ]);
        let expected_result = BytesType::from(vec![
            0x74, 0x68, 0x65, 0x20, 0x6b, 0x69, 0x64, 0x20, 0x64, 0x6f, 0x6e, 0x27, 0x74, 0x20,
            0x70, 0x6c, 0x61, 0x79,
        ]);

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_fixed_xor_key_too_long() {
        let plain = BytesType::from(vec![0x1c, 0x01, 0x11, 0x00]);
        let key = BytesType::from(vec![0x68, 0x69, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20]);
        let expected_result = BytesType::from(vec![0x74, 0x68, 0x65, 0x20]);

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_hamming_distance_single_byte() {
        // from u8
        let bytes = BytesType::from(0x02);
        // from Vec<u8>
        let other = BytesType::from(vec![0xa0]);
        let expected_result = 3;

        let result = bytes.hamming_distance(&other);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_hamming_distance_two_bytes_1() {
        let bytes = BytesType::from(vec![0x02, 0xb0]);
        let other = BytesType::from(vec![0xa0, 0x01]);
        let expected_result = 7;

        let result = bytes.hamming_distance(&other);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_hamming_distance_two_bytes_2() {
        let bytes = BytesType::from(vec![0x1d, 0x42]);
        let other = BytesType::from(vec![0x1f, 0x4d]);
        let expected_result = 5;

        let result = bytes.hamming_distance(&other);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_hamming_distance_three_bytes() {
        let bytes = BytesType::from(vec![0x1d, 0x42, 0x1f]);
        let other = BytesType::from(vec![0x4d, 0x0b, 0x0f]);
        let expected_result = 6;

        let result = bytes.hamming_distance(&other);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_hamming_distance_five_bytes() {
        let bytes = BytesType::from(vec![0x1d, 0x42, 0x1f, 0x4d, 0x0b]);
        let other = BytesType::from(vec![0x0f, 0x02, 0x1f, 0x4f, 0x13]);
        let expected_result = 6;

        let result = bytes.hamming_distance(&other);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_transpose_no_transposition() {
        let bytes = BytesType::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let keysize = 1;

        let mut expected_result = BlockBytes::new_with_lax_filling(10);
        expected_result.push(bytes.clone());

        let result = bytes.transpose(keysize);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_transpose_equal_distribution() {
        let bytes = BytesType::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let keysize = 2;

        let mut expected_result = BlockBytes::new_with_lax_filling(5);
        expected_result.push(BytesType::from(vec![1, 3, 5, 7, 9]));
        expected_result.push(BytesType::from(vec![2, 4, 6, 8, 10]));

        let result = bytes.transpose(keysize);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_transpose_unequal_distribution() {
        let bytes = BytesType::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let keysize = 3;

        let mut expected_result = BlockBytes::new_with_lax_filling(4);
        expected_result.push(BytesType::from(vec![1, 4, 7, 10]));
        expected_result.push(BytesType::from(vec![2, 5, 8]));
        expected_result.push(BytesType::from(vec![3, 6, 9]));

        let result = bytes.transpose(keysize);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_transpose_not_enough_elements() {
        let bytes = BytesType::from(vec![1, 2, 3]);
        let keysize = 4;

        let mut expected_result = BlockBytes::new_with_lax_filling(1);
        expected_result.push(BytesType::from(1));
        expected_result.push(BytesType::from(2));
        expected_result.push(BytesType::from(3));
        expected_result.push(BytesType::default());

        let result = bytes.transpose(keysize);

        assert_eq!(result, expected_result);
    }
}
