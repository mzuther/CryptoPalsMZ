use openssl::{cipher, cipher_ctx};
use rand::prelude::*;
use std::{convert, slice, sync, vec};

use crate::crypto_vecs::hexadecimal::Hexadecimal;
use crate::crypto_vecs::traits::{
    AutoProbe, FromBytes, InternalData, InternalDataVec, InternalDataVecMut, LenBytes,
    Representation, ToBytes,
};
use crate::crypto_vecs::{self, Base64Type, BlockBytes, HexadecimalType, UnicodeType};

// ================

#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Bytes {
    bytes: Vec<u8>,
}

pub type BytesType = crypto_vecs::CryptoVec<Bytes, u8>;

// ================

impl InternalData for Bytes {
    type Element = u8;
    type Collection = Vec<u8>;

    fn new_from(data: Self::Collection) -> Self {
        match Self::clean_and_validate(data) {
            Ok(data) => Self { bytes: data },
            Err(error) => panic!("{}", error),
        }
    }

    fn from_literal(string_literal: &str) -> Self {
        Hexadecimal::from_literal(string_literal).to_bytes_raw()
    }

    fn with_capacity(bytes: usize) -> Self {
        Self::new_from(Vec::with_capacity(bytes))
    }

    fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    fn clean_and_validate(data: Self::Collection) -> Result<Self::Collection, String> {
        Ok(data)
    }

    // ----------------

    // iterate over bytes
    fn elements(&self) -> impl Iterator<Item = Self::Element> {
        self.bytes.iter().copied()
    }
}

// ----------------

impl InternalDataVec for Bytes {
    fn data(&self) -> &Vec<<Self as InternalData>::Element> {
        &self.bytes
    }

    fn chunks(
        &self,
        chunk_size: usize,
    ) -> slice::Chunks<'_, <Self as InternalData>::Element> {
        assert!(chunk_size > 0, "chunk size must be non-zero");

        self.bytes.chunks(chunk_size)
    }

    fn rchunks(
        &self,
        chunk_size: usize,
    ) -> slice::RChunks<'_, <Self as InternalData>::Element> {
        assert!(chunk_size > 0, "chunk size must be non-zero");

        self.bytes.rchunks(chunk_size)
    }

    // ----------------

    fn get(&self, index: usize) -> Option<&<Self as InternalData>::Element> {
        self.bytes.get(index)
    }
}

// ----------------

impl InternalDataVecMut for Bytes {
    fn data_mut(&mut self) -> &mut Vec<<Self as InternalData>::Element> {
        &mut self.bytes
    }

    fn push(&mut self, value: <Self as InternalData>::Element) {
        self.bytes.push(value)
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
    fn to_bytes_raw(&self) -> Bytes {
        self.clone()
    }

    // ----------------

    // performance (prevent round trip via trait)
    fn to_bytes(&self) -> BytesType {
        BytesType::new_from_ref(&self.bytes)
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
    const LOOKUP_BITS_IN_NIBBLE: [u32; 16] =
        [0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4];

    // ----------------

    pub fn from_hex_literal(string_literal: &str) -> Self {
        let hexadecimal = HexadecimalType::from_literal(string_literal);

        hexadecimal.to_bytes()
    }

    pub fn from_base64_literal(string_literal: &str) -> Self {
        let base64 = Base64Type::from_literal(string_literal);

        base64.to_bytes()
    }

    pub fn from_unicode_literal(string_literal: &str) -> Self {
        let unicode = UnicodeType::from_literal(string_literal);

        unicode.to_bytes()
    }

    // ----------------

    pub fn to_blocks(&self, block_size: usize) -> BlockBytes {
        assert!(block_size > 0, "block size must be non-zero");

        self.data().chunks(block_size).fold(
            BlockBytes::new(block_size),
            |mut acc, block| {
                acc.push(Self::new_from_ref(block));
                acc
            },
        )
    }

    pub fn to_blocks_bits(&self, block_size_bits: usize) -> BlockBytes {
        let block_size = crypto_vecs::bits_to_bytes(block_size_bits);

        self.to_blocks(block_size)
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
        assert_eq!(
            self.len_bytes(),
            other.len_bytes(),
            "size of blocks not equal ({} bytes <-> {} bytes)",
            self.len_bytes(),
            other.len_bytes()
        );

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

    // normalized Hamming distance (relative to total number of bits)
    //
    // 0.0: all bits are identical
    // 1.0: all bits have been inverted
    pub fn hamming_distance_normalized(&self, other: &Self) -> f64 {
        self.hamming_distance(other) as f64 / self.len_bits() as f64
    }

    // ----------------

    pub fn create_random_key(key_size: usize) -> Self {
        let mut rng = rand::rng();

        BytesType::new_from((0..key_size).map(|_| rng.random()).collect())
    }

    pub fn create_random_key_bits(key_size_bits: usize) -> Self {
        let key_size = crypto_vecs::bits_to_bytes(key_size_bits);

        BytesType::create_random_key(key_size)
    }

    pub fn affix_garbage(&self, prefix_size: usize, suffix_size: usize) -> BytesType {
        let mut bytes_extended = BytesType::create_random_key(prefix_size);
        bytes_extended.extend(self);
        bytes_extended.extend(BytesType::create_random_key(suffix_size));

        bytes_extended
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

        let mut cipher_context =
            cipher_ctx::CipherCtx::new().expect("what can go wrong?");

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

        let mut cipher_context =
            cipher_ctx::CipherCtx::new().expect("what can go wrong?");

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
        let processing_state =
            cipher_context.cipher_update_vec(self.as_slice(), buffer.as_mut());

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
        let mut transposed_blocks =
            vec![Self::with_capacity(block_size); number_of_blocks];

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

// ----------------

impl AutoProbe for BytesType {}

// ================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_vecs::base64::Base64;

    // ----------------

    #[test]
    fn unit_bytes_default() {
        let expected_result = BytesType::new_from(Vec::default());

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

        let expected_result = BytesType::new_from(expected_result_vec);

        let result = BytesType::new_from(vec![0xd3]);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_from_byte_vector() {
        // avoid "vec!" macro as this is used by the implementation
        let mut expected_result_vec = Vec::default();
        expected_result_vec.push(0x41);
        expected_result_vec.push(0x62);
        expected_result_vec.push(0x33);

        let expected_result = BytesType::new_from(expected_result_vec);

        let result = BytesType::new_from(vec![0x41, 0x62, 0x33]);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_from_hex_literal() {
        let expected_result =
            BytesType::new_from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);

        let result = BytesType::from_hex_literal("41c3bce4bda0");

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_from_base64_literal() {
        let expected_result = BytesType::new_from_ref(&Base64::COMPLETE_ALPHABET_BYTES);

        let result = BytesType::from_base64_literal(Base64::COMPLETE_ALPHABET);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_from_unicode_literal() {
        let expected_result =
            BytesType::new_from(vec![0x41, 0xc3, 0xbc, 0xe4, 0xbd, 0xa0]);

        let result = BytesType::from_unicode_literal("Aü你");

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_to_codepage_1252_ascii() {
        let bytes = BytesType::new_from(vec![0x41, 0x62, 0x33]);
        let expected_result = String::from("Ab3");

        let result = bytes.to_codepage_1252();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_to_codepage_1252_unicode() {
        let bytes = BytesType::new_from(vec![
            0x46, 0x72, 0xc3, 0xbc, 0x68, 0x6a, 0x61, 0x68, 0x72,
        ]);
        let expected_result = String::from("FrÃ¼hjahr");

        let result = bytes.to_codepage_1252();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_to_codepage_1252_unicode_string() {
        let unicode = UnicodeType::from_literal("\n Hi. Servus. Grüezi. 你好.\t");
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
        let bytes = BytesType::new_from(vec![0xd3]);

        let expected_result = 1;

        let result = bytes.len_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_len_bytes_several_bytes() {
        let bytes = BytesType::new_from(vec![0x41, 0x62, 0x33]);

        let expected_result = 3;

        let result = bytes.len_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_chunks() {
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0xff,
        ]);

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
        let bytes =
            BytesType::new_from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d]);

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
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0xff,
        ]);

        let mut expected_result = Vec::default();
        expected_result.push(BytesType::new_from(vec![0x41, 0x62, 0xf3]));
        expected_result.push(BytesType::new_from(vec![0xd3, 0x42, 0x6f]));
        expected_result.push(BytesType::new_from(vec![0x12, 0x0d, 0xff]));

        let result = bytes.chunks_as_collection(3);

        for (index, result_chunk) in result.iter().enumerate() {
            assert_eq!(result_chunk, expected_result.get(index).unwrap());
        }
    }

    #[test]
    fn unit_bytes_chunks_remainder_as_collection() {
        let bytes =
            BytesType::new_from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut expected_result = Vec::default();
        expected_result.push(BytesType::new_from(vec![0x41, 0x62, 0xf3]));
        expected_result.push(BytesType::new_from(vec![0xd3, 0x42, 0x6f]));
        expected_result.push(BytesType::new_from(vec![0x12, 0x0d]));

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
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0xff,
        ]);

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
        let bytes =
            BytesType::new_from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d]);

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
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0xff,
        ]);

        let mut expected_result = Vec::default();
        expected_result.push(BytesType::new_from(vec![0x12, 0x0d, 0xff]));
        expected_result.push(BytesType::new_from(vec![0xd3, 0x42, 0x6f]));
        expected_result.push(BytesType::new_from(vec![0x41, 0x62, 0xf3]));

        let result = bytes.rchunks_as_collection(3);

        for (index, result_chunk) in result.iter().enumerate() {
            assert_eq!(result_chunk, expected_result.get(index).unwrap());
        }
    }

    #[test]
    fn unit_bytes_rchunks_remainder_as_collection() {
        let bytes =
            BytesType::new_from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut expected_result = Vec::default();
        expected_result.push(BytesType::new_from(vec![0x6f, 0x12, 0x0d]));
        expected_result.push(BytesType::new_from(vec![0xf3, 0xd3, 0x42]));
        expected_result.push(BytesType::new_from(vec![0x41, 0x62]));

        let result = bytes.rchunks_as_collection(3);

        for (index, result_chunk) in result.iter().enumerate() {
            assert_eq!(result_chunk, expected_result.get(index).unwrap());
        }
    }

    #[test]
    fn unit_bytes_take_n() {
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);
        let expected_result = vec![0x41, 0x62, 0xf3];

        let result = bytes.take_n(3).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_take_n_longer_than_original() {
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);
        let expected_result = vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e];

        let result = bytes.take_n(12).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_take_n_as_collection() {
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);
        let expected_result = BytesType::new_from(vec![0x41, 0x62, 0xf3]);

        let result = bytes.take_n_as_collection(3).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_take_n_as_collection_longer_than_original() {
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);
        let expected_result = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);

        let result = bytes.take_n_as_collection(12).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_skip_n() {
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);
        let expected_result = vec![0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e];

        let result = bytes.skip_n(3).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_skip_n_longer_than_original() {
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);

        let expected_result = None;

        let result = bytes.skip_n(12);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_skip_n_as_collection() {
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);
        let expected_result =
            BytesType::new_from(vec![0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e]);

        let result = bytes.skip_n_as_collection(3).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_skip_n_as_collection_longer_than_original() {
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);
        let expected_result = None;

        let result = bytes.skip_n_as_collection(12);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_rtake_n() {
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);
        let expected_result = vec![0x12, 0x0d, 0x1e];

        let result = bytes.rtake_n(3).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_rtake_n_longer_than_original() {
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);
        let expected_result = vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e];

        let result = bytes.rtake_n(12).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_rtake_n_as_collection() {
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);
        let expected_result = BytesType::new_from(vec![0x12, 0x0d, 0x1e]);

        let result = bytes.rtake_n_as_collection(3).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_rtake_n_as_collection_longer_than_original() {
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);
        let expected_result = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);

        let result = bytes.rtake_n_as_collection(12).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_rskip_n() {
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);
        let expected_result = vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f];

        let result = bytes.rskip_n(3).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_rskip_n_longer_than_original() {
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);
        let expected_result = None;

        let result = bytes.rskip_n(12);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_rskip_n_as_collection() {
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);
        let expected_result =
            BytesType::new_from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f]);

        let result = bytes.rskip_n_as_collection(3).unwrap();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_rskip_n_as_collection_longer_than_original() {
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);
        let expected_result = None;

        let result = bytes.rskip_n_as_collection(12);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_push_to_default() {
        let expected_result = BytesType::new_from(vec![0xd3, 0x42, 0x6f]);

        let mut result = BytesType::default();
        result.push(0xd3);
        result.push(0x42);
        result.push(0x6f);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_push_to_existing() {
        let expected_result = BytesType::new_from(vec![0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut result = BytesType::new_from(vec![0xd3, 0x42, 0x6f]);
        result.push(0x12);
        result.push(0x0d);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_extend_to_default() {
        let expected_result = BytesType::new_from(vec![0xd3, 0x42, 0x6f]);

        let mut result = BytesType::default();
        result.extend(vec![0xd3, 0x42, 0x6f]);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_extend_to_existing() {
        let expected_result = BytesType::new_from(vec![0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut result = BytesType::new_from(vec![0xd3, 0x42, 0x6f]);
        result.extend(vec![0x12, 0x0d]);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_iter() {
        let bytes = BytesType::new_from(vec![0xd3, 0x42, 0x6f]);
        let mut bytes_iter = bytes.iter();

        assert_eq!(bytes_iter.next(), Some(&0xd3));
        assert_eq!(bytes_iter.next(), Some(&0x42));
        assert_eq!(bytes_iter.next(), Some(&0x6f));
        assert_eq!(bytes_iter.next(), None);
    }

    #[test]
    fn unit_bytes_into_iter() {
        let bytes = BytesType::new_from(vec![0xd3, 0x42, 0x6f]);
        let mut bytes_iter = bytes.into_iter();

        assert_eq!(bytes_iter.next(), Some(0xd3));
        assert_eq!(bytes_iter.next(), Some(0x42));
        assert_eq!(bytes_iter.next(), Some(0x6f));
        assert_eq!(bytes_iter.next(), None);
    }

    #[test]
    fn unit_bytes_as_mut_to_switch_byte() {
        let expected_result = BytesType::new_from(vec![0xd3, 0xff, 0x6f]);

        let mut result = BytesType::new_from(vec![0xd3, 0x42, 0x6f]);
        let result_mut = result.as_mut();
        result_mut[1] = 0xff;

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_as_mut_to_extend() {
        let expected_result = BytesType::new_from(vec![0xd3, 0x42, 0x6f, 0x12, 0x0d]);

        let mut result = BytesType::new_from(vec![0xd3, 0x42, 0x6f]);
        let result_mut = result.as_mut();
        result_mut.extend_from_slice(&vec![0x12, 0x0d]);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_as_mut_slice_to_switch_byte() {
        let expected_result = BytesType::new_from(vec![0xd3, 0xff, 0x6f]);

        let mut result = BytesType::new_from(vec![0xd3, 0x42, 0x6f]);
        let result_mut = result.as_mut_slice();
        result_mut[1] = 0xff;

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_to_string_single_byte() {
        let bytes = BytesType::new_from(vec![0xaf]);
        let expected_result = String::from("Bytes[01] { af }");

        let result = bytes.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_to_string_byte_vector() {
        let bytes = BytesType::new_from(vec![0x41, 0x62, 0xf3]);
        let expected_result = String::from("Bytes[03] { 4162f3 }");

        let result = bytes.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_to_string_three_blocks() {
        let bytes = BytesType::new_from(vec![
            0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d, 0x1e,
        ]);
        let expected_result = String::from("Bytes[09] { 4162f3d3 426f120d 1e }");

        let result = bytes.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_to_string_no_space_at_end() {
        let bytes =
            BytesType::new_from(vec![0x41, 0x62, 0xf3, 0xd3, 0x42, 0x6f, 0x12, 0x0d]);
        let expected_result = String::from("Bytes[08] { 4162f3d3 426f120d }");

        let result = bytes.to_string();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_fixed_xor_single_byte() {
        let plain = BytesType::new_from(vec![0x1c]);
        let key = BytesType::new_from(vec![0x74]);
        let expected_result = BytesType::new_from(vec![0x68]);

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_fixed_xor_single_byte_key() {
        let plain = BytesType::new_from(vec![
            0x1c, 0x01, 0x11, 0x00, 0x1f, 0xa2, 0x4b, 0x53, 0x98, 0xc5,
        ]);
        let key = BytesType::new_from(vec![0x74]);
        let expected_result = BytesType::new_from(vec![
            0x68, 0x75, 0x65, 0x74, 0x6b, 0xd6, 0x3f, 0x27, 0xec, 0xb1,
        ]);

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_fixed_xor_full_length_key() {
        let plain = BytesType::new_from(vec![
            0x1c, 0x01, 0x11, 0x00, 0x1f, 0x01, 0x01, 0x00, 0x06, 0x1a, 0x02, 0x4b, 0x53,
            0x53, 0x50, 0x09, 0x18, 0x1c,
        ]);
        let key = BytesType::new_from(vec![
            0x68, 0x69, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x62, 0x75, 0x6c, 0x6c, 0x27,
            0x73, 0x20, 0x65, 0x79, 0x65,
        ]);
        let expected_result = BytesType::new_from(vec![
            0x74, 0x68, 0x65, 0x20, 0x6b, 0x69, 0x64, 0x20, 0x64, 0x6f, 0x6e, 0x27, 0x74,
            0x20, 0x70, 0x6c, 0x61, 0x79,
        ]);

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_fixed_xor_key_too_long() {
        let plain = BytesType::new_from(vec![0x1c, 0x01, 0x11, 0x00]);
        let key =
            BytesType::new_from(vec![0x68, 0x69, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20]);
        let expected_result = BytesType::new_from(vec![0x74, 0x68, 0x65, 0x20]);

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_hamming_distance_single_byte() {
        let bytes = BytesType::new_from(vec![0x02]);
        let other = BytesType::new_from(vec![0xa0]);

        let expected_result = 3;
        let expected_result_normalized = 0.375;

        let result = bytes.hamming_distance(&other);
        let result_normalized = bytes.hamming_distance_normalized(&other);

        assert_eq!(result, expected_result);
        assert_eq!(result_normalized, expected_result_normalized);
    }

    #[test]
    fn unit_bytes_hamming_distance_two_bytes_1() {
        let bytes = BytesType::from_hex_literal("02b0");
        let other = BytesType::from_hex_literal("a001");

        let expected_result = 7;
        let expected_result_normalized = 0.4375;

        let result = bytes.hamming_distance(&other);
        let result_normalized = bytes.hamming_distance_normalized(&other);

        assert_eq!(result, expected_result);
        assert_eq!(result_normalized, expected_result_normalized);
    }

    #[test]
    fn unit_bytes_hamming_distance_two_bytes_2() {
        let bytes = BytesType::from_hex_literal("1d42");
        let other = BytesType::from_hex_literal("1f4d");

        let expected_result = 5;
        let expected_result_normalized = 0.3125;

        let result = bytes.hamming_distance(&other);
        let result_normalized = bytes.hamming_distance_normalized(&other);

        assert_eq!(result, expected_result);
        assert_eq!(result_normalized, expected_result_normalized);
    }

    #[test]
    fn unit_bytes_hamming_distance_three_bytes() {
        let bytes = BytesType::from_hex_literal("1d421f");
        let other = BytesType::from_hex_literal("4d0b0f");

        let expected_result = 6;
        let expected_result_normalized = 0.25;

        let result = bytes.hamming_distance(&other);
        let result_normalized = bytes.hamming_distance_normalized(&other);

        assert_eq!(result, expected_result);
        assert_eq!(result_normalized, expected_result_normalized);
    }

    #[test]
    fn unit_bytes_hamming_distance_five_bytes_1() {
        let bytes = BytesType::from_hex_literal("1d421f4d0b");
        let other = BytesType::from_hex_literal("0f021f4f13");

        let expected_result = 6;
        let expected_result_normalized = 0.15;

        let result = bytes.hamming_distance(&other);
        let result_normalized = bytes.hamming_distance_normalized(&other);

        assert_eq!(result, expected_result);
        assert_eq!(result_normalized, expected_result_normalized);
    }

    #[test]
    fn unit_bytes_hamming_distance_five_bytes_2() {
        let bytes = BytesType::from_hex_literal("0f021f4f13");
        let other = BytesType::from_hex_literal("4e3f78120a");

        let expected_result = 20;
        let expected_result_normalized = 0.5;

        let result = bytes.hamming_distance(&other);
        let result_normalized = bytes.hamming_distance_normalized(&other);

        assert_eq!(result, expected_result);
        assert_eq!(result_normalized, expected_result_normalized);
    }

    #[test]
    #[should_panic(expected = "size of blocks not equal")]
    fn unit_bytes_hamming_distance_unequal_size() {
        let bytes = BytesType::from_hex_literal("1d421f4d0b");
        let other = BytesType::from_hex_literal("0f021f4f");

        let _ = bytes.hamming_distance(&other);
    }

    // ----------------

    #[test]
    fn unit_bytes_create_random_key_length() {
        let key_size = 16;

        let bytes_key = BytesType::create_random_key(key_size);

        assert_eq!(bytes_key.len_bytes(), key_size);
    }

    #[test]
    fn unit_bytes_create_random_key_different() {
        let key_size = 16;

        let bytes_key = BytesType::create_random_key(key_size);
        let other_key = BytesType::create_random_key(key_size);

        assert_ne!(bytes_key, other_key);
        assert_eq!(bytes_key.len_bytes(), other_key.len_bytes());
    }

    #[test]
    fn unit_bytes_create_random_key_bits_length() {
        let key_size_bits = 256;

        let bytes_key = BytesType::create_random_key_bits(key_size_bits);

        assert_eq!(bytes_key.len_bits(), key_size_bits);
    }

    #[test]
    fn unit_bytes_create_random_key_bits_different() {
        let key_size_bits = 256;

        let bytes_key = BytesType::create_random_key_bits(key_size_bits);
        let other_key = BytesType::create_random_key_bits(key_size_bits);

        assert_ne!(bytes_key, other_key);
        assert_eq!(bytes_key.len_bits(), other_key.len_bits());
    }

    #[test]
    fn unit_bytes_affix_garbage() {
        let prefix_size = 2;
        let suffix_size = 9;
        let bytes = BytesType::new_from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        let result = bytes.affix_garbage(prefix_size, suffix_size);

        assert_eq!(
            result
                .rtake_n_as_collection(10 + suffix_size)
                .unwrap()
                .take_n_as_collection(10)
                .unwrap(),
            bytes
        );

        assert_eq!(
            result.len_bytes(),
            bytes.len_bytes() + prefix_size + suffix_size
        );
    }

    #[test]
    fn unit_bytes_affix_garbage_prefix() {
        let prefix_size = 5;
        let bytes = BytesType::new_from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        let result = bytes.affix_garbage(prefix_size, 0);

        assert_eq!(result.rtake_n_as_collection(10).unwrap(), bytes);
        assert_eq!(result.len_bytes(), bytes.len_bytes() + prefix_size);
    }

    #[test]
    fn unit_bytes_affix_garbage_suffix() {
        let suffix_size = 4;
        let bytes = BytesType::new_from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        let result = bytes.affix_garbage(0, suffix_size);

        assert_eq!(result.take_n_as_collection(10).unwrap(), bytes);
        assert_eq!(result.len_bytes(), bytes.len_bytes() + suffix_size);
    }

    #[test]
    fn unit_bytes_affix_garbag_different() {
        let bytes = BytesType::new_from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        let affixed_1 = bytes.affix_garbage(3, 6);
        let affixed_2 = bytes.affix_garbage(3, 6);

        assert_ne!(affixed_1, affixed_2);
        assert_eq!(affixed_1.len_bytes(), affixed_2.len_bytes());
    }

    // ----------------

    #[test]
    fn unit_bytes_transpose_no_transposition() {
        let bytes = BytesType::new_from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let keysize = 1;

        let mut expected_result = BlockBytes::new_with_lax_filling(10);
        expected_result.push(bytes.clone());

        let result = bytes.transpose(keysize);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_transpose_equal_distribution() {
        let bytes = BytesType::new_from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let keysize = 2;

        let mut expected_result = BlockBytes::new_with_lax_filling(5);
        expected_result.push(BytesType::new_from(vec![1, 3, 5, 7, 9]));
        expected_result.push(BytesType::new_from(vec![2, 4, 6, 8, 10]));

        let result = bytes.transpose(keysize);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_transpose_unequal_distribution() {
        let bytes = BytesType::new_from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let keysize = 3;

        let mut expected_result = BlockBytes::new_with_lax_filling(4);
        expected_result.push(BytesType::new_from(vec![1, 4, 7, 10]));
        expected_result.push(BytesType::new_from(vec![2, 5, 8]));
        expected_result.push(BytesType::new_from(vec![3, 6, 9]));

        let result = bytes.transpose(keysize);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_bytes_transpose_not_enough_elements() {
        let bytes = BytesType::new_from(vec![1, 2, 3]);
        let keysize = 4;

        let mut expected_result = BlockBytes::new_with_lax_filling(1);
        expected_result.push(BytesType::new_from(vec![1]));
        expected_result.push(BytesType::new_from(vec![2]));
        expected_result.push(BytesType::new_from(vec![3]));
        expected_result.push(BytesType::default());

        let result = bytes.transpose(keysize);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_bytes_new_auto_probe_expanding() {
        let final_probe =
            BytesType::from_hex_literal("00010203 04050607 08090a0b 0c0d0e0f");
        let size_start = 0;
        let is_expanding = true;

        let mut auto_probe =
            BytesType::new_auto_probe(final_probe.clone(), size_start, is_expanding);

        assert_eq!(auto_probe.next(), Some(Default::default()));

        for current_size in 1..=final_probe.len_bytes() {
            assert_eq!(
                auto_probe.next(),
                final_probe.take_n_as_collection(current_size)
            );
        }

        assert_eq!(auto_probe.next(), None);
    }

    #[test]
    fn unit_bytes_new_auto_probe_expanding_initial_size() {
        let final_probe =
            BytesType::from_hex_literal("00010203 04050607 08090a0b 0c0d0e0f");
        let size_start = 2;
        let is_expanding = true;

        let mut auto_probe =
            BytesType::new_auto_probe(final_probe.clone(), size_start, is_expanding);

        for current_size in 2..=final_probe.len_bytes() {
            assert_eq!(
                auto_probe.next(),
                final_probe.take_n_as_collection(current_size)
            );
        }

        assert_eq!(auto_probe.next(), None);
    }

    #[test]
    fn unit_bytes_new_auto_probe_shrinking() {
        let final_probe =
            BytesType::from_hex_literal("00010203 04050607 08090a0b 0c0d0e0f");
        let size_start = 0;
        let is_expanding = false;

        let mut auto_probe =
            BytesType::new_auto_probe(final_probe.clone(), size_start, is_expanding);

        for current_size in (1..=final_probe.len_bytes()).rev() {
            assert_eq!(
                auto_probe.next(),
                final_probe.take_n_as_collection(current_size)
            );
        }

        assert_eq!(auto_probe.next(), Some(Default::default()));
        assert_eq!(auto_probe.next(), None);
    }

    #[test]
    fn unit_bytes_new_auto_probe_shrinking_final_size() {
        let final_probe =
            BytesType::from_hex_literal("00010203 04050607 08090a0b 0c0d0e0f");
        let size_start = 2;
        let is_expanding = false;

        let mut auto_probe =
            BytesType::new_auto_probe(final_probe.clone(), size_start, is_expanding);

        for current_size in (size_start..=final_probe.len_bytes()).rev() {
            assert_eq!(
                auto_probe.next(),
                final_probe.take_n_as_collection(current_size)
            );
        }

        assert_eq!(auto_probe.next(), None);
    }

    #[test]
    fn unit_bytes_new_auto_probe_repeat_expanding_initial_size() {
        let element = b'A';
        let size_start = 2;
        let size_end = 16;

        let mut auto_probe =
            BytesType::new_auto_probe_repeat(element, size_start, size_end);
        let expected_final_probe = BytesType::new_from(vec![element; size_end]);

        for current_size in size_start..=size_end {
            assert_eq!(
                auto_probe.next(),
                expected_final_probe.take_n_as_collection(current_size)
            );
        }

        assert_eq!(auto_probe.next(), None);
    }

    #[test]
    fn unit_bytes_new_auto_probe_repeat_shrinking_final_size() {
        let element = b'A';
        let size_start = 16;
        let size_end = 2;

        let mut auto_probe =
            BytesType::new_auto_probe_repeat(element, size_start, size_end);
        let expected_final_probe = BytesType::new_from(vec![element; size_start]);

        for current_size in (size_end..=size_start).rev() {
            assert_eq!(
                auto_probe.next(),
                expected_final_probe.take_n_as_collection(current_size)
            );
        }

        assert_eq!(auto_probe.next(), None);
    }

    #[test]
    fn unit_bytes_new_auto_probe_mover_single_byte() {
        let original_probe = BytesType::from_hex_literal("00010203");
        let moving_part = BytesType::from_hex_literal("ff");

        let mut auto_probe = BytesType::new_auto_probe_mover(original_probe, moving_part);

        assert_eq!(
            auto_probe.next(),
            Some(BytesType::from_hex_literal("ff00010203"))
        );

        assert_eq!(
            auto_probe.next(),
            Some(BytesType::from_hex_literal("00ff010203"))
        );

        assert_eq!(
            auto_probe.next(),
            Some(BytesType::from_hex_literal("0001ff0203"))
        );

        assert_eq!(
            auto_probe.next(),
            Some(BytesType::from_hex_literal("000102ff03"))
        );

        assert_eq!(
            auto_probe.next(),
            Some(BytesType::from_hex_literal("00010203ff"))
        );

        assert_eq!(auto_probe.next(), None);
    }

    #[test]
    fn unit_bytes_new_auto_probe_mover_multiple_bytes() {
        let original_probe = BytesType::from_hex_literal("00010203");
        let moving_part = BytesType::from_hex_literal("effe");

        let mut auto_probe = BytesType::new_auto_probe_mover(original_probe, moving_part);

        assert_eq!(
            auto_probe.next(),
            Some(BytesType::from_hex_literal("effe00010203"))
        );

        assert_eq!(
            auto_probe.next(),
            Some(BytesType::from_hex_literal("00effe010203"))
        );

        assert_eq!(
            auto_probe.next(),
            Some(BytesType::from_hex_literal("0001effe0203"))
        );

        assert_eq!(
            auto_probe.next(),
            Some(BytesType::from_hex_literal("000102effe03"))
        );

        assert_eq!(
            auto_probe.next(),
            Some(BytesType::from_hex_literal("00010203effe"))
        );

        assert_eq!(auto_probe.next(), None);
    }
}
