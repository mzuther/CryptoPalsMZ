use crate::crypto_vecs::traits::EncryptionOracle;
use crate::crypto_vecs::{self, BlockBytes, BytesType, traits::LenBytes};

// ================

pub struct AesSuffixEncryption {
    block_size: usize,
    key: BytesType,
    plain_suffix: BytesType,
}

// ================

impl AesSuffixEncryption {
    // move "key" and "plain_suffix" into struct so they cannot be read from calling code
    pub fn from_key(key: BytesType, plain_suffix: BytesType) -> Self {
        Self {
            block_size: key.len_bytes(),
            key,
            plain_suffix,
        }
    }

    // move "plain_suffix" into struct
    pub fn new(block_size: usize, plain_suffix: BytesType) -> Self {
        Self::from_key(BytesType::create_random_key(block_size), plain_suffix)
    }

    // move "plain_suffix" into struct
    pub fn new_bits(block_size_bits: usize, plain_suffix: BytesType) -> Self {
        let block_size = crypto_vecs::bits_to_bytes(block_size_bits);

        Self::new(block_size, plain_suffix)
    }
}

// ----------------

impl EncryptionOracle for AesSuffixEncryption {
    fn encrypt(&self, plain: &BytesType) -> Result<BlockBytes, String> {
        let mut plain_appended = plain.clone();
        plain_appended.extend(&self.plain_suffix);

        plain_appended
            .to_blocks(self.block_size)
            .aes_ecb_encrypt(&self.key)
    }
}
