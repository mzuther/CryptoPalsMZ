use crate::crypto_vecs::traits::EncryptionOracle;
use crate::crypto_vecs::{self, BlockBytes, BytesType, traits::LenBytes};

// ================

pub struct OracleResponse<R, H> {
    response: Result<R, String>,
    hint: Option<H>,
}

// ================

impl<R, H> OracleResponse<R, H> {
    pub fn response(&self) -> &Result<R, String> {
        &self.response
    }

    pub fn expect(&self, msg: &str) -> &R {
        self.response.as_ref().expect(msg)
    }

    pub fn unwrap(&self) -> &R {
        self.response.as_ref().unwrap()
    }

    pub fn has_hint(&self) -> bool {
        self.hint.is_some()
    }

    pub fn hint(&self) -> &Option<H> {
        &self.hint
    }

    pub fn unwrap_hint(&self) -> &H {
        self.hint.as_ref().unwrap()
    }
}

// ================

pub struct AesSuffixEncryption {
    block_size: usize,
    key: BytesType,
    plain_suffix: BytesType,
}

// ----------------

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

impl EncryptionOracle<()> for AesSuffixEncryption {
    fn encrypt(&self, mut plain: BytesType) -> OracleResponse<BlockBytes, ()> {
        plain.extend(&self.plain_suffix);

        OracleResponse {
            response: plain.to_blocks(self.block_size).aes_ecb_encrypt(&self.key),
            hint: None,
        }
    }
}
