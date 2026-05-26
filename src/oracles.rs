/* ----------------------------------------------------------------------------

   CryptoPalsMZ
   ============
   My take on https://cryptopals.com/

   Copyright (c) 2026 Martin Zuther (http://www.mzuther.de/)

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

   Thank you for using free software!

---------------------------------------------------------------------------- */

use crate::constants;
use crate::crypto_vecs::traits::{DecryptionOracle, EncryptionOracle, LenBytes, ToBytes};
use crate::crypto_vecs::{self, ByteBlocks, Bytes};

// ----------------

use rand::prelude::*;

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

pub struct AesEcbDetection {
    block_size: usize,
    key: Bytes,
}

// ----------------

impl AesEcbDetection {
    // move "key" into struct so it cannot be read from calling code
    pub fn from_key(key: Bytes) -> Self {
        Self {
            block_size: key.len_bytes(),
            key,
        }
    }

    pub fn new(block_size: usize) -> Self {
        Self::from_key(Bytes::create_random_key(block_size))
    }

    pub fn new_bits(block_size_bits: usize) -> Self {
        let block_size = crypto_vecs::bits_to_bytes(block_size_bits);

        Self::new(block_size)
    }
}

// ----------------

impl EncryptionOracle<constants::AesMode> for AesEcbDetection {
    fn encrypt(&self, plain: Bytes) -> OracleResponse<ByteBlocks, constants::AesMode> {
        let mut rng = rand::rng();

        let plain_padded_blocks = plain
            .affix_garbage(rng.random_range(5..=10), rng.random_range(5..=10))
            .to_blocks(self.block_size);

        // use ECB mode in 50% of the cases
        if rng.random() {
            OracleResponse {
                response: plain_padded_blocks.aes_ecb_encrypt(&self.key),
                hint: Some(constants::AesMode::ECB),
            }
        } else {
            let initialization_vector = Bytes::create_random_key(self.block_size);

            OracleResponse {
                response: plain_padded_blocks
                    .aes_cbc_encrypt(&self.key, &initialization_vector),
                hint: Some(constants::AesMode::NonECB),
            }
        }
    }
}

// ================

pub struct AesEcbSuffix {
    block_size: usize,
    key: Bytes,
    plain_suffix: Bytes,
}

// ----------------

impl AesEcbSuffix {
    // move "key" and "plain_suffix" into struct so they cannot be read from calling code
    pub fn from_key(key: Bytes, plain_suffix: Bytes) -> Self {
        Self {
            block_size: key.len_bytes(),
            key,
            plain_suffix,
        }
    }

    // move "plain_suffix" into struct
    pub fn new(block_size: usize, plain_suffix: Bytes) -> Self {
        Self::from_key(Bytes::create_random_key(block_size), plain_suffix)
    }

    // move "plain_suffix" into struct
    pub fn new_bits(block_size_bits: usize, plain_suffix: Bytes) -> Self {
        let block_size = crypto_vecs::bits_to_bytes(block_size_bits);

        Self::new(block_size, plain_suffix)
    }
}

// ----------------

impl EncryptionOracle<()> for AesEcbSuffix {
    fn encrypt(&self, mut plain: Bytes) -> OracleResponse<ByteBlocks, ()> {
        plain.extend(&self.plain_suffix);

        OracleResponse {
            response: plain.to_blocks(self.block_size).aes_ecb_encrypt(&self.key),
            hint: None,
        }
    }
}

// ================

pub struct AesEcbCookieCutter {
    block_size: usize,
    key: Bytes,
}

// ----------------

impl AesEcbCookieCutter {
    // move "key" into struct so it cannot be read from calling code
    pub fn from_key(key: Bytes) -> Self {
        Self {
            block_size: key.len_bytes(),
            key,
        }
    }

    pub fn new(block_size: usize) -> Self {
        Self::from_key(Bytes::create_random_key(block_size))
    }

    // move "plain_suffix" into struct
    pub fn new_bits(block_size_bits: usize) -> Self {
        let block_size = crypto_vecs::bits_to_bytes(block_size_bits);

        Self::new(block_size)
    }

    // ----------------

    fn profile_for(&self, email_address: &str) -> Option<String> {
        if email_address.contains("&") || email_address.contains("=") {
            None
        } else {
            let user_id = 10;
            let role = "user";

            Some(format!(
                "email={}&uid={}&role={}",
                email_address, user_id, role
            ))
        }
    }

    pub fn parse_key_value_cookie(
        &self,
        cookie: &str,
    ) -> Result<serde_json::Value, String> {
        // using "serde_json" to parse the cookie would make much more sense,
        // but the challenge explicitly asks for writing the parsing code
        let json_chunks = cookie
            // iterate over key-value pairs
            .split("&")
            .map(|chunk| {
                let (key, value) = chunk.split_once("=")?;

                if key.is_empty() || value.is_empty() || value.contains("=") {
                    None
                } else {
                    Some(format!("\"{}\": \"{}\"", key, value))
                }
            });

        if json_chunks.clone().any(|chunk| chunk.is_none()) {
            Err(String::from("found invalid data"))
        } else {
            serde_json::from_str(&format!(
                "{{ {} }}",
                json_chunks
                    .map(|chunk| chunk.expect("cannot be None"))
                    .collect::<Vec<String>>()
                    .join(", ")
            ))
            .map_err(|err| err.to_string())
        }
    }
}

// ----------------

impl EncryptionOracle<()> for AesEcbCookieCutter {
    fn encrypt(&self, email_address: Bytes) -> OracleResponse<ByteBlocks, ()> {
        let email_address_string = self.profile_for(email_address.to_unicode().as_ref());

        OracleResponse {
            response: match email_address_string {
                Some(x) => Bytes::from_unicode_literal(&x)
                    .to_blocks(self.block_size)
                    .aes_ecb_encrypt(&self.key),
                None => Ok(ByteBlocks::new(self.block_size)),
            },
            hint: None,
        }
    }
}

// ----------------

impl DecryptionOracle<ByteBlocks, ()> for AesEcbCookieCutter {
    fn decrypt(&self, cypher: &Bytes) -> self::OracleResponse<ByteBlocks, ()> {
        let plain = cypher.to_blocks(self.block_size).aes_ecb_decrypt(&self.key);

        OracleResponse {
            response: match plain {
                Ok(x) => Ok(x),
                Err(_) => Ok(ByteBlocks::new(self.block_size)),
            },

            hint: None,
        }
    }
}
