use std::{iter, slice};

use crate::crypto_vecs::{self, Base64Type, BlockBytes, BytesType, HexadecimalType, UnicodeType};
use crate::oracles;

// ================

pub trait InternalData {
    type Collection;

    fn new_from(data: Self::Collection) -> Self;
    fn with_capacity(capacity: usize) -> Self;

    fn capacity(&self) -> usize;
    fn clean_and_validate(data: Self::Collection) -> Result<Self::Collection, String>;

    // ----------------

    fn with_capacity_bits(capacity_bits: usize) -> Self
    where
        Self: Sized,
    {
        let capacity = crypto_vecs::bits_to_bytes(capacity_bits);

        Self::with_capacity(capacity)
    }
}

pub trait InternalDataVec
where
    Self: Sized + InternalData<Collection = Vec<Self::Element>> + LenBytes,
    Self::Element: Clone,
{
    type Element;

    fn data(&self) -> &Vec<Self::Element>;
    fn chunks(&self, chunk_size: usize) -> slice::Chunks<'_, Self::Element>;
    fn rchunks(&self, chunk_size: usize) -> slice::RChunks<'_, Self::Element>;

    fn get(&self, index: usize) -> Option<&Self::Element>;

    // ----------------

    fn new_from_ref(data: &[Self::Element]) -> Self {
        Self::new_from(data.to_vec())
    }

    // clone of underlying collection
    fn to_vec(&self) -> Vec<Self::Element> {
        self.data().to_vec()
    }

    // reference to underlying collection
    fn as_slice(&self) -> &[Self::Element] {
        self.data().as_slice()
    }

    // ----------------

    fn take_n(&self, length: usize) -> Option<&[Self::Element]> {
        if self.len_bytes() <= length {
            Some(self.as_slice())
        } else {
            self.chunks(length).next()
        }
    }

    fn skip_n(&self, length: usize) -> Option<&[Self::Element]> {
        if length == 0 {
            Some(self.as_slice())
        } else if length >= self.len_bytes() {
            None
        } else {
            self.rchunks(self.len_bytes() - length).next()
        }
    }

    fn rtake_n(&self, length: usize) -> Option<&[Self::Element]> {
        if self.len_bytes() <= length {
            Some(self.as_slice())
        } else {
            self.rchunks(length).next()
        }
    }

    fn rskip_n(&self, length: usize) -> Option<&[Self::Element]> {
        if length == 0 {
            Some(self.as_slice())
        } else if length >= self.len_bytes() {
            None
        } else {
            self.chunks(self.len_bytes() - length).next()
        }
    }

    // ----------------

    fn chunks_as_collection(&self, chunk_size: usize) -> Vec<Self> {
        self.chunks(chunk_size)
            .map(|chunk| Self::new_from_ref(chunk))
            .collect()
    }

    fn rchunks_as_collection(&self, chunk_size: usize) -> Vec<Self> {
        self.rchunks(chunk_size)
            .map(|chunk| Self::new_from_ref(chunk))
            .collect()
    }

    fn take_n_as_collection(&self, length: usize) -> Option<Self> {
        self.take_n(length)
            .map(|element| Self::new_from_ref(element))
    }

    fn skip_n_as_collection(&self, length: usize) -> Option<Self> {
        self.skip_n(length)
            .map(|element| Self::new_from_ref(element))
    }

    fn rtake_n_as_collection(&self, length: usize) -> Option<Self> {
        self.rtake_n(length)
            .map(|element| Self::new_from_ref(element))
    }

    fn rskip_n_as_collection(&self, length: usize) -> Option<Self> {
        self.rskip_n(length)
            .map(|element| Self::new_from_ref(element))
    }
}

pub trait InternalDataVecMut {
    type Element;

    fn data_mut(&mut self) -> &mut Vec<Self::Element>;

    fn push(&mut self, value: Self::Element);

    // ----------------

    fn as_mut_slice(&mut self) -> &mut [Self::Element] {
        self.data_mut().as_mut_slice()
    }
}

// ----------------

// iterate over / count logical elements (String or char)
pub trait Elements {
    type Element;

    fn elements(&self) -> impl Iterator<Item = Self::Element>;

    // ----------------

    fn to_elements(&self) -> Vec<Self::Element> {
        self.elements().collect::<Vec<Self::Element>>()
    }

    fn len(&self) -> usize {
        self.elements().count()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ----------------

pub trait Representation {
    fn representation_name(&self) -> &str;
    fn representation(&self) -> String;
}

// ----------------

pub trait LenBytes {
    fn len_bytes(&self) -> usize;

    // ----------------

    fn len_bits(&self) -> usize {
        self.len_bytes() * 8
    }
}

// ----------------

pub trait FromBytes {
    fn from_bytes(bytes: &BytesType) -> Self;
}

// ----------------

pub trait ToBytes {
    fn to_bytes(&self) -> self::BytesType;

    // ----------------

    fn to_hexadecimal(&self) -> self::HexadecimalType {
        self::HexadecimalType::from(&self.to_bytes())
    }

    fn to_base64(&self) -> self::Base64Type {
        self::Base64Type::from(&self.to_bytes())
    }

    fn to_unicode(&self) -> self::UnicodeType {
        self::UnicodeType::from(&self.to_bytes())
    }
}

// ================

pub trait AutoProbe<E>
where
    Self: InternalDataVec<Element = E>,
{
    fn new_auto_probe(
        item: E,
        size_start: usize,
        size_end: usize,
    ) -> iter::FromFn<impl FnMut() -> Option<Self>>
    where
        Self: Sized,
        E: Clone,
    {
        let is_expanding = size_start < size_end;

        let mut current_counter = size_start.min(size_end);
        let counter_end = size_start.max(size_end);

        std::iter::from_fn(move || {
            if current_counter <= counter_end {
                let result = Some(Self::new_from(vec![
                    item.clone();
                    if is_expanding {
                        current_counter
                    } else {
                        counter_end - current_counter
                    }
                ]));
                current_counter += 1;

                result
            } else {
                None
            }
        })
    }
}

// ================

pub trait EncryptionOracle<H> {
    fn encrypt(&self, plain: BytesType) -> oracles::OracleResponse<BlockBytes, H>;

    // ----------------

    fn encrypt_blocks(&self, plain: BlockBytes) -> oracles::OracleResponse<BlockBytes, H> {
        self.encrypt(plain.to_bytes())
    }

    // ----------------

    fn bytes_missing_in_last_block(&self, pre_padding_size: usize) -> Result<usize, String> {
        let mut probe = BytesType::default();

        if pre_padding_size > 0 {
            probe.extend(vec![b'A'; pre_padding_size]);
        }

        let original_length = self.encrypt(probe.clone()).unwrap().len_bytes();

        // start from 1 as we immediately append a byte to the probe;
        // exit after 1024 bytes of padding to prevent eternal loop
        for padding_length in 1..1024 {
            probe.push(b'A');

            match self.encrypt(probe.clone()).response() {
                Ok(cypher_with_padding) => {
                    // new block was added by encryptor
                    if cypher_with_padding.len_bytes() > original_length {
                        return Ok(padding_length);
                    }
                }
                Err(e) => return Err(e.clone()),
            };
        }

        Err("could not detect padding".to_string())
    }

    fn detect_block_size(&self) -> Result<(usize, usize), String> {
        // ensure last block is full before detecting block size
        let bytes_to_new_block = self.bytes_missing_in_last_block(0)?;

        let block_size = self.bytes_missing_in_last_block(bytes_to_new_block)?;

        Ok((bytes_to_new_block, block_size))
    }
}

// ----------------

pub trait DecryptionOracle<R, H> {
    fn decrypt(&self, cypher: &BytesType) -> oracles::OracleResponse<R, H>;
}
