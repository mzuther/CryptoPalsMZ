use std::{iter, slice};

use crate::crypto_vecs::{
    self, Base64Type, BlockBytes, Bytes, BytesType, HexadecimalType, UnicodeType,
};
use crate::oracles;

// ================

pub trait InternalData
where
    Self::Element: Clone,
{
    // iterate over / count logical elements (e.g. String, char)
    type Element;
    // collection holding logical elements (e.g. Vec, String)
    type Collection;

    // ----------------

    fn new_from(data: Self::Collection) -> Self;
    fn new_from_elements(elements: &[Self::Element]) -> Self;

    fn from_literal(string_literal: &str) -> Self;
    fn with_capacity(capacity: usize) -> Self;

    fn capacity(&self) -> usize;
    fn clean_and_validate(data: Self::Collection) -> Result<Self::Collection, String>;

    // ----------------

    fn elements(&self) -> impl Iterator<Item = Self::Element>;
    fn data(&self) -> &Self::Collection;

    // ----------------

    fn representation_name(&self) -> &str;
    fn representation(&self) -> String;

    // ================

    fn with_capacity_bits(capacity_bits: usize) -> Self
    where
        Self: Sized,
    {
        let capacity = crypto_vecs::bits_to_bytes(capacity_bits);

        Self::with_capacity(capacity)
    }

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

    // ----------------

    // get nth logical element
    fn get(&self, index: usize) -> Option<Self::Element> {
        self.elements().nth(index)
    }
}

// ----------------

pub trait InternalDataVec: InternalData
where
    Self: Sized
        + InternalData<Collection = Vec<<Self as InternalData>::Element>>
        + LenBytes,
    Self::Element: Clone,
{
    fn chunks(&self, chunk_size: usize) -> slice::Chunks<'_, Self::Element>;
    fn rchunks(&self, chunk_size: usize) -> slice::RChunks<'_, Self::Element>;

    // ================

    // clone of underlying collection
    fn to_vec(&self) -> Vec<Self::Element> {
        self.data().to_vec()
    }

    // reference to underlying collection
    fn as_slice(&self) -> &[Self::Element] {
        self.data().as_slice()
    }

    // ----------------

    #[doc(hidden)]
    fn _take_it(&self, length: usize, reverse: bool) -> Option<&[Self::Element]> {
        if length == 0 {
            None
        } else if length > self.len_bytes() {
            Some(self.as_slice())
        } else {
            if reverse {
                self.rchunks(length).next()
            } else {
                self.chunks(length).next()
            }
        }
    }

    #[doc(hidden)]
    fn _leave_it(&self, length: usize, reverse: bool) -> Option<&[Self::Element]> {
        if length == 0 {
            Some(self.as_slice())
        } else if length >= self.len_bytes() {
            None
        } else {
            if reverse {
                self.chunks(self.len_bytes() - length).next()
            } else {
                self.rchunks(self.len_bytes() - length).next()
            }
        }
    }

    fn take_n(&self, length: usize) -> Option<&[Self::Element]> {
        self._take_it(length, false)
    }

    fn skip_n(&self, length: usize) -> Option<&[Self::Element]> {
        self._leave_it(length, false)
    }

    fn rtake_n(&self, length: usize) -> Option<&[Self::Element]> {
        self._take_it(length, true)
    }

    fn rskip_n(&self, length: usize) -> Option<&[Self::Element]> {
        self._leave_it(length, true)
    }

    // ----------------

    fn chunks_as_collection(&self, chunk_size: usize) -> Vec<Self> {
        self.chunks(chunk_size)
            .map(|chunk| Self::new_from_elements(chunk))
            .collect()
    }

    fn rchunks_as_collection(&self, chunk_size: usize) -> Vec<Self> {
        self.rchunks(chunk_size)
            .map(|chunk| Self::new_from_elements(chunk))
            .collect()
    }

    fn take_n_as_collection(&self, length: usize) -> Option<Self> {
        self.take_n(length)
            .map(|element| Self::new_from_elements(element))
    }

    fn skip_n_as_collection(&self, length: usize) -> Option<Self> {
        self.skip_n(length)
            .map(|element| Self::new_from_elements(element))
    }

    fn rtake_n_as_collection(&self, length: usize) -> Option<Self> {
        self.rtake_n(length)
            .map(|element| Self::new_from_elements(element))
    }

    fn rskip_n_as_collection(&self, length: usize) -> Option<Self> {
        self.rskip_n(length)
            .map(|element| Self::new_from_elements(element))
    }
}

// ----------------

pub trait InternalDataVecMut: InternalDataVec
where
    Self::Element: Clone,
{
    fn data_mut(&mut self) -> &mut Vec<Self::Element>;

    fn push(&mut self, value: Self::Element);

    // ================

    fn as_mut_slice(&mut self) -> &mut [Self::Element] {
        self.data_mut().as_mut_slice()
    }
}

// ----------------

pub trait LenBytes {
    fn len_bytes(&self) -> usize;

    // ================

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
    fn to_bytes_raw(&self) -> Bytes;

    // ================

    fn to_bytes(&self) -> BytesType {
        BytesType::new_from(self.to_bytes_raw().to_vec())
    }

    fn to_hexadecimal(&self) -> HexadecimalType {
        HexadecimalType::from(&self.to_bytes())
    }

    fn to_base64(&self) -> Base64Type {
        Base64Type::from(&self.to_bytes())
    }

    fn to_unicode(&self) -> UnicodeType {
        UnicodeType::from(&self.to_bytes())
    }
}

// ================

pub trait AutoProbe
where
    Self: Default + Extend<Self::Element> + InternalDataVecMut + LenBytes,
    Self::Element: Clone,
{
    fn new_auto_probe(
        final_probe: Self,
        size_start: usize,
        is_expanding: bool,
    ) -> iter::FromFn<impl FnMut() -> Option<Self>> {
        let size_end = final_probe.len_bytes();
        let mut size_iter = either::Either::Left(size_start..=size_end);

        if !is_expanding {
            size_iter = either::Either::Right(
                size_iter
                    .expect_left("is valid and of type \"either::Left\"")
                    .rev(),
            )
        };

        std::iter::from_fn(move || {
            size_iter.next().map(|current_size| {
                final_probe
                    .take_n_as_collection(current_size)
                    .unwrap_or_default()
            })
        })
    }

    // ----------------

    fn new_auto_probe_repeat(
        element: Self::Element,
        size_start: usize,
        size_end: usize,
    ) -> iter::FromFn<impl FnMut() -> Option<Self>> {
        let size_start_actual = size_start.min(size_end);
        let size_end_actual = size_start.max(size_end);

        Self::new_auto_probe(
            Self::new_from_elements(&vec![element; size_end_actual]),
            size_start_actual,
            size_start < size_end,
        )
    }

    fn new_auto_probe_mover(
        original_probe: Self,
        moving_part: Self,
    ) -> iter::FromFn<impl FnMut() -> Option<Self>> {
        assert!(!original_probe.is_empty());
        assert!(!moving_part.is_empty());

        let mut size_iter = 0..=original_probe.len_bytes();

        std::iter::from_fn(move || {
            size_iter.next().map(|size_current| {
                let mut result = original_probe
                    .take_n_as_collection(size_current)
                    .unwrap_or_default();

                result.extend(moving_part.to_vec());

                result.extend(
                    original_probe
                        .skip_n_as_collection(size_current)
                        .unwrap_or_default()
                        .to_vec(),
                );

                result
            })
        })
    }
}

// ================

pub trait EncryptionOracle<H> {
    fn encrypt(&self, plain: BytesType) -> oracles::OracleResponse<BlockBytes, H>;

    // ================

    fn encrypt_blocks(
        &self,
        plain: BlockBytes,
    ) -> oracles::OracleResponse<BlockBytes, H> {
        self.encrypt(plain.to_bytes())
    }

    // ----------------

    fn bytes_missing_in_last_block(
        &self,
        pre_padding_size: usize,
    ) -> Result<usize, String> {
        let mut original_length = None;

        // exit after 1024 bytes of padding to prevent eternal loop
        for (iteration, current_probe) in BytesType::new_auto_probe_repeat(
            b'A',
            pre_padding_size,
            1024 + pre_padding_size,
        )
        .enumerate()
        {
            let oracle_response = self.encrypt(current_probe);

            if iteration == 0 {
                original_length = Some(oracle_response.unwrap().len_bytes())
            } else {
                match oracle_response.response() {
                    Ok(cypher_with_padding) => {
                        // new block was added by encryptor
                        if cypher_with_padding.len_bytes()
                            > original_length
                                .expect("first iteration initializes original length")
                        {
                            return Ok(iteration);
                        }
                    }
                    Err(e) => return Err(e.clone()),
                };
            }
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
