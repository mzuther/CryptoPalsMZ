use std::{convert, fmt, slice, vec};

use crate::crypto_vecs;

// ----------------

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct Blocks<T> {
    blocks: Vec<T>,
    block_size: usize,
    strict_filling: bool,
}

// ----------------

impl<T> fmt::Display for self::Blocks<T>
where
    T: Clone + ExactSizeIterator + Extend<T> + Ord + PartialEq + PartialOrd + ToString,
{
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

impl<T> fmt::Debug for self::Blocks<T>
where
    T: Clone + ExactSizeIterator + Extend<T> + Ord + PartialEq + PartialOrd + ToString,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

// uses lax filling to maximize usefulness
impl<T> convert::From<Vec<T>> for crypto_vecs::Blocks<T>
where
    T: Clone + ExactSizeIterator + Extend<T> + Ord + PartialEq + PartialOrd + ToString,
{
    fn from(blocks: Vec<T>) -> Self {
        assert!(!blocks.is_empty());

        let block_sizes = blocks.iter().map(|block| block.len());
        let max_block_size = block_sizes.max().unwrap();

        Self {
            blocks,
            block_size: max_block_size,
            strict_filling: false,
        }
    }
}

impl<T> IntoIterator for crypto_vecs::Blocks<T>
where
    T: Clone + ExactSizeIterator + Extend<T> + Ord + PartialEq + PartialOrd + ToString,
{
    type Item = T;
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.blocks.into_iter()
    }
}

impl<T> self::Blocks<T>
where
    T: Clone + ExactSizeIterator + Extend<T> + Ord + PartialEq + PartialOrd + ToString,
{
    pub fn new(block_size: usize) -> Self {
        assert!(block_size > 0);

        Self {
            blocks: Vec::new(),
            block_size,
            strict_filling: true,
        }
    }

    pub fn new_bits(block_size_bits: usize) -> Self {
        // TODO: let bytes = Self::bits_to_bytes(block_size_bits);
        let bytes = block_size_bits / 8;

        Self::new(bytes)
    }

    pub fn new_with_lax_filling(block_size: usize) -> Self {
        assert!(block_size > 0);

        Self {
            blocks: Vec::new(),
            block_size,
            strict_filling: false,
        }
    }

    pub fn new_with_lax_filling_bits(block_size_bits: usize) -> Self {
        // TODO: let bytes = Self::bits_to_bytes(block_size_bits);
        let bytes = block_size_bits / 8;

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
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    // ----------------

    pub fn iter(&self) -> slice::Iter<'_, T> {
        self.blocks.iter()
    }

    pub fn iter_mut(&mut self) -> slice::IterMut<'_, T> {
        self.blocks.iter_mut()
    }

    pub fn to_vec(&self) -> Vec<T> {
        self.blocks.to_vec()
    }

    fn get_last_block(&self) -> &T {
        self.iter().last().expect("BlockBytes must not be empty")
    }

    fn get_last_block_mut(&mut self) -> &mut T {
        self.iter_mut()
            .last()
            .expect("BlockBytes must not be empty")
    }

    pub fn get_last_block_size(&self) -> usize {
        self.get_last_block().len()
    }

    pub fn get_last_block_size_bits(&self) -> usize {
        self.get_last_block_size() * 8
    }

    // ----------------

    pub fn push(&mut self, block: T) {
        let block_size = self.get_block_size();

        assert!(
            block.len() <= block_size,
            "block is too big, {} bytes > {} bytes",
            block.len(),
            block_size
        );

        if !self.blocks.is_empty() && self.uses_strict_filling() {
            let last_block_size = self.get_last_block_size();

            assert_eq!(
                last_block_size, block_size,
                "last block is not full, has only {} bytes",
                last_block_size
            );
        }

        self.blocks.push(block);
    }

    pub fn pop(&mut self) -> Option<T> {
        self.blocks.pop()
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
}
