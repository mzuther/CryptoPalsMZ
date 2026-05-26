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

pub mod traits;

// ----------------

mod base64;
mod byte_blocks;
mod bytes;
mod hexadecimal;
mod unicode;

// ----------------

pub use crate::crypto_vecs::base64::Base64;
pub use crate::crypto_vecs::byte_blocks::ByteBlocks;
pub use crate::crypto_vecs::bytes::Bytes;
pub use crate::crypto_vecs::hexadecimal::Hexadecimal;
pub use crate::crypto_vecs::unicode::Unicode;

// ================

pub fn bits_to_bytes(bits: usize) -> usize {
    assert!(
        bits.is_multiple_of(8),
        "{} bits are not divisible by 8",
        bits
    );

    bits / 8
}
