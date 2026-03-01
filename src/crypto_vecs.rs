mod base64;
mod block_bytes;
mod bytes;
mod hexadecimal;
mod unicode;

// ----------------

pub use crate::crypto_vecs::base64::Base64;
pub use crate::crypto_vecs::block_bytes::BlockBytes;
pub use crate::crypto_vecs::bytes::Bytes;
pub use crate::crypto_vecs::hexadecimal::Hexadecimal;
pub use crate::crypto_vecs::unicode::Unicode;

// ----------------

pub trait ToBytes {
    fn to_bytes(&self) -> self::Bytes;

    fn to_hexadecimal(&self) -> self::Hexadecimal {
        self::Hexadecimal::from(&self.to_bytes())
    }

    fn to_base64(&self) -> self::Base64 {
        self::Base64::from(&self.to_bytes())
    }

    fn to_unicode(&self) -> self::Unicode {
        self::Unicode::from(&self.to_bytes())
    }
}
