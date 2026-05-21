//! TAME block cipher
//!

// Idea: Unbalanced feistel where the short side is one half of the min block size
// and the other half absorbs the rest:
// L: 8 bytes R: 8 bytes min block (128bit)
// L: 8 bytes R: 120 bytes max block (1024 bit)

pub use cipher;

use crate::util::{AuthorName, Direction};
use cipher::typenum::Unsigned as _;
use cipher::{
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut,
    InvalidLength, KeyInit, KeySizeUser, ParBlocksSizeUser,
    consts::{U1, U32},
};
use core::fmt;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

const ROUNDS: usize = 32;
const MIN_KEY_SIZE: usize = 8;
const MAX_KEY_SIZE: usize = 128;
const MIN_BLOCK_SIZE: usize = 16;
const MAX_BLOCK_SIZE: usize = 128;
const ROUND_KEY_SIZE: usize = 16;
/// Binary expansion of pi.
const IV: [u8; 128] = [
    0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x85, 0xf7, 0x9c, 0xa0, 0x2c,
    0x33, 0x22, 0xbc, 0xf5, 0x7c, 0xb7, 0xaf, 0x01, 0xbd, 0x5d, 0xa2, 0xd1, 0x01, 0xd4, 0xe8, 0x4c,
    0x98, 0x28, 0xdb, 0x48, 0x4d, 0xac, 0x28, 0xa3, 0x85, 0x41, 0xf7, 0x7e, 0xb9, 0xa1, 0x89, 0xd5,
    0x04, 0x0f, 0x11, 0x9f, 0x53, 0xb2, 0x2a, 0xe4, 0x79, 0x46, 0xea, 0xf2, 0x6c, 0xf9, 0x30, 0x60,
    0xa8, 0x38, 0xc4, 0x02, 0x33, 0x75, 0x3f, 0xb8, 0x0c, 0x58, 0x33, 0x3a, 0xcc, 0x1e, 0xa5, 0xd5,
    0x96, 0xea, 0xd7, 0xf0, 0x26, 0x7b, 0xd7, 0x60, 0x1b, 0x69, 0x89, 0xdc, 0x06, 0xfc, 0x67, 0xb7,
    0x20, 0x9e, 0x67, 0xe6, 0x3f, 0x63, 0x6c, 0xaa, 0xe6, 0x79, 0x2b, 0xd0, 0x87, 0x30, 0x1a, 0xa5,
    0x1b, 0x3f, 0xa4, 0xc3, 0xba, 0x65, 0xe1, 0x45, 0x9a, 0x68, 0x95, 0xbe, 0xe5, 0xc4, 0xaa, 0x42,
];

const LEFT_SIZE: usize = MIN_BLOCK_SIZE / 2;
const RIGHT_MAX_SIZE: usize = MAX_BLOCK_SIZE - LEFT_SIZE;
const RIGHT_MIN_SIZE: usize = MIN_BLOCK_SIZE - LEFT_SIZE;

fn a_round(left: &mut [u8; LEFT_SIZE], right: &mut [u8]) {
    debug_assert!(right.len() =< RIGHT_MAX_SIZE);
    debug_assert!(right.len() >= RIGHT_MIN_SIZE);
}

fn b_round(left: &mut [u8], right: &mut [u8; LEFT_SIZE]) {
    debug_assert!(left.len() =< RIGHT_MAX_SIZE);
    debug_assert!(left.len() >= RIGHT_MIN_SIZE);
}

#[derive(Clone, Copy, Debug)]
struct RoundKey {
    key_material: [u8; ROUND_KEY_SIZE],
}

#[derive(Clone, Copy, Debug)]
struct InternalKeys {
    round_keys: [RoundKey; ROUNDS],
}

impl Default for RoundKey {
    fn default() -> Self {
        Self {
            key_material: [0; ROUND_KEY_SIZE],
        }
    }
}

impl Default for InternalKeys {
    fn default() -> Self {
        Self {
            round_keys: [RoundKey::default(); ROUNDS],
        }
    }
}

/// The TAME block cipher.
#[derive(Clone, Default)]
struct Tame {
    internal_keys: InternalKeys,
}

impl KeySizeUser for Tame {
    type KeySize = U32;
}

impl KeyInit for Tame {
    fn new(key: &cipher::Key<Self>) -> Self {
        Self::new_from_slice(key).unwrap()
    }

    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        if key.len() < MIN_KEY_SIZE || key.len() > MAX_KEY_SIZE {
            return Err(InvalidLength);
        }
        Ok(Self::default())
    }
}

impl BlockSizeUser for Tame {
    type BlockSize = U32;
}

impl ParBlocksSizeUser for Tame {
    type ParBlocksSize = U1;
}

impl BlockCipherEncrypt for Tame {
    #[inline]
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(self);
    }
}

impl BlockCipherEncBackend for Tame {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        // TODO
    }
}

impl BlockCipherDecrypt for Tame {
    #[inline]
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(self);
    }
}

impl BlockCipherDecBackend for Tame {
    #[inline]
    fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        // TODO
    }
}

impl fmt::Debug for Tame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TAME { ... }")
    }
}

impl AlgorithmName for Tame {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TAME")
    }
}

impl AuthorName for Tame {
    fn write_author_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NA")
    }
}
