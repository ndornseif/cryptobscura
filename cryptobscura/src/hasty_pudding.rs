//! Hasty pudding cipher
//!
//! Note that the test vectors supplied with the HPCs AES submission
//! are not calculated with the implementation that fixed the weak keys.
//! This means that they wont match for this version that has the fix applied.
//!
//! Unlike the original this version of the cipher does not accept
//! keys or blocks whose size is not a multiple of eight bits.
//! The Tiny size sub-cipher (blocks shorter than 36 bits) is not implemented.
pub use cipher;

use crate::util::AuthorName;
use cipher::typenum::Unsigned as _;
use cipher::{
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut,
    InvalidLength, KeyInit, KeySizeUser, ParBlocksSizeUser,
    consts::{U1, U8, U16, U64, U512},
};
use core::fmt;

/// Digits of pi, decimal: 3141592653589793238
const HPC_PI: u64 = 0x2b99_2ddf_a232_49d6;
/// Digits of e, decimal: 2718281828459045235
const HPC_E: u64 = 0x25b9_46eb_c0b3_6173;
/// Digits of sqrt(2), decimal: 14142135623730950488
const HPC_R2: u64 = 0xc442_f56b_e9e1_7158;
const STIR_PASSES: usize = 3;
const ROUND_COUNT: usize = 8;
const KX_SIZE: usize = 256;
/// Number of sub-ciphers. (Tiny, Short, Medium, Long and Extended)
const CIPHER_COUNT: usize = 5;
const BACKUP_SIZE: usize = CIPHER_COUNT + 1;
const BYTES_U64: usize = (u64::BITS / u8::BITS) as usize;

const CIPHER_ID_SHORT: usize = 2;
const CIPHER_ID_MEDIUM: usize = 3;
const CIPHER_ID_LONG: usize = 4;
const CIPHER_ID_EXTENDED: usize = 5;

/// Maximum block size supported by the short sub-cipher.
const BLOCK_SIZE_SHORT: usize = <HastyPuddingShort as BlockSizeUser>::BlockSize::USIZE;
/// Maximum block size supported by the medium sub-cipher.
const BLOCK_SIZE_MEDIUM: usize = <HastyPuddingMedium as BlockSizeUser>::BlockSize::USIZE;
/// Maximum block size supported by the long sub-cipher.
const BLOCK_SIZE_LONG: usize = <HastyPuddingLong as BlockSizeUser>::BlockSize::USIZE;
/// Maximum block size supported by the extended sub-cipher.
const BLOCK_SIZE_EXTENDED: usize = <HastyPuddingExtended as BlockSizeUser>::BlockSize::USIZE;

/// Base trait derived by the HPC sub-ciphers.
trait HastyPuddingBase<const CIPHER_ID: usize>
where
    Self: Sized,
{
    fn new_raw(kx: &[u64; KX_SIZE], backup: &[usize; BACKUP_SIZE]) -> Self;

    fn cipher_init(key: &[u8]) -> Self {
        Self::cipher_init_with_backup(key, [0_usize; BACKUP_SIZE])
    }

    #[allow(clippy::cast_possible_truncation)]
    fn cipher_init_with_backup(
        key: &[u8],
        backup: [usize; BACKUP_SIZE],
    ) -> Self {
        // Since the backup option is unused in the ciphers current interation
        // we just panic if it contains an invalid value.
        assert!(backup[0] + STIR_PASSES <= 64, "backup[0] to high.");
        let key_len_bits = key.len() * u8::BITS as usize;
        let mut kx = [0_u64; KX_SIZE];
        kx[0] = HPC_PI.wrapping_add(CIPHER_ID as u64);
        kx[1] = HPC_E.wrapping_mul(key_len_bits as u64);
        kx[2] = HPC_R2.rotate_left(CIPHER_ID as u32);

        for i in 3..KX_SIZE {
            kx[i] = kx[i - 1].wrapping_add(kx[i - 2] ^ kx[i - 3].rotate_right(23));
        }

        let mut left_key_bits: usize = key_len_bits;
        let mut left_key = key;

        loop {
            let iteration_key_bits = left_key_bits.min(KX_SIZE * 64 / 2);
            let whole_bytes = iteration_key_bits / u8::BITS as usize;

            let (chunk, rest) = left_key.split_at(whole_bytes);
            left_key = rest;

            let mut sh: u32 = 0;
            for (i, &b) in chunk.iter().enumerate() {
                kx[i / BYTES_U64] ^= u64::from(b) << sh;
                sh = (sh + u8::BITS) & 0b11_1111;
            }

            let mut s0 = kx[248];
            let mut s1 = kx[249];
            let mut s2 = kx[250];
            let mut s3 = kx[251];
            let mut s4 = kx[252];
            let mut s5 = kx[253];
            let mut s6 = kx[254];
            let mut s7 = kx[255];

            for pass in 0..(STIR_PASSES + backup[0]) {
                for ki in 0..KX_SIZE {
                    s0 ^= (kx[ki] ^ kx[(ki + 83) & 255]).wrapping_add(kx[s0 as usize & 255]);
                    s2 = s2.wrapping_add(kx[ki]); // Added in 1999 to fix Wagner equivalent key problem
                    s1 = s1.wrapping_add(s0);
                    s3 ^= s2;
                    s5 = s5.wrapping_sub(s4);
                    s7 ^= s6;
                    s3 = s3.wrapping_add(s0 >> 13);
                    s4 ^= s1 << 11;
                    s5 ^= s3 << (s1 & 31);
                    s6 = s6.wrapping_add(s2 >> 17);
                    s7 |= s3.wrapping_add(s4);
                    s2 = s2.wrapping_sub(s5);
                    s0 = s0.wrapping_sub(s6 ^ ki as u64);
                    s1 ^= s5.wrapping_add(HPC_PI);
                    s2 = s2.wrapping_add(s7 >> pass);
                    s2 ^= s1;
                    s4 = s4.wrapping_sub(s3);
                    s6 ^= s5;
                    s0 = s0.wrapping_add(s7);
                    kx[ki] = s2.wrapping_add(s6);
                }
            }

            left_key_bits -= iteration_key_bits;
            if left_key_bits == 0 {
                break;
            }
        }
        Self::new_raw(&kx, &backup)
    }
}

fn npc_encrypt_short() {}

/// Generates the struct definition and all cipher trait impls for one HPC sub-cipher.
///
/// Parameters:
/// - `$name`:         struct identifier (e.g. `HastyPuddingMedium`)
/// - `$block_size`:   `RustCrypto` block-size typenum (e.g. `U16`)
/// - `$cipher_id`:    the sub-cipher ID constant used to seed the KX schedule
/// - `$display_name`: string literal fragment for `Debug` / `AlgorithmName` (e.g. `"Medium"`)
macro_rules! impl_hpc_variant {
    ($name:ident, $block_size:ty, $cipher_id:expr, $display_name:literal) => {
        #[doc = concat!(
            "The Hasty Pudding cipher (",
            $display_name,
            " sub-cipher) in its modified 1999 implementation."
        )]
        #[derive(Clone)]
        pub struct $name {
            kx: [u64; KX_SIZE],
            backup: [usize; BACKUP_SIZE],
        }

        impl Default for $name {
            fn default() -> Self {
                Self { kx: [0; KX_SIZE], backup: [0; BACKUP_SIZE] }
            }
        }

        impl HastyPuddingBase<{ $cipher_id }> for $name {
            fn new_raw(kx: &[u64; KX_SIZE], backup: &[usize; BACKUP_SIZE]) -> Self {
                Self { kx: *kx, backup: *backup }
            }
        }

        impl KeySizeUser for $name {
            type KeySize = U16;
        }

        impl KeyInit for $name {
            fn new(key: &cipher::Key<Self>) -> Self {
                Self::new_from_slice(key).unwrap()
            }

            fn new_from_slice(_key: &[u8]) -> Result<Self, InvalidLength> {
                // TODO Impl here
                Ok($name::default())
            }
        }

        impl BlockSizeUser for $name {
            type BlockSize = $block_size;
        }

        impl ParBlocksSizeUser for $name {
            type ParBlocksSize = U1;
        }

        impl BlockCipherEncrypt for $name {
            #[inline]
            fn encrypt_with_backend(
                &self,
                f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>,
            ) {
                f.call(self);
            }
        }

        impl BlockCipherEncBackend for $name {
            #[inline]
            fn encrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
                // TODO Impl here
                let _ = block;
            }
        }

        impl BlockCipherDecrypt for $name {
            #[inline]
            fn decrypt_with_backend(
                &self,
                f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>,
            ) {
                f.call(self);
            }
        }

        impl BlockCipherDecBackend for $name {
            #[inline]
            fn decrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
                // TODO Impl here
                let _ = block;
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!("Hasty Pudding Cipher ", $display_name, " { ... }"))
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!("Hasty Pudding Cipher ", $display_name))
            }
        }

        #[cfg(feature = "zeroize")]
        impl Drop for $name {
            fn drop(&mut self) {
                // TODO Zeroize here
            }
        }

        impl AuthorName for $name {
            fn write_author_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("Richard Schroeppel")
            }
        }
    };
}

impl_hpc_variant!(HastyPuddingShort, U8, CIPHER_ID_SHORT, "Short");
impl_hpc_variant!(HastyPuddingMedium, U16, CIPHER_ID_MEDIUM, "Medium");
impl_hpc_variant!(HastyPuddingLong, U64, CIPHER_ID_LONG, "Long");
impl_hpc_variant!(HastyPuddingExtended, U512, CIPHER_ID_EXTENDED, "Extended");
