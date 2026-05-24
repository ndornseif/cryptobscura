//! Hasty pudding cipher
//!
//! Note that the test vectors supplied with the HPCs AES submission
//! are not calculated with the implementation that fixed the weak keys.
//! This means that they wont match for this version that has the fix applied.
//!
//! Unlike the original this version of the cipher does not accept
//! keys or blocks whose size is not a multiple of eight bits.
//! A key of len zero could still be used, needs to be covered in tests.
pub use cipher;

use crate::util::AuthorName;
use cipher::{
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut,
    InvalidLength, KeyInit, KeySizeUser, ParBlocksSizeUser,
    consts::{U1, U8, U16, U64},
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
/// Number of sub-ciphers. (Tiny, Short, Medium and Long)
const CIPHER_COUNT: usize = 4;
const BACKUP_SIZE: usize = CIPHER_COUNT + 1;
const BYTES_U64: usize = (u64::BITS / u8::BITS) as usize;
const TWEAK_MAX_SIZE: usize = 512 / 8;

const CIPHER_ID_SHORT: usize = 2;
const CIPHER_ID_MEDIUM: usize = 3;
const CIPHER_ID_LONG: usize = 4;


fn hpc_short_encrypt(
    _s: &mut [u64; ROUND_COUNT],
    _spice: &[u64; ROUND_COUNT],
    _kx: &[u64; KX_SIZE],
    _block_size_bits: usize,
    _mask: u64,
    _backup: usize,
) {
}

fn hpc_short_decrypt(
    _s: &mut [u64; ROUND_COUNT],
    _spice: &[u64; ROUND_COUNT],
    _kx: &[u64; KX_SIZE],
    _block_size_bits: usize,
    _mask: u64,
    _backup: usize,
) {
}

#[allow(clippy::cast_possible_truncation)]
fn hpc_medium_encrypt(
    s: &mut [u64; ROUND_COUNT],
    spice: &[u64; ROUND_COUNT],
    kx: &[u64; KX_SIZE],
    block_size_bits: usize,
    mask: u64,
    _backup: usize,
) {
    let mut s0 = s[0];
    let mut s1 = s[1];

    for ri in 0..ROUND_COUNT {
        let k0 = kx[s0 as usize & 255];
        s1 = s1.wrapping_add(k0);
        s0 ^= k0 << 8;
        s1 ^= s0;
        s1 &= mask;

        s0 = s0.wrapping_sub(s1 >> 11);
        s0 ^= s1 << 2;
        s0 = s0.wrapping_sub(spice[ri ^ 4]);
        s0 = s0.wrapping_add((s0 << 32) ^ HPC_PI.wrapping_add(block_size_bits as u64));
        s0 ^= s0 >> 17;
        s0 ^= s0 >> 34;
        let mut t = spice[ri];
        s0 ^= t;
        s0 = s0.wrapping_add(t << 5);
        t >>= 4;
        s1 = s1.wrapping_add(t);
        s0 ^= t;
        let var_shift = (22 + (s0 & 31)) as u32;
        s0 = s0.wrapping_add(s0 << var_shift);
        s0 ^= s0 >> 23;
        s0 = s0.wrapping_sub(spice[ri ^ 7]);

        let t_idx = s0 as usize & 255;
        let k = kx[t_idx];
        let mut kk = kx[(t_idx + 3 * ri + 1) & 255];
        s1 ^= k;
        s0 ^= kk << 8;
        kk ^= k;
        s1 = s1.wrapping_add(kk >> 5);
        s0 = s0.wrapping_sub(kk << 12);
        s0 ^= kk & !255_u64;
        s1 = s1.wrapping_add(s0);
        s1 &= mask;

        s0 = s0.wrapping_add(s1 << 3);
        s0 ^= spice[ri ^ 2];
        s0 = s0.wrapping_add(kx[block_size_bits + ri + 16]);
        s0 = s0.wrapping_add(s0 << 22);
        s0 ^= s1 >> 4;
        s0 = s0.wrapping_add(spice[ri ^ 1]);
        s0 ^= s0 >> ((ri + 33) as u32);
    }

    s[0] = s0;
    s[1] = s1;
}

#[allow(clippy::cast_possible_truncation)]
fn hpc_medium_decrypt(
    s: &mut [u64; ROUND_COUNT],
    spice: &[u64; ROUND_COUNT],
    kx: &[u64; KX_SIZE],
    block_size_bits: usize,
    mask: u64,
    _backup: usize,
) {
    let mut s0 = s[0];
    let mut s1 = s[1];

    for ri in (0..ROUND_COUNT).rev() {
        // Invert Part 4
        s0 ^= s0 >> ((ri + 33) as u32);
        s0 = s0.wrapping_sub(spice[ri ^ 1]);
        s0 ^= s1 >> 4;
        let t = s0.wrapping_sub(s0 << 22);
        s0 = s0.wrapping_sub(t << 22);
        s0 = s0.wrapping_sub(kx[block_size_bits + ri + 16]);
        s0 ^= spice[ri ^ 2];
        s0 = s0.wrapping_sub(s1 << 3);
        s1 = s1.wrapping_sub(s0);

        // Invert Part 3
        let t_idx = s0 as usize & 255;
        let k = kx[t_idx];
        let mut kk = kx[(t_idx + 3 * ri + 1) & 255];
        kk ^= k;
        s0 ^= kk & !255_u64;
        s0 = s0.wrapping_add(kk << 12);
        s1 = s1.wrapping_sub(kk >> 5);
        kk ^= k;
        s0 ^= kk << 8;
        s1 ^= k;

        // Invert Part 2
        s0 = s0.wrapping_add(spice[ri ^ 7]);
        s0 ^= s0 >> 23;
        s0 ^= s0 >> 46;
        let var_shift = (22 + (s0 & 31)) as u32;
        let t2 = s0 << var_shift;
        s0 = s0.wrapping_sub(s0.wrapping_sub(t2) << var_shift);
        let t3 = spice[ri] >> 4;
        s0 ^= t3;
        s1 = s1.wrapping_sub(t3);
        let t4 = spice[ri];
        s0 = s0.wrapping_sub(t4 << 5);
        s0 ^= t4;
        // Single application inverts both s0 ^= s0 >> 17 and s0 ^= s0 >> 34
        s0 ^= s0 >> 17;
        let c = HPC_PI.wrapping_add(block_size_bits as u64);
        let t5 = s0.wrapping_sub(c);
        s0 = s0.wrapping_sub((t5 << 32) ^ c);
        s0 = s0.wrapping_add(spice[ri ^ 4]);
        s1 &= mask;

        // Invert Part 1
        s0 ^= s1 << 2;
        s0 = s0.wrapping_add(s1 >> 11);
        s1 ^= s0;
        let k2 = kx[s0 as usize & 255];
        s0 ^= k2 << 8;
        s1 = s1.wrapping_sub(k2);
        s1 &= mask;
    }

    s[0] = s0;
    s[1] = s1;
}

fn hpc_long_encrypt(
    _s: &mut [u64; ROUND_COUNT],
    _spice: &[u64; ROUND_COUNT],
    _kx: &[u64; KX_SIZE],
    _block_size_bits: usize,
    _mask: u64,
    _backup: usize,
) {
}

fn hpc_long_decrypt(
    _s: &mut [u64; ROUND_COUNT],
    _spice: &[u64; ROUND_COUNT],
    _kx: &[u64; KX_SIZE],
    _block_size_bits: usize,
    _mask: u64,
    _backup: usize,
) {
}


/// Mask for the high u64 word of the state. For byte-aligned block sizes that
/// are multiples of 64 bits this is always all-ones, making the masking steps
/// no-ops.  Kept for correctness and to match the reference algorithm.
fn compute_mask(bit_size: usize) -> u64 {
    let shift = (bit_size - 1) & 63;
    (((1_u64 << shift).wrapping_sub(1)) << 1) | 1
}

/// Number of u64 words that carry block data in the eight-word state array.
/// For blocks up to 64 bits: 1; up to 128 bits: 2; otherwise: 8 (all words).
fn state_word_count(bit_size: usize) -> usize {
    if bit_size <= 64 {
        1
    } else if bit_size <= 128 {
        2
    } else {
        8
    }
}

/// Number of bytes loaded into the eight-word state array. For blocks up to
/// 512 bits this equals the block's byte length; larger blocks use all 64
/// bytes of the eight-word array and the extended sub-cipher handles the rest.
fn state_byte_limit(byte_len: usize, bit_size: usize) -> usize {
    if bit_size <= 512 { byte_len } else { 64 }
}

/// Little-endian load of up to 64 bytes into the state array.  `l64` words of
/// eight bytes each are read; the caller must ensure `l64 * 8 <= buf.len()`.
fn load_state(buf: &[u8], l64: usize) -> [u64; ROUND_COUNT] {
    let mut s = [0_u64; ROUND_COUNT];
    for i in 0..l64 {
        let base = i * BYTES_U64;
        for (j, &b) in buf[base..base + BYTES_U64].iter().enumerate() {
            s[i] |= (b as u64) << (j * u8::BITS as usize);
        }
    }
    s
}

/// Little-endian store of `l64` words of eight bytes each back into `buf`.
fn store_state(s: &[u64; ROUND_COUNT], l64: usize, buf: &mut [u8]) {
    for i in 0..l64 {
        let base = i * BYTES_U64;
        for j in 0..BYTES_U64 {
            buf[base + j] = ((s[i] >> (j * u8::BITS as usize)) & 0xff) as u8;
        }
    }
}

/// Base trait derived by the HPC sub-ciphers.
trait HastyPuddingBase<const CIPHER_ID: usize>
where
    Self: Sized,
{
    fn new_raw(kx: &[u64; KX_SIZE], backup: &[usize; BACKUP_SIZE]) -> Self;
    fn kx(&self) -> &[u64; KX_SIZE];
    fn backup(&self) -> &[usize; BACKUP_SIZE];

    fn cipher_init(key: &[u8]) -> Self {
        Self::cipher_init_with_backup(key, [0_usize; BACKUP_SIZE])
    }

    #[allow(clippy::cast_possible_truncation)]
    fn cipher_init_with_backup(key: &[u8], backup: [usize; BACKUP_SIZE]) -> Self {
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

    /// Encrypts `buf` in place. `tweak` must be at most 64 bytes. Both must be
    /// non-empty multiples of eight bits; sub-byte sizes are not supported.
    fn hpc_encrypt(&self, buf: &mut [u8], tweak: &[u8]) {
        if buf.is_empty() || tweak.len() > TWEAK_MAX_SIZE {
            return;
        }
        let pl_bits = buf.len() * u8::BITS as usize;

        let mut spice = [0_u64; ROUND_COUNT];
        for (i, &b) in tweak.iter().enumerate() {
            let sh = (i * u8::BITS as usize) & 63;
            spice[i / BYTES_U64] |= (b as u64) << sh;
        }

        let mask = compute_mask(pl_bits);
        let byte_limit = state_byte_limit(buf.len(), pl_bits);
        let l64 = state_word_count(pl_bits);

        let mut s = load_state(buf, l64);
        if pl_bits < 512 {
            s[l64 - 1] &= mask;
        }

        let kx = self.kx();
        let cipher_backup = self.backup()[CIPHER_ID];

        for i in 0..=cipher_backup {
            s[0] = s[0].wrapping_add(i as u64);

            for j in 0..ROUND_COUNT {
                s[j] = s[j].wrapping_add(kx[(pl_bits + j) & 0xff]);
            }
            if pl_bits < 512 {
                s[l64 - 1] &= mask;
            }

            Self::subcipher_encrypt(&mut s, &spice, kx, buf, pl_bits, mask, i);

            for j in 0..ROUND_COUNT {
                s[j] = s[j].wrapping_add(kx[(pl_bits + ROUND_COUNT + j) & 0xff]);
            }
            if pl_bits < 512 {
                s[l64 - 1] &= mask;
            }
        }

        store_state(&s, l64, &mut buf[..byte_limit]);
    }

    /// Decrypts `buf` in place. `tweak` must match the value used during
    /// encryption. Both must be non-empty multiples of eight bits.
    fn hpc_decrypt(&self, buf: &mut [u8], tweak: &[u8]) {
        if buf.is_empty() || tweak.len() > TWEAK_MAX_SIZE {
            return;
        }
        let ct_bits = buf.len() * u8::BITS as usize;

        let mut spice = [0_u64; ROUND_COUNT];
        for (i, &b) in tweak.iter().enumerate() {
            let sh = (i * u8::BITS as usize) & 63;
            spice[i / BYTES_U64] |= (b as u64) << sh;
        }

        let mask = compute_mask(ct_bits);
        let byte_limit = state_byte_limit(buf.len(), ct_bits);
        let l64 = state_word_count(ct_bits);

        let mut s = load_state(buf, l64);
        if ct_bits < 512 {
            s[l64 - 1] &= mask;
        }

        let kx = self.kx();
        let cipher_backup = self.backup()[CIPHER_ID];

        for i in (0..=cipher_backup).rev() {
            for j in 0..ROUND_COUNT {
                s[j] = s[j].wrapping_sub(kx[(ct_bits + ROUND_COUNT + j) & 0xff]);
            }
            if ct_bits < 512 {
                s[l64 - 1] &= mask;
            }

            Self::subcipher_decrypt(&mut s, &spice, kx, buf, ct_bits, mask, i);

            for j in 0..ROUND_COUNT {
                s[j] = s[j].wrapping_sub(kx[(ct_bits + j) & 0xff]);
            }
            s[0] = s[0].wrapping_sub(i as u64);
            if ct_bits < 512 {
                s[l64 - 1] &= mask;
            }
        }

        store_state(&s, l64, &mut buf[..byte_limit]);
    }

    /// Dispatches to the appropriate sub-cipher encrypt based on `CIPHER_ID`.
    fn subcipher_encrypt(
        s: &mut [u64; ROUND_COUNT],
        spice: &[u64; ROUND_COUNT],
        kx: &[u64; KX_SIZE],
        _buf: &mut [u8],
        block_size_bits: usize,
        mask: u64,
        backup: usize,
    ) {
        if CIPHER_ID == CIPHER_ID_SHORT {
            hpc_short_encrypt(s, spice, kx, block_size_bits, mask, backup);
        } else if CIPHER_ID == CIPHER_ID_MEDIUM {
            hpc_medium_encrypt(s, spice, kx, block_size_bits, mask, backup);
        } else if CIPHER_ID == CIPHER_ID_LONG {
            hpc_long_encrypt(s, spice, kx, block_size_bits, mask, backup);
        }
    }

    /// Dispatches to the appropriate sub-cipher decrypt based on `CIPHER_ID`.
    fn subcipher_decrypt(
        s: &mut [u64; ROUND_COUNT],
        spice: &[u64; ROUND_COUNT],
        kx: &[u64; KX_SIZE],
        _buf: &mut [u8],
        block_size_bits: usize,
        mask: u64,
        backup: usize,
    ) {
        if CIPHER_ID == CIPHER_ID_SHORT {
            hpc_short_decrypt(s, spice, kx, block_size_bits, mask, backup);
        } else if CIPHER_ID == CIPHER_ID_MEDIUM {
            hpc_medium_decrypt(s, spice, kx, block_size_bits, mask, backup);
        } else if CIPHER_ID == CIPHER_ID_LONG {
            hpc_long_decrypt(s, spice, kx, block_size_bits, mask, backup);
        }
    }
}

/// Generates the struct definition and all cipher trait impls for one HPC sub-cipher.
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
                Self {
                    kx: [0; KX_SIZE],
                    backup: [0; BACKUP_SIZE],
                }
            }
        }

        impl HastyPuddingBase<{ $cipher_id }> for $name {
            fn new_raw(kx: &[u64; KX_SIZE], backup: &[usize; BACKUP_SIZE]) -> Self {
                Self {
                    kx: *kx,
                    backup: *backup,
                }
            }

            fn kx(&self) -> &[u64; KX_SIZE] {
                &self.kx
            }

            fn backup(&self) -> &[usize; BACKUP_SIZE] {
                &self.backup
            }
        }

        impl KeySizeUser for $name {
            type KeySize = U16;
        }

        impl KeyInit for $name {
            fn new(key: &cipher::Key<Self>) -> Self {
                Self::cipher_init(key)
            }

            fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
                Ok(Self::cipher_init(key))
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
            fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
                let mut buf = *block.get_in();
                self.hpc_encrypt(buf.as_mut(), &[]);
                *block.get_out() = buf;
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
            fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
                let mut buf = *block.get_in();
                self.hpc_decrypt(buf.as_mut(), &[]);
                *block.get_out() = buf;
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
