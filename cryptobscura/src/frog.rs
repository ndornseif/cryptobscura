//! FROG block cipher
//!
//! FROG is a variable-key, 128-bit block cipher submitted to NIST's AES competition in 1998
//! by `TecApro` International S.A. (Georgoudis, Leroux, and Chaves).
//! While the cipher itself supports other block sizes, this implementation is only tested
//! for the standard 128 bits.  
//! It was eliminated after
//! the first round of evaluation for a series of reasons including a 
//! 1999 cryptanalysis by Wagner, Ferguson, and Schneier that showcased
//! large sets of weak keys.
//! The defining idea in the design of FROG is to make the encryption procedure
//! itself strongly key dependent. Denying the attacker information about the 
//! ciphers inner workings without keeping the implementation secret.
//!
//! This implementation is based on the designers reference C implementation. 
//! It can be found under `./references/frog/` or in [^1].
//!
//! ## Implementation notes
//!
//! - **Side Channel attacks.** The round S-Box lookup is both key-dependent and data-dependent, 
//!   making this implementation of FROG susceptible to side-channel attacks.
//! - **Zeroization.** Enable the `zeroize` Cargo feature to clear the 4 608-byte key state
//!   from memory when the [`Frog`] value is dropped.
//!
//! The key schedule is computationally expensive relative to the block operation.
//! Since it is performed twice during initalization -- once for decrypt once for encrypt --
//! rekeying is slow compared en- or decryption.
//!
//! The AES version only uses 128, 192 and 256 bit keys, but the ciphers design supports
//! any key in the 5–125 byte range.  
//! [`KeySizeUser::KeySize`] is set to 16 bytes as a canonical value for `RustCrypto`
//! compatibility, use [`KeyInit::new_from_slice`] for other sizes.
//!
//! ## Security
//!
//! **FROG is not recommended for new applications.** It was broken before the AES selection
//! concluded and has never been standardised.
//!
//! Wagner, Ferguson, and Schneier (1999)[^2] found that FROG's diffusion layer
//! provides slow avalance for certain sets of weak keys.  
//! A differential attack on the decryption mode causes 2<sup>−29</sup> of keys
//! to be weak.  
//! This implementation does **not** detect or reject weak keys.
//!
//!
//! ## Example
//!
//! ```
//! use cryptobscura::frog::{
//!     Frog,
//!     cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
//! };
//!
//! let key = [0x42u8; 16];
//! let cipher = Frog::new_from_slice(&key).expect("valid key length");
//!
//! let plaintext = b"FROG example!!! ";
//! let mut block = Block::<Frog>::default();
//! block.copy_from_slice(plaintext);
//!
//! cipher.encrypt_block(&mut block);
//! assert_ne!(block.as_slice(), plaintext);
//! assert_eq!(block.as_slice(), [95_u8, 183, 44, 162, 150, 52, 168, 243, 35, 191, 11, 208, 189, 101, 76, 228]);
//!
//! cipher.decrypt_block(&mut block);
//! assert_eq!(block.as_slice(), plaintext);
//! ```
//!
//! ## References
//!
//![^1]: [D. Georgoudis, D. Leroux, B. S. Chaves, TecApro International S.A.; "The FROG Encryption Algorithm"; 1998](https://web.archive.org/web/20170708064547/http://www.grupolotusbrasil.com.br/grupoconceptprime.com.br/ftp.suporte/util/LIVROS%20E%20TREINAMENTOS/SEGURANCA/criptografia_diciplina/CIE/cd-rom/softwares/Sources/sources.pascal/frog/frog.htm)
//!
//![^2]: [D. Wagner, N. Ferguson, B. Schneier; "Cryptanalysis of Frog,"; Proceedings of the 2nd AES candidate conference; NIST; 1999](https://web.archive.org/web/20251031194144/https://www.schneier.com/wp-content/uploads/2016/02/paper-frog.pdf)

pub use cipher;

use cipher::typenum::Unsigned as _;
use cipher::{
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut,
    InvalidLength, KeyInit, KeySizeUser, ParBlocksSizeUser,
    consts::{U1, U16},
};
use core::fmt;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

const BLOCK_SIZE: usize = <Frog as BlockSizeUser>::BlockSize::USIZE;
const MAX_KEY_SIZE: usize = 125;
const MIN_KEY_SIZE: usize = 5;
const NUM_ITER: usize = 8;
const SUBST_PERMU_SIZE: usize = 1 << u8::BITS;

#[derive(Clone, Copy, Debug, PartialEq)]
/// Defines cipher working direction.
enum Direction {
    Encrypt,
    Decrypt,
}

#[derive(Clone, Copy, Debug)]
/// Round key used by FROG.
/// The full algorithm needs one for each round
/// and direction so 16 in total.
struct IterKey {
    xor_bu: [u8; BLOCK_SIZE],
    subst_permu: [u8; SUBST_PERMU_SIZE],
    bomb_permu: [u8; BLOCK_SIZE],
}

/// Collection of round key required for
/// either encryption or decryption.
type InternalKey = [IterKey; NUM_ITER];

impl Default for IterKey {
    fn default() -> Self {
        Self {
            xor_bu: [0; BLOCK_SIZE],
            subst_permu: [0; SUBST_PERMU_SIZE],
            bomb_permu: [0; BLOCK_SIZE],
        }
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for IterKey {
    fn zeroize(&mut self) {
        self.xor_bu.zeroize();
        self.subst_permu.zeroize();
        self.bomb_permu.zeroize();
    }
}

#[derive(Clone)]
/// The FROG block cipher as submitted to the AES competition.
pub struct Frog {
    enc_keys: InternalKey,
    dec_keys: InternalKey,
}

/// Inverts a permutation array of size `N`.
#[allow(clippy::cast_possible_truncation)]
fn invert_permutation<const N: usize>(permutation: &mut [u8; N]) {
    let mut inverse = [0_u8; N];
    for i in 0..N {
        inverse[permutation[i] as usize] = i as u8;
    }
    *permutation = inverse;
}

/// Receives an arbitrary byte array of size `N` and
/// turns it into a permutation with values between 0 and `N-1`.
/// Reference Text: Section B.1.3
fn make_permutation<const N: usize>(permutation: &mut [u8; N]) {
    let mut use_buf = [0_u8; N];

    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::needless_range_loop)]
    for i in 0..N {
        use_buf[i] = i as u8;
    }

    let mut index: usize = 0;
    let mut remaining = N;

    for sub_perm in permutation.iter_mut().take(N - 1) {
        index = (index + *sub_perm as usize) % remaining;
        *sub_perm = use_buf[index];

        use_buf.copy_within(index + 1..remaining, index);
        remaining -= 1;

        if index >= remaining {
            index = 0;
        }
    }

    permutation[N - 1] = use_buf[0];
}

/// Turn unstructured internal key to valid key.
/// Reference Text: Section B.1.2
#[allow(clippy::cast_possible_truncation)]
fn make_internal_key(direction: Direction, internal_keys: &mut InternalKey) {
    for key in internal_keys.iter_mut().take(NUM_ITER) {
        make_permutation(&mut key.subst_permu);
        if direction == Direction::Decrypt {
            invert_permutation(&mut key.subst_permu);
        }
        make_permutation(&mut key.bomb_permu);

        let mut used = [false; BLOCK_SIZE];
        let mut cur_node: u8 = 0;
        for _ in 0..(BLOCK_SIZE - 1) {
            if key.bomb_permu[cur_node as usize] == 0 {
                let mut free_node = cur_node;

                loop {
                    free_node = (free_node + 1) % (BLOCK_SIZE as u8);
                    if !used[free_node as usize] {
                        break;
                    }
                }

                key.bomb_permu[cur_node as usize] = free_node;
                let mut cycle_tail = free_node;

                while key.bomb_permu[cycle_tail as usize] != free_node {
                    cycle_tail = key.bomb_permu[cycle_tail as usize];
                }
                key.bomb_permu[cycle_tail as usize] = 0;
            }
            used[cur_node as usize] = true;
            cur_node = key.bomb_permu[cur_node as usize];
        }
        for i in 0..BLOCK_SIZE as u8 {
            let next_idx = if i == (BLOCK_SIZE - 1) as u8 {
                0
            } else {
                i + 1
            };
            if key.bomb_permu[i as usize] == next_idx {
                let skip_idx = if next_idx == (BLOCK_SIZE - 1) as u8 {
                    0
                } else {
                    next_idx + 1
                };
                key.bomb_permu[i as usize] = skip_idx;
            }
        }
    }
}

/// Encrypt `plaintext` using `internal_keys`.
/// Reference Text: Section B.1.1
fn encrypt_frog(plaintext: &mut [u8], internal_keys: &InternalKey) {
    for iteration in 0..NUM_ITER {
        for i in 0..BLOCK_SIZE {
            plaintext[i] = internal_keys[iteration].subst_permu
                [(plaintext[i] ^ internal_keys[iteration].xor_bu[i]) as usize];
            if i < (BLOCK_SIZE - 1) {
                plaintext[i + 1] ^= plaintext[i];
            } else {
                plaintext[0] ^= plaintext[i];
            }
            plaintext[internal_keys[iteration].bomb_permu[i] as usize] ^= plaintext[i];
        }
    }
}

/// Decrypt `ciphertext` using `internal_keys`.
/// Reference Text: Section B.1.1
fn decrypt_frog(ciphertext: &mut [u8], internal_keys: &InternalKey) {
    for iteration in (0..NUM_ITER).rev() {
        for i in (0..BLOCK_SIZE).rev() {
            ciphertext[internal_keys[iteration].bomb_permu[i] as usize] ^= ciphertext[i];
            if i < (BLOCK_SIZE - 1) {
                ciphertext[i + 1] ^= ciphertext[i];
            } else {
                ciphertext[0] ^= ciphertext[i];
            }
            ciphertext[i] = internal_keys[iteration].subst_permu[ciphertext[i] as usize]
                ^ internal_keys[iteration].xor_bu[i];
        }
    }
}

/// Hash `binary_key` into a 'random key'.
/// Reference Text: Section B.1.2
#[allow(clippy::cast_possible_truncation)]
fn hash_key(binary_key: &[u8]) -> InternalKey {
    const RANDOM_SEED_SIZE: usize = 251;
    /// Values taken from RAND Corporation's "A Million Random Digits"
    const RANDOM_SEED: [u8; RANDOM_SEED_SIZE] = [
        113, 21, 232, 18, 113, 92, 63, 157, 124, 193, 166, 197, 126, 56, 229, 229, 156, 162, 54,
        17, 230, 89, 189, 87, 169, 0, 81, 204, 8, 70, 203, 225, 160, 59, 167, 189, 100, 157, 84,
        11, 7, 130, 29, 51, 32, 45, 135, 237, 139, 33, 17, 221, 24, 50, 89, 74, 21, 205, 191, 242,
        84, 53, 3, 230, 231, 118, 15, 15, 107, 4, 21, 34, 3, 156, 57, 66, 93, 255, 191, 3, 85, 135,
        205, 200, 185, 204, 52, 37, 35, 24, 68, 185, 201, 10, 224, 234, 7, 120, 201, 115, 216, 103,
        57, 255, 93, 110, 42, 249, 68, 14, 29, 55, 128, 84, 37, 152, 221, 137, 39, 11, 252, 50,
        144, 35, 178, 190, 43, 162, 103, 249, 109, 8, 235, 33, 158, 111, 252, 205, 169, 54, 10, 20,
        221, 201, 178, 224, 89, 184, 182, 65, 201, 10, 60, 6, 191, 174, 79, 98, 26, 160, 252, 51,
        63, 79, 6, 102, 123, 173, 49, 3, 110, 233, 90, 158, 228, 210, 209, 237, 30, 95, 28, 179,
        204, 220, 72, 163, 77, 166, 192, 98, 165, 25, 145, 162, 91, 212, 41, 230, 110, 6, 107, 187,
        127, 38, 82, 98, 30, 67, 225, 80, 208, 134, 60, 250, 153, 87, 148, 60, 66, 165, 72, 29,
        165, 82, 211, 207, 0, 177, 206, 13, 6, 14, 92, 248, 60, 201, 132, 95, 35, 215, 118, 177,
        121, 180, 27, 83, 131, 26, 39, 46, 12,
    ];

    let key_len = binary_key.len();

    let mut simple_key = InternalKey::default();

    // B.1.2a: fill simple_key by XOR-ing the cycling seed with the cycling key
    let mut i_seed: usize = 0;
    let mut i_key: usize = 0;
    let mut fill = |buf: &mut [u8]| {
        for b in buf {
            *b = RANDOM_SEED[i_seed] ^ binary_key[i_key];
            i_seed += 1;
            if i_seed == RANDOM_SEED_SIZE {
                i_seed = 0;
            }
            i_key += 1;
            if i_key == key_len {
                i_key = 0;
            }
        }
    };
    for ik in &mut simple_key {
        fill(&mut ik.xor_bu);
        fill(&mut ik.subst_permu);
        fill(&mut ik.bomb_permu);
    }

    // B.1.2b
    make_internal_key(Direction::Encrypt, &mut simple_key);

    // B.1.2c: init IV from key bytes
    let last = if key_len >= BLOCK_SIZE {
        BLOCK_SIZE - 1
    } else {
        key_len - 2
    };
    let mut iv_buffer = [0_u8; BLOCK_SIZE];
    for i in 0..=last {
        iv_buffer[i] ^= binary_key[i];
    }
    iv_buffer[0] ^= key_len as u8;

    // B.1.2d: fill random_key with successive encryptions of iv_buffer
    // Field sizes (16, 256, 16) are all multiples of BLOCK_SIZE, so each fill
    // lands on a field boundary with no partial-block edge cases.
    let mut random_key = InternalKey::default();
    for ik in &mut random_key {
        encrypt_frog(&mut iv_buffer, &simple_key);
        ik.xor_bu.copy_from_slice(&iv_buffer);
        for chunk in ik.subst_permu.chunks_mut(BLOCK_SIZE) {
            encrypt_frog(&mut iv_buffer, &simple_key);
            chunk.copy_from_slice(&iv_buffer);
        }
        encrypt_frog(&mut iv_buffer, &simple_key);
        ik.bomb_permu.copy_from_slice(&iv_buffer);
    }

    random_key
}

impl KeySizeUser for Frog {
    type KeySize = U16;
}

impl KeyInit for Frog {
    fn new(key: &cipher::Key<Self>) -> Self {
        Self::new_from_slice(key).unwrap()
    }

    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        if key.len() < MIN_KEY_SIZE || key.len() > MAX_KEY_SIZE {
            return Err(InvalidLength);
        }
        let mut enc_keys = hash_key(key);
        let mut dec_keys = enc_keys;
        make_internal_key(Direction::Encrypt, &mut enc_keys);
        make_internal_key(Direction::Decrypt, &mut dec_keys);

        Ok(Self { enc_keys, dec_keys })
    }
}

impl BlockSizeUser for Frog {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for Frog {
    type ParBlocksSize = U1;
}

impl BlockCipherEncrypt for Frog {
    #[inline]
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(self);
    }
}

impl BlockCipherEncBackend for Frog {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut buf = *block.get_in();
        encrypt_frog(buf.as_mut(), &self.enc_keys);
        *block.get_out() = buf;
    }
}

impl BlockCipherDecrypt for Frog {
    #[inline]
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(self);
    }
}

impl BlockCipherDecBackend for Frog {
    #[inline]
    fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut buf = *block.get_in();
        decrypt_frog(buf.as_mut(), &self.dec_keys);
        *block.get_out() = buf;
    }
}

impl fmt::Debug for Frog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FROG { ... }")
    }
}

impl AlgorithmName for Frog {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FROG")
    }
}

#[cfg(feature = "zeroize")]
impl Drop for Frog {
    fn drop(&mut self) {
        for k in &mut self.enc_keys {
            k.zeroize();
        }
        for k in &mut self.dec_keys {
            k.zeroize();
        }
    }
}

/// Provides the name of the cipher's author or submitting organisation.
#[allow(clippy::missing_errors_doc)]
pub trait AuthorName {
    /// Write author name into `f`.
    fn write_author_name(f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

impl AuthorName for Frog {
    fn write_author_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TecApro")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    /// Super basic functionality test.
    fn round_trip() {
        let key = [0x01u8; 16];
        let frog = Frog::new_from_slice(&key).unwrap();

        let plaintext: [u8; BLOCK_SIZE] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let mut block = Block::<Frog>::default();
        block.copy_from_slice(&plaintext);

        BlockCipherEncrypt::encrypt_block(&frog, &mut block);
        assert_ne!(
            block.as_slice(),
            plaintext.as_slice(),
            "block unchanged after encrypt"
        );

        BlockCipherDecrypt::decrypt_block(&frog, &mut block);
        assert_eq!(
            block.as_slice(),
            plaintext.as_slice(),
            "decrypt(encrypt(pt)) != pt"
        );
    }
}
