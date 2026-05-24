//! Tests the HPC Rust implementation against the C reference on pseudorandom data.
mod common;

use common::{Lehmer64, hex, hpc_ref};
use cryptobscura::hasty_pudding::{
    HastyPuddingMedium,
    cipher::{
        Block, BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit,
        typenum::Unsigned as _,
    },
};

type Medium = HastyPuddingMedium;
const MEDIUM_BLOCK_SIZE: usize = <Medium as BlockSizeUser>::BlockSize::USIZE;
const MEDIUM_BLOCK_BITS: usize = MEDIUM_BLOCK_SIZE * 8;

/// Builds C and Rust cipher state for `key`, then encrypts and decrypts
/// `pt_count` random plaintexts, asserting that both implementations agree.
fn compare_medium_vs_c(rng: &mut Lehmer64, key: &[u8], pt_count: usize) {
    let rust_cipher = Medium::new_from_slice(key).unwrap();
    let mut c_state = hpc_ref::init(key);

    for _ in 0..pt_count {
        let mut pt = [0u8; MEDIUM_BLOCK_SIZE];
        rng.fill_bytes(&mut pt);

        // Encrypt
        let c_ct = hpc_ref::encrypt(&mut c_state, &pt, MEDIUM_BLOCK_BITS);

        let mut rust_block = Block::<Medium>::default();
        rust_block.copy_from_slice(&pt);
        BlockCipherEncrypt::encrypt_block(&rust_cipher, &mut rust_block);
        let rust_ct: [u8; MEDIUM_BLOCK_SIZE] = rust_block.into();

        assert_ne!(
            &pt[..],
            c_ct.as_slice(),
            "C encrypt left block unchanged\n  key={} pt={}",
            hex(key),
            hex(&pt)
        );
        assert_ne!(
            &pt[..],
            &rust_ct[..],
            "Rust encrypt left block unchanged\n  key={} pt={}",
            hex(key),
            hex(&pt)
        );
        assert_eq!(
            c_ct.as_slice(),
            &rust_ct[..],
            "C/Rust encrypt mismatch\n  key={}\n   pt={}\n  C ct={}\nRust ct={}",
            hex(key),
            hex(&pt),
            hex(&c_ct),
            hex(&rust_ct)
        );

        // Decrypt
        let c_pt = hpc_ref::decrypt(&mut c_state, &c_ct, MEDIUM_BLOCK_BITS);
        BlockCipherDecrypt::decrypt_block(&rust_cipher, &mut rust_block);
        let rust_pt: [u8; MEDIUM_BLOCK_SIZE] = rust_block.into();

        assert_eq!(
            c_pt.as_slice(),
            &pt[..],
            "C decrypt failed to recover plaintext\n  key={}\n   ct={}\n  C pt={}",
            hex(key),
            hex(&c_ct),
            hex(&c_pt)
        );
        assert_eq!(
            &rust_pt[..],
            &pt[..],
            "Rust decrypt failed to recover plaintext\n  key={}\n   ct={}\nRust pt={}",
            hex(key),
            hex(&c_ct),
            hex(&rust_pt)
        );
    }
}

/// High-volume C comparison across the three AES-competition key sizes.
#[test]
fn test_hpc_medium_vs_c_aes_key_sizes() {
    const KEY_SIZES: &[usize] = &[16, 24, 32];
    const KEY_COUNT: usize = 32;
    const PLAINTEXT_COUNT: usize = 32;
    const SEED: u128 = 0x1a2b_3c4d_5e6f_7891_0a1b_2c3d_4e5f_6071;

    let mut rng = Lehmer64::new(SEED);
    for &key_len in KEY_SIZES {
        for _ in 0..KEY_COUNT {
            let mut key = vec![0u8; key_len];
            rng.fill_bytes(&mut key);
            compare_medium_vs_c(&mut rng, &key, PLAINTEXT_COUNT);
        }
    }
}

/// C comparison for non-AES key sizes, including empty and short keys.
#[test]
fn test_hpc_medium_vs_c_various_key_sizes() {
    const KEY_SIZES: &[usize] = &[0, 1, 8, 64];
    const KEY_COUNT: usize = 4;
    const PLAINTEXT_COUNT: usize = 8;
    const SEED: u128 = 0x7f8a_9b0c_1d2e_3f40_5061_7283_9405_a6b7;

    let mut rng = Lehmer64::new(SEED);
    for &key_len in KEY_SIZES {
        for _ in 0..KEY_COUNT {
            let mut key = vec![0u8; key_len];
            rng.fill_bytes(&mut key);
            compare_medium_vs_c(&mut rng, &key, PLAINTEXT_COUNT);
        }
    }
}
