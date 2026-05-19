//! Tests the FROG Rust implementation against the C reference on pseudorandom data
//! and performs the KATs contained in blobby files in `./tests/data`.
mod common;

use common::{Lehmer64, frog_ref, hex};
use cryptobscura::{
    frog::{
        Frog,
        cipher::{
            Block, BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit,
            typenum::Unsigned,
        },
    },
    util::Direction,
};

type Cipher = Frog;
const BLOCK_SIZE: usize = <Cipher as BlockSizeUser>::BlockSize::USIZE;

/// Builds C and Rust cipher state for `key`, then encrypts and decrypts
/// `pt_count` random plaintexts, asserting that both implementations agree.
fn compare_vs_c(rng: &mut Lehmer64, key: &[u8], pt_count: usize) {
    let rust_cipher = Cipher::new_from_slice(key).unwrap();
    let mut ik_enc = frog_ref::setup_ik(key, Direction::Encrypt);
    let mut ik_dec = frog_ref::setup_ik(key, Direction::Decrypt);

    for _ in 0..pt_count {
        let mut pt = [0_u8; BLOCK_SIZE];
        rng.fill_bytes(&mut pt);

        // Encrypt
        let c_ct = frog_ref::encrypt(&mut ik_enc, &pt);

        let mut rust_block = Block::<Cipher>::default();
        rust_block.copy_from_slice(&pt);
        BlockCipherEncrypt::encrypt_block(&rust_cipher, &mut rust_block);
        let rust_ct: [u8; BLOCK_SIZE] = rust_block.into();

        assert_ne!(
            pt,
            c_ct,
            "C encrypt left block unchanged\n  key={} pt={}",
            hex(key),
            hex(&pt)
        );
        assert_ne!(
            pt,
            rust_ct,
            "Rust encrypt left block unchanged\n  key={} pt={}",
            hex(key),
            hex(&pt)
        );
        assert_eq!(
            c_ct,
            rust_ct,
            "C/Rust encrypt mismatch\n  key={}\n   pt={}\n  C ct={}\nRust ct={}",
            hex(key),
            hex(&pt),
            hex(&c_ct),
            hex(&rust_ct)
        );

        // Decrypt
        let c_pt = frog_ref::decrypt(&mut ik_dec, &c_ct);
        BlockCipherDecrypt::decrypt_block(&rust_cipher, &mut rust_block);
        let rust_pt: [u8; BLOCK_SIZE] = rust_block.into();

        assert_eq!(
            pt,
            c_pt,
            "C decrypt failed to recover plaintext\n  key={}\n   ct={}\n  C pt={}",
            hex(key),
            hex(&c_ct),
            hex(&c_pt)
        );
        assert_eq!(
            pt,
            rust_pt,
            "Rust decrypt failed to recover plaintext\n  key={}\n   ct={}\nRust pt={}",
            hex(key),
            hex(&c_ct),
            hex(&rust_pt)
        );
    }
}

/// High-volume C comparison across the three AES-competition key sizes.
#[test]
fn test_frog_vs_c_aes_key_sizes() {
    const KEY_SIZES: &[usize] = &[16, 24, 32];
    const KEY_COUNT: usize = 64;
    const PLAINTEXT_COUNT: usize = 64;
    const SEED: u128 = 0x95dd_4194_6904_2c94_94ab_132a012c_d540;

    let mut rng = Lehmer64::new(SEED);
    for &key_len in KEY_SIZES {
        for _ in 0..KEY_COUNT {
            let mut key = vec![0_u8; key_len];
            rng.fill_bytes(&mut key);
            compare_vs_c(&mut rng, &key, PLAINTEXT_COUNT);
        }
    }
}

/// C comparison for non-AES key sizes.
#[test]
fn test_frog_vs_c_non_aes_key_sizes() {
    const KEY_SIZES: &[usize] = &[5, 6, 7, 15, 17, 57, 124, 125];
    const KEY_COUNT: usize = 2;
    const PLAINTEXT_COUNT: usize = 2;
    const SEED: u128 = 0x2619_c491_e083_8d85_96c8_80b7_5131_ef15;

    let mut rng = Lehmer64::new(SEED);
    for &key_len in KEY_SIZES {
        for _ in 0..KEY_COUNT {
            let mut key = vec![0_u8; key_len];
            rng.fill_bytes(&mut key);
            compare_vs_c(&mut rng, &key, PLAINTEXT_COUNT);
        }
    }
}

// blobby KATs for AES Key sizes.
cipher::block_cipher_test!(frog_kat_128, "frog_128", Frog);
cipher::block_cipher_test!(frog_kat_192, "frog_192", Frog);
cipher::block_cipher_test!(frog_kat_256, "frog_256", Frog);
