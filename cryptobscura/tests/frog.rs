//! Test FROG cipher againts C reference implementation.
mod common;

use common::Lehmer64;
use cryptobscura::{
    frog::{
        Frog,
        cipher::{
            Block, BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit,
            typenum::Unsigned,
        },
    },
    util::hex,
};
use std::ffi::c_int;

/// Cipher under test.
type Cipher = Frog;
const BLOCK_SIZE: usize = <Cipher as BlockSizeUser>::BlockSize::USIZE;

#[repr(C)]
struct CIterKey {
    xor_bu: [u8; 16],
    subst_permu: [u8; 256],
    bomb_permu: [u8; 16],
}

#[link(name = "frog_ref", kind = "static")]
unsafe extern "C" {
    fn hashKey(binary_key: *mut u8, key_len: c_int, random_key: *mut [CIterKey; 8]);
    fn makeInternalKey(direction: u8, key: *mut CIterKey);
    fn encryptFrog(plain_text: *mut u8, key: *mut CIterKey);
    fn decryptFrog(cipher_text: *mut u8, key: *mut CIterKey);
}

/// Builds C and Rust cipher state for `key`, then encrypts and decrypts
/// `pt_count` random plaintexts and asserts that both implementations agree.
fn compare_vs_c(rng: &mut Lehmer64, key: &mut [u8], pt_count: usize) {
    let key_len = key.len();
    let rust_cipher = Cipher::new_from_slice(key).unwrap();

    // Safety: CIterKey is repr(C) and matches the C struct layout.
    // hashKey reads key[..key_len] but does not write to the buffer.
    let mut ik_enc: [CIterKey; 8] = unsafe { std::mem::zeroed() };
    let mut ik_dec: [CIterKey; 8] = unsafe { std::mem::zeroed() };
    unsafe {
        hashKey(key.as_mut_ptr(), key_len as c_int, &mut ik_enc);
        makeInternalKey(0_u8 /* DIR_ENCRYPT */, ik_enc.as_mut_ptr());
        hashKey(key.as_mut_ptr(), key_len as c_int, &mut ik_dec);
        makeInternalKey(1_u8 /* DIR_DECRYPT */, ik_dec.as_mut_ptr());
    }

    for _ in 0..pt_count {
        let mut pt = [0_u8; BLOCK_SIZE];
        rng.fill_bytes(&mut pt);

        let mut c_ct = pt;
        unsafe {
            encryptFrog(c_ct.as_mut_ptr(), ik_enc.as_mut_ptr());
        }

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

        unsafe {
            decryptFrog(c_ct.as_mut_ptr(), ik_dec.as_mut_ptr());
        }
        BlockCipherDecrypt::decrypt_block(&rust_cipher, &mut rust_block);
        let rust_pt: [u8; BLOCK_SIZE] = rust_block.into();

        assert_eq!(
            pt,
            c_ct,
            "C decrypt failed to recover plaintext\n  key={}\n   ct={}\n  C pt={}",
            hex(key),
            hex(&rust_ct),
            hex(&c_ct)
        );
        assert_eq!(
            pt,
            rust_pt,
            "Rust decrypt failed to recover plaintext\n  key={}\n   ct={}\nRust pt={}",
            hex(key),
            hex(&rust_ct),
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
            compare_vs_c(&mut rng, &mut key, PLAINTEXT_COUNT);
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
            compare_vs_c(&mut rng, &mut key, PLAINTEXT_COUNT);
        }
    }
}
