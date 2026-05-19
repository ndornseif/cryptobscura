//! Safe wrappers around the FROG C reference implementation.
#![allow(dead_code)]

use cryptobscura::util::Direction;
use std::ffi::c_int;

pub const BLOCK_SIZE: usize = 16;

/// Mirrors `tIterKey` from `frog.h`. Eight of these form one `tInternalKey`.
#[repr(C)]
pub struct CIterKey {
    pub xor_bu: [u8; BLOCK_SIZE],
    pub subst_permu: [u8; 256],
    pub bomb_permu: [u8; BLOCK_SIZE],
}

#[link(name = "frog_ref", kind = "static")]
unsafe extern "C" {
    // hashKey reads key[..key_len] but never writes to the buffer.
    fn hashKey(binary_key: *mut u8, key_len: c_int, random_key: *mut [CIterKey; 8]);
    fn makeInternalKey(direction: u8, key: *mut CIterKey);
    fn encryptFrog(plain_text: *mut u8, key: *mut CIterKey);
    fn decryptFrog(cipher_text: *mut u8, key: *mut CIterKey);
}

/// Expand `key` into a C internal key for the given direction.
pub fn setup_ik(key: &[u8], direction: Direction) -> [CIterKey; 8] {
    let dir_byte: u8 = match direction {
        Direction::Encrypt => 0,
        Direction::Decrypt => 1,
    };
    let mut ik: [CIterKey; 8] = unsafe { std::mem::zeroed() };
    unsafe {
        // Cast to *mut u8: hashKey only reads the key, never writes.
        hashKey(key.as_ptr() as *mut u8, key.len() as c_int, &mut ik);
        makeInternalKey(dir_byte, ik.as_mut_ptr());
    }
    ik
}

/// Encrypt one block using a pre-expanded C internal key.
pub fn encrypt(ik: &mut [CIterKey; 8], pt: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut block = *pt;
    unsafe { encryptFrog(block.as_mut_ptr(), ik.as_mut_ptr()) };
    block
}

/// Decrypt one block using a pre-expanded C internal key.
pub fn decrypt(ik: &mut [CIterKey; 8], ct: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut block = *ct;
    unsafe { decryptFrog(block.as_mut_ptr(), ik.as_mut_ptr()) };
    block
}
