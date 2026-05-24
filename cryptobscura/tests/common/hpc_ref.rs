//! Safe wrappers around the HPC C reference implementation.
#![allow(dead_code)]

use std::ffi::c_int;

const C_HPC_KX_SIZE: usize = 256;
const C_HPC_CIPHER_COUNT: usize = 5;
const C_HPC_BACKUP_SIZE: usize = C_HPC_CIPHER_COUNT + 1;

/// Mirrors `struct HpcState` from `hpc.h` (without `HPC_USE_SINGLE_KX`).
#[repr(C)]
pub struct HpcState {
    kx: [[u64; C_HPC_KX_SIZE]; C_HPC_CIPHER_COUNT],
    backup: [usize; C_HPC_BACKUP_SIZE],
}

#[link(name = "hpc_ref", kind = "static")]
unsafe extern "C" {
    fn hpc_init(state: *mut HpcState, key: *const u8, key_bit_size: usize) -> c_int;
    fn hpc_encrypt(
        state: *mut HpcState,
        plaintext: *const u8,
        o_ciphertext: *mut u8,
        data_bit_size: usize,
        tweak: *const u8,
        tweak_bit_size: usize,
    ) -> c_int;
    fn hpc_decrypt(
        state: *mut HpcState,
        ciphertext: *const u8,
        o_plaintext: *mut u8,
        data_bit_size: usize,
        tweak: *const u8,
        tweak_bit_size: usize,
    ) -> c_int;
}

/// Initialise a C HPC state from `key`.
pub fn init(key: &[u8]) -> HpcState {
    let mut state = unsafe { std::mem::zeroed::<HpcState>() };
    let ret = unsafe { hpc_init(&mut state, key.as_ptr(), key.len() * 8) };
    assert_eq!(ret, 1, "hpc_init failed");
    state
}

/// Encrypt `block` in place using the C reference. `block_bits` is the block size in bits.
pub fn encrypt(state: &mut HpcState, block: &[u8], block_bits: usize) -> Vec<u8> {
    let mut out = vec![0u8; block.len()];
    let ret = unsafe {
        hpc_encrypt(
            state,
            block.as_ptr(),
            out.as_mut_ptr(),
            block_bits,
            std::ptr::null(),
            0,
        )
    };
    assert_eq!(ret, 1, "hpc_encrypt failed");
    out
}

/// Decrypt `block` in place using the C reference. `block_bits` is the block size in bits.
pub fn decrypt(state: &mut HpcState, block: &[u8], block_bits: usize) -> Vec<u8> {
    let mut out = vec![0u8; block.len()];
    let ret = unsafe {
        hpc_decrypt(
            state,
            block.as_ptr(),
            out.as_mut_ptr(),
            block_bits,
            std::ptr::null(),
            0,
        )
    };
    assert_eq!(ret, 1, "hpc_decrypt failed");
    out
}
