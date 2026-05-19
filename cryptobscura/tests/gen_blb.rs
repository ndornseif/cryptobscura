//! KAT file generator — run by setting `REGEN_KATS=1`:
//!
//! ```text
//! REGEN_KATS=1 cargo test regen_frog_kats -- --nocapture
//! ```
//!
//! The generated `.blb` files are committed to the repository.
//! They should only be regenerated when the C implementation changes, 
//! or new test vectors are added.
#![allow(missing_docs)]
mod common;

use common::frog_ref;
use blobby::encode_blobs;
use std::{fs, path::Path};
use cryptobscura::util::Direction;

const BLB_DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");

fn push(blobs: &mut Vec<Vec<u8>>, key: &[u8], pt: &[u8; frog_ref::BLOCK_SIZE], ik: &mut [frog_ref::CIterKey; 8]) {
    blobs.push(key.to_vec());
    blobs.push(pt.to_vec());
    blobs.push(frog_ref::encrypt(ik, pt).to_vec());
}

fn gen_for_key_size(key_size: usize) -> (String, Vec<u8>) {
    let mut blobs: Vec<Vec<u8>> = Vec::new();
    let bs = frog_ref::BLOCK_SIZE;
    let zero_pt = [0u8; frog_ref::BLOCK_SIZE];
    let ones_pt = [0xFFu8; frog_ref::BLOCK_SIZE];

    // Variable-key: one bit set per bit of the key, zero plaintext.
    for byte_idx in 0..key_size {
        for bit_idx in 0..8u8 {
            let mut key = vec![0u8; key_size];
            key[key_size - byte_idx - 1] = 1 << (7 - bit_idx);
            let mut ik = frog_ref::setup_ik(&key, Direction::Encrypt);
            push(&mut blobs, &key, &zero_pt, &mut ik);
        }
    }

    // Variable-text: zero key, one bit set per bit of the plaintext.
    {
        let zero_key = vec![0u8; key_size];
        let mut ik = frog_ref::setup_ik(&zero_key, Direction::Encrypt);
        for byte_idx in 0..bs {
            for bit_idx in 0..8u8 {
                let mut pt = [0u8; frog_ref::BLOCK_SIZE];
                pt[bs - byte_idx - 1] = 1 << (7 - bit_idx);
                push(&mut blobs, &zero_key, &pt, &mut ik);
            }
        }
    }

    // Corner cases: all-zeros, all-ones, cross combinations.
    for &(kfill, pfill) in &[(0x00u8, 0x00u8), (0xFF, 0xFF), (0x00, 0xFF), (0xFF, 0x00)] {
        let mut key = vec![kfill; key_size];
        let pt = [pfill; frog_ref::BLOCK_SIZE];
        let mut ik = frog_ref::setup_ik(&key, Direction::Encrypt);
        push(&mut blobs, &mut key, &pt, &mut ik);
    }

    // Walking byte in key: one byte = 0xFF, rest 0x00; zero plaintext.
    for byte_idx in 0..key_size {
        let mut key = vec![0u8; key_size];
        key[byte_idx] = 0xFF;
        let mut ik = frog_ref::setup_ik(&key, Direction::Encrypt);
        push(&mut blobs, &key, &zero_pt, &mut ik);
    }

    // Alternating patterns: 0x55 and 0xAA in key and plaintext.
    for &fill in &[0x55u8, 0xAA] {
        let mut key = vec![fill; key_size];
        let mut ik = frog_ref::setup_ik(&key, Direction::Encrypt);
        push(&mut blobs, &mut key, &zero_pt, &mut ik);
        push(&mut blobs, &mut key, &ones_pt, &mut ik);

        let zero_key = vec![0u8; key_size];
        let mut ik_zero = frog_ref::setup_ik(&zero_key, Direction::Encrypt);
        let pt = [fill; frog_ref::BLOCK_SIZE];
        push(&mut blobs, &zero_key, &pt, &mut ik_zero);
    }

    let count = blobs.len() / 3;
    let (encoded, _) = encode_blobs(&blobs);
    let fname = format!("frog_{}.blb", key_size * 8);
    println!("  {fname}: {count} vectors");
    (fname, encoded)
}

/// Regenerate `tests/data/frog_*.blb` from the C reference implementation.
///
/// Skipped unless `REGEN_KATS=1` is set.
#[test]
fn regen_frog_kats() {
    if std::env::var_os("REGEN_KATS").is_none() {
        return;
    }
    fs::create_dir_all(BLB_DATA_DIR).expect("create tests/data");
    println!("Generating FROG KAT files:");
    for key_size in [16usize, 24, 32] {
        let (fname, data) = gen_for_key_size(key_size);
        let path = Path::new(BLB_DATA_DIR).join(&fname);
        fs::write(&path, &data).unwrap_or_else(|e| panic!("write {fname}: {e}"));
    }
}
