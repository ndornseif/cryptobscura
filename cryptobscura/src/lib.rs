#![doc = include_str!("../../README.md")]
#![no_std]
extern crate alloc;

// # General TODOS
// Use cipher crate macro for KATs using blobby.
//  -> Implement generating the blobby file from the c functions, but in rust.
//  -> Base on the gen_kat example that already generates NIST compatible KATs.
// Make sure doctest in `./tests/common/mod.rs` are executed.
// Instead of using const BLOCK_SIZE: usize = <Cipher as BlockSizeUser>::BlockSize::USIZE;
//  -> Use the fn block_size() -> usize function implemented for the BlockSizeUser trait.
// Benchmark rust and C version against each other.
// Implement Hasty Pudding cipher

pub mod frog;
pub mod util;
