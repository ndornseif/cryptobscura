#![doc = include_str!("../../README.md")]
#![no_std]
extern crate alloc;

// # General TODOS
// Instead of using const BLOCK_SIZE: usize = <Cipher as BlockSizeUser>::BlockSize::USIZE;
//  -> Use the fn block_size() -> usize function implemented for the BlockSizeUser trait.
// Benchmark rust and C version against each other.
// Implement Hasty Pudding cipher

pub mod frog;
pub mod util;
