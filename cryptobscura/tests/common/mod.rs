//! Code common to the testing system.
#![allow(dead_code)]
pub mod frog_ref;
pub mod hpc_ref;

/// Encode `bytes` as a lowercase hex string.
pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write as _;
            write!(s, "{b:02x}").unwrap();
            s
        })
}

/// Tiny fast PRNG (Lehmer/LCG variant) for generating test data.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Lehmer64 {
    state: u128,
}

impl Lehmer64 {
    const MULTIPLIER: u128 = 0xda94_2042_e4dd_58b5;

    /// Initalize new generator with seed.
    ///
    /// Output will only contain zeroes if seed is zero.
    pub fn new(seed: u128) -> Self {
        Self { state: seed }
    }

    /// Generate a pseudorandom `u64`.
    ///
    /// This advances the generator state one step.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(Self::MULTIPLIER);
        (self.state >> 64) as u64
    }

    /// Fill a `u8` buffer with pseudorandom data.
    ///
    /// Advances the generator `ceil(dest.len() / 8)` steps.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }
}
