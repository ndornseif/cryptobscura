/// Tiny fast PRNG (Lehmer/LCG variant) for generating test data.
///
/// # Usage
/// ```
/// use common::Lehmer64;
/// let mut prng = Lehmer64::new(0x123456789ABCDEF);
/// assert_eq!(0, prng.next_u64());
/// assert_eq!(0, prng.next_u64());
///
/// let mut buffer = [0_u8; 3];
/// prng.fill_bytes(&mut buffer);
/// assert_eq!([0, 1, 3], buffer);
/// ```
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
