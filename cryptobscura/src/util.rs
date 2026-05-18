//! General utility functions for working with ciphers.  
//!
//! # Encoding convention note
//!
//! //! `hex` encodes bytes left-to-right as is standard convention.
//! `binary_to_hex_string` / `hex_string_to_binary` use the reversed byte
//! order of the NIST AES candidate test vectors: the first hex pair represents
//! the last byte.  
//! Unless specifically interacting with aforementioned code use `hex`.

use alloc::string::String;
use core::fmt::Write as _;

/// Encode `bytes` as a lowercase hex string.
///
/// # Usage
/// ```
/// use cryptobscura::util::hex;
/// let some_bytes = [0xab_u8, 0xcd, 0xef];
/// assert_eq!("abcdef", hex(&some_bytes));
/// ```
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

fn binary_to_hex_nibble(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        10..=15 => b'a' + n - 10,
        _ => panic!("Invalid nibble"),
    }
}

fn hex_nibble_to_binary(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        b'A'..=b'F' => digit - b'A' + 10,
        _ => panic!("invalid hex digit"),
    }
}

/// Encode `bin` as hex into `out` using NIST/C reference byte order.
///
/// Meaning the nibbles are read left-to-right.
/// Returns the written `&str`, or `None` if `out` is smaller than `2 * bin.len()`.
/// The output hex is lowercase.
///
/// # Usage
/// ```
/// use cryptobscura::util::binary_to_hex_string;
/// let some_bytes = [0xab_u8, 0xcd, 0xef];
/// // Twice the length since each byte becomes two hex digits.
/// // There is no null terminator used.
/// let mut output_buffer = [0_u8; 6];
/// let ret_str = binary_to_hex_string(&some_bytes, &mut output_buffer).unwrap();
/// assert_eq!("efcdab", ret_str);
/// assert_eq!("efcdab", std::str::from_utf8(&output_buffer).unwrap());
/// ```
#[allow(clippy::missing_panics_doc)]
pub fn binary_to_hex_string<'a>(bin: &[u8], out: &'a mut [u8]) -> Option<&'a str> {
    if out.len() < bin.len() * 2 {
        return None;
    }
    for (i, byte) in bin.iter().rev().enumerate() {
        out[i * 2] = binary_to_hex_nibble(byte >> 4);
        out[i * 2 + 1] = binary_to_hex_nibble(byte & 0x0f);
    }
    Some(core::str::from_utf8(&out[..bin.len() * 2]).unwrap())
}

/// Decode `hex` into `out` using NIST/C reference byte order.
///
/// Meaning the nibbles are read left-to-right.
/// Fills `min(out.len(), hex.len() / 2)` bytes.
/// The conversion is not case sensitive.
///
/// # Usage
/// ```
/// use cryptobscura::util::hex_string_to_binary;
/// let some_str = "efcdab";
/// let mut output_buffer = [0_u8; 3];
/// hex_string_to_binary(some_str, &mut output_buffer);
/// assert_eq!([0xab_u8, 0xcd, 0xef], output_buffer);
/// ```
///
/// # Panics
/// - Panics if `hex` contains invalid hex digits.
pub fn hex_string_to_binary(hex: &str, out: &mut [u8]) {
    for (slot, pair) in out.iter_mut().zip(hex.as_bytes().rchunks_exact(2)) {
        *slot = (hex_nibble_to_binary(pair[0]) << 4) | hex_nibble_to_binary(pair[1]);
    }
}

/// These test compare the hex conversion functions against those implemented
/// by FROGs C reference implementation.
#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::{c_char, c_int};

    #[link(name = "frog_ref", kind = "static")]
    unsafe extern "C" {
        // Decodes a hex string into binary, reversed: first hex pair → last byte.
        fn hexStringToBinary(hex: *const c_char, out: *mut u8, binary_len: c_int);
        // Encodes binary into a hex string, reversed: last byte first.
        // Writes 2*binary_len ASCII chars followed by a NUL into `out`.
        fn binaryToHexString(bin: *mut u8, out: *mut c_char, binary_len: c_int);
    }

    // All test vectors are 32-char hex strings = 16-byte binary.
    const BINARY_LEN: usize = 16;
    const HEX_LEN: usize = BINARY_LEN * 2;

    const HEX_VECTORS: &[&[u8; HEX_LEN]] = &[
        b"00000000000000000000000000000000",
        b"80000000000000000000000000000000",
        b"ffffffffffffffffffffffffffffffff",
        b"6ccbd28a71cc30e2a79de52d532a1a1e",
        b"0123456789abcdef0123456789abcdef",
        b"deadbeefcafebabe0123456789abcdef",
    ];

    fn c_hex_to_bin(hex: &[u8; HEX_LEN]) -> [u8; BINARY_LEN] {
        let mut buf = [0u8; BINARY_LEN];
        unsafe {
            hexStringToBinary(
                hex.as_ptr() as *const c_char,
                buf.as_mut_ptr(),
                BINARY_LEN as c_int,
            );
        }
        buf
    }

    fn c_bin_to_hex(bin: &[u8; BINARY_LEN]) -> [u8; HEX_LEN] {
        let mut bin_buf = *bin;
        let mut hex_buf = [0i8; HEX_LEN + 1]; // +1 for NUL
        unsafe {
            binaryToHexString(
                bin_buf.as_mut_ptr(),
                hex_buf.as_mut_ptr(),
                BINARY_LEN as c_int,
            );
        }
        let mut out = [0u8; HEX_LEN];
        for (o, &c) in out.iter_mut().zip(hex_buf[..HEX_LEN].iter()) {
            *o = c as u8; // all hex chars are ASCII (<128), cast is safe
        }
        out
    }

    #[test]
    fn hex_to_bin_matches_c() {
        for &hex in HEX_VECTORS {
            let c = c_hex_to_bin(hex);
            let mut rust = [0u8; BINARY_LEN];
            hex_string_to_binary(core::str::from_utf8(hex).unwrap(), &mut rust);
            assert_eq!(rust, c);
        }
    }

    #[test]
    fn bin_to_hex_matches_c() {
        for &hex in HEX_VECTORS {
            let bin = c_hex_to_bin(hex);
            let c = c_bin_to_hex(&bin);
            let mut out = [0u8; HEX_LEN];
            let rust = binary_to_hex_string(&bin, &mut out).unwrap().as_bytes();
            assert_eq!(rust, c);
        }
    }

    #[test]
    fn round_trip() {
        for &hex in HEX_VECTORS {
            let bin = c_hex_to_bin(hex);
            let mut out_buf = [0u8; HEX_LEN];
            let encoded = binary_to_hex_string(&bin, &mut out_buf).unwrap();
            let mut decoded = [0u8; BINARY_LEN];
            hex_string_to_binary(encoded, &mut decoded);
            assert_eq!(bin, decoded);
        }
    }

    #[test]
    fn binary_to_hex_string_rejects_small_buffer() {
        let bin = [0xde, 0xad, 0xbe, 0xef];
        let mut out = [0u8; 7]; // needs 8
        assert!(binary_to_hex_string(&bin, &mut out).is_none());
    }
}
