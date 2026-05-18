//! Small example to showcase that the cryptobscura ciphers can be used with
//! the existing cipher modes of the RustCrypto ecosystem.

use cbc::cipher::{
    BlockModeDecrypt, BlockModeEncrypt, BlockSizeUser, KeyIvInit, KeySizeUser,
    block_padding::Pkcs7, typenum::Unsigned,
};
use cryptobscura::{frog::Frog, util::hex};

const BLOCK_SIZE: usize = <Frog as BlockSizeUser>::BlockSize::USIZE;
// Frog also supports keys sizes in 5..=125 byte, but defaults to 16.
const KEY_SIZE: usize = <Frog as KeySizeUser>::KeySize::USIZE;

type FrogCbcEnc = cbc::Encryptor<Frog>;
type FrogCbcDec = cbc::Decryptor<Frog>;

fn main() {
    let key: [u8; KEY_SIZE] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let iv: [u8; BLOCK_SIZE] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    // 28 bytes, spans two blocks
    let plaintext = b"FROG block cipher, CBC mode.";

    println!("Key:        {}", hex(&key));
    println!("IV:         {}", hex(&iv));
    println!(
        "Plaintext:  \"{}\"",
        std::str::from_utf8(plaintext).unwrap()
    );

    // Allocate two blocks for PKCS7-padded output.
    let mut enc_buf = [0u8; BLOCK_SIZE * 2];
    enc_buf[..plaintext.len()].copy_from_slice(plaintext);

    let ct = FrogCbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded::<Pkcs7>(&mut enc_buf, plaintext.len())
        .unwrap();

    println!("Ciphertext: {}", hex(ct));

    let mut dec_buf = [0u8; BLOCK_SIZE * 2];
    dec_buf.copy_from_slice(ct);

    let decrypted = FrogCbcDec::new(&key.into(), &iv.into())
        .decrypt_padded::<Pkcs7>(&mut dec_buf)
        .unwrap();

    println!("Decrypted:  {:?}", std::str::from_utf8(decrypted).unwrap());
    println!();
    assert_eq!(plaintext.len(), decrypted.len());
    if plaintext == decrypted {
        println!("Decrypted data matches plaintext.");
    } else {
        println!("ERROR: Decrypted data does not match plaintext.");
    }
}
