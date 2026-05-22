//! Generates variable-key KATs in the format used by the NIST AES competition.
//! See `./reference/NIST` for the NIST provided examples of the KAT format.

use std::{
    fmt,
    fs::File,
    io::{self, BufWriter, prelude::*},
    path::{Path, PathBuf},
};

use cipher::{AlgorithmName, Block, BlockCipherEncrypt, BlockSizeUser, KeyInit};
use cryptobscura::{
    frog::Frog,
    util::{AuthorName, binary_to_hex_string},
};

/// Result output directory
const KAT_DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/data");

struct AlgName<C: AlgorithmName>(core::marker::PhantomData<C>);
struct AuthName<C: AuthorName>(core::marker::PhantomData<C>);

impl<C: AlgorithmName> fmt::Display for AlgName<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        C::write_alg_name(f)
    }
}

impl<C: AuthorName> fmt::Display for AuthName<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        C::write_author_name(f)
    }
}

/// Build the output path for a KAT file: `<KAT_DATA_DIR>/ecb_<variant>_<cipher>.txt`.
fn kat_path<C: AlgorithmName>(variant: &str) -> PathBuf {
    let name = format!("{}", AlgName::<C>(core::marker::PhantomData)).to_lowercase();
    Path::new(KAT_DATA_DIR).join(format!("ecb_{variant}_{name}.txt"))
}

/// Encode `bytes` as a hex string using NIST/C reference byte order (last byte first).
fn to_nist_hex(bytes: &[u8]) -> String {
    let mut buf = vec![0_u8; bytes.len() * 2];
    let _ = binary_to_hex_string(bytes, &mut buf);
    String::from_utf8(buf).unwrap()
}

/// Write NIST style KAT file header to `writer`.
fn write_header(
    writer: &mut impl Write,
    path: &Path,
    test_mode: &str,
    aname: &dyn fmt::Display,
    authname: &dyn fmt::Display,
) -> io::Result<()> {
    let fname = path.file_name().unwrap().to_str().unwrap();
    write!(
        writer,
        r#"
=========================

FILENAME:  "{fname}"

Electronic Codebook (ECB) Mode
{test_mode}

Algorithm Name: {aname}
Principal Submitter: {authname}

"#
    )
}

/// Generate the NIST KATs for a constant plaintext with variable keys.
fn gen_variable_key_kat<C>(
    output_path: &Path,
    plaintext: &Block<C>,
    key_sizes: &[usize],
) -> io::Result<()>
where
    C: AlgorithmName + AuthorName + KeyInit + BlockCipherEncrypt + BlockSizeUser,
{
    let mut writer = BufWriter::new(File::create(output_path)?);

    write_header(
        &mut writer,
        output_path,
        "Variable Key Known Answer Tests",
        &AlgName::<C>(core::marker::PhantomData),
        &AuthName::<C>(core::marker::PhantomData),
    )?;

    let pt_hex = to_nist_hex(&plaintext[..]);

    for &key_bytes in key_sizes {
        write!(
            writer,
            "==========\n\nKEYSIZE={ksize}\n\nPT={pt_hex}\n\n",
            ksize = key_bytes * 8
        )?;
        let mut test_count: usize = 1;
        for byte_idx in 0..key_bytes {
            for bit_idx in 0..8 {
                let mut block = Block::<C>::default();
                block.copy_from_slice(&plaintext[..]);

                let mut key = vec![0_u8; key_bytes];
                key[key_bytes - byte_idx - 1] = 1 << (8 - bit_idx - 1);

                let cipher = C::new_from_slice(&key).unwrap();
                BlockCipherEncrypt::encrypt_block(&cipher, &mut block);

                let key_hex = to_nist_hex(&key);
                let ct_hex = to_nist_hex(&block[..]);

                write!(writer, "I={test_count}\nKEY={key_hex}\nCT={ct_hex}\n\n")?;
                test_count += 1;
            }
        }
    }
    Ok(())
}

/// Generate the NIST KATs for a constant key with variable plaintext.
fn gen_variable_pt_kat<C>(output_path: &Path, keys: &[Vec<u8>]) -> io::Result<()>
where
    C: AlgorithmName + AuthorName + KeyInit + BlockCipherEncrypt + BlockSizeUser,
{
    let mut writer = BufWriter::new(File::create(output_path)?);

    write_header(
        &mut writer,
        output_path,
        "Variable Text Known Answer Tests",
        &AlgName::<C>(core::marker::PhantomData),
        &AuthName::<C>(core::marker::PhantomData),
    )?;

    let block_size = Block::<C>::default().len();

    for key in keys {
        let key_hex = to_nist_hex(key);
        write!(
            writer,
            "==========\n\nKEYSIZE={ksize}\n\nKEY={key_hex}\n\n",
            ksize = key.len() * 8
        )?;
        let mut test_count: usize = 1;
        for byte_idx in 0..block_size {
            for bit_idx in 0..8 {
                let mut plaintext = vec![0_u8; block_size];
                plaintext[block_size - byte_idx - 1] = 1 << (8 - bit_idx - 1);

                let mut block = Block::<C>::default();
                block.copy_from_slice(&plaintext);

                let cipher = C::new_from_slice(key).unwrap();
                BlockCipherEncrypt::encrypt_block(&cipher, &mut block);

                let pt_hex = to_nist_hex(&plaintext);
                let ct_hex = to_nist_hex(&block[..]);

                write!(writer, "I={test_count}\nPT={pt_hex}\nCT={ct_hex}\n\n")?;
                test_count += 1;
            }
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    /// Key lengths to export (bytes).
    const KEY_LENGTHS: [usize; 3] = [16, 24, 32];

    gen_variable_key_kat::<Frog>(
        &kat_path::<Frog>("vk"),
        &Block::<Frog>::default(),
        &KEY_LENGTHS,
    )?;
    let keys: [Vec<u8>; 3] = KEY_LENGTHS.map(|len| vec![0_u8; len]);
    gen_variable_pt_kat::<Frog>(&kat_path::<Frog>("vt"), &keys)?;
    Ok(())
}
