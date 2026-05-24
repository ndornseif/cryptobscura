//! Build C reference implementations for use in comparison tests.
use std::{env, fs, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // FROG
    let frog_dir = manifest_dir.join("../references/frog");
    let frog_c = frog_dir.join("frog.c");
    let wrapper = out_dir.join("frog_ref.c");
    fs::write(&wrapper, format!("#include \"{}\"\n", frog_c.display())).unwrap();
    cc::Build::new()
        .file(&wrapper)
        .include(&frog_dir)
        .warnings(false)
        .compile("frog_ref");
    println!("cargo:rerun-if-changed=../references/frog/frog.c");
    println!("cargo:rerun-if-changed=../references/frog/frog.h");
    println!("cargo:rerun-if-changed=../references/frog/aes.h");

    // Hasty Pudding Cipher
    let hpc_dir = manifest_dir.join("../references/hasty_pudding");
    cc::Build::new()
        .file(&hpc_dir.join("src/hpc.c"))
        .include(&hpc_dir.join("include"))
        .warnings(false)
        .compile("hpc_ref");
    println!("cargo:rerun-if-changed=../references/hasty_pudding/src/hpc.c");
    println!("cargo:rerun-if-changed=../references/hasty_pudding/include/hpc/hpc.h");
}
