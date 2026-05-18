//! Build C reference implementations for use in comparison tests.
use std::{env, fs, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let frog_dir = manifest_dir.join("../references/frog");
    let frog_c = frog_dir.join("frog.c");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

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
}
