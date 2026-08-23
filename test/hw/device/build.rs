// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! Put memory.x where cortex-m-rt's link.x will find it.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set for a build script"));
    fs::write(out.join("memory.x"), include_bytes!("memory.x")).expect("memory.x is writable");

    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=build.rs");
}
