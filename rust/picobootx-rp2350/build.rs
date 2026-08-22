// Copyright (C) 2026 Piers Finlayson <piers@piers.rocks>
//
// MIT License

//! Put picobootx.x where the linker can find it.
//!
//! The flash erase's critical part is placed in .ramfunc, and a section name on
//! its own places nothing: it is the consumer's linker script that decides
//! where .ramfunc lands.  picobootx.x is the script that answers for it, and it
//! reaches the link through -Tpicobootx.x, which needs the directory it sits in
//! on the linker's search path.
//!
//! cargo does not carry a dependency's link arguments to the binary being
//! linked, so the flag is the consumer's to add.  What this script can do is
//! make sure that when they add it, the file is there to be found.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set for a build script"));
    fs::write(out.join("picobootx.x"), include_bytes!("picobootx.x"))
        .expect("picobootx.x is writable in OUT_DIR");

    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=picobootx.x");
}
