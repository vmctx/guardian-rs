use std::env;

fn main() {
    println!("cargo:rerun-if-changed=../vm");
    let cargo_make = env::var("CARGO_MAKE");
    // require cargo make to assure vm is built before core
    assert!(cargo_make.is_ok(), "vm changed, please build with cargo make first")
}
