#[cfg(not(feature = "testing"))]
fn main() {
    use std::path::Path;
    use std::env;

    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-search={}", Path::new(&dir).join("libs").display());
}

#[cfg(feature = "testing")]
fn main() { }