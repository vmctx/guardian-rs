#[cfg(not(feature = "testing"))]
fn main() {
    println!("cargo:rustc-link-search=C:\\Users\\Joshua\\ClionProjects\\obfuscator\\vm\\libs");
    println!("cargo:rustc-link-search=libs");
    println!("cargo:rustc-link-lib=minicrt");
}

#[cfg(feature = "testing")]
fn main() { }