fn main() {
    println!("cargo:rustc-link-search=C:\\Users\\Joshua\\ClionProjects\\obfuscator\\resources\\libs");
    println!("cargo:rustc-link-search=libs");
    println!("cargo:rustc-link-lib=minicrt");
}