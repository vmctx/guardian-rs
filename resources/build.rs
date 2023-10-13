fn main() {
    println!("cargo:rustc-link-search=resources");
    println!("cargo:rustc-link-lib=minicrt");
}