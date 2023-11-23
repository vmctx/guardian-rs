fn main() {
    println!("cargo:rustc-link-arg=/MAP:target/{}.map", env!("CARGO_PKG_NAME"));
    println!("cargo:rustc-env=-Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --target x86_64-pc-windows-msvc")
}