use std::process::Command;
use std::env;

fn main() {
    let path = env::var("CARGO_MANIFEST_DIR").unwrap().replace(
        "\\core", "\\vm-build",
    );
    Command::new("cargo").env_clear()
        .env("Path", env::var("Path").unwrap())
        .env("TMP", env::var("TMP").unwrap())
        .env("TEMP", env::var("TEMP").unwrap())
        .current_dir(path.clone())
        .args(&["b", "--release", "--target", "x86_64-pc-windows-msvc"])
        .status().unwrap();
}