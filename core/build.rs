use std::process::Command;
use std::env;

fn main() {
    let path = env::var("CARGO_MANIFEST_DIR").unwrap().replace(
        "\\core", "\\vm-build",
    );
    let mut cargo_vars = Vec::new();
    for (var, _) in env::vars() {
        if var.to_ascii_lowercase().starts_with("cargo_") {
            cargo_vars.push(var);
        }
    }
    let mut command = Command::new("cargo");

    for var in cargo_vars {
        command.env_remove(var);
    }

    let status = command.current_dir(path.clone())
        .args(&["b", "--release", "--target", "x86_64-pc-windows-msvc"])
        .status().unwrap();
    assert!(status.success(), "could not build vm");
}
