use std::process::Command;
use std::env;

fn main() {
    let mut cargo_vars = Vec::new();
    env::vars().into_iter().for_each(|(key, _)| if key.starts_with("CARGO_") {
        cargo_vars.push(key);
    });

    let mut command = Command::new("cargo");

    for var in cargo_vars {
        command.env_remove(var);
    }

    let path = env::var("CARGO_MANIFEST_DIR").unwrap()
        .replace("\\core", "\\vm-build", );
    let status = command.current_dir(path)
        .args(&["b", "--release", "--target", "x86_64-pc-windows-msvc"])
        .status().unwrap();
    assert!(status.success(), "could not build vm");
}
