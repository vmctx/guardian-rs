use std::env::current_dir;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use test_binary::{build_test_binary, TestBinary};
use obfuscator::virt::machine::disassemble;
use obfuscator::virt::virtualizer::virtualize;

// todo write test cases to verify instruction generate
// correct opcodes (size etc)

#[test]
fn binary_hello_world() {
    // build and test normal binary
    let (output, exit_status) = build_and_run("hello_world");

    assert_eq!(output, "hi -18\nhi 82\n");
    assert!(exit_status.success());

    // test virtualized binary
    let (output, exit_status) = virtualize_and_run(
        "hello_world",
        vec!["hello_world::calc".to_owned()]
    );

    assert_eq!(output, "hi -18\nhi 82\n");
    assert!(exit_status.success());
}

#[test]
fn binary_two_functions() {
    // build and test normal binary
    let (output, exit_status) = build_and_run("two_functions");

    assert!(exit_status.success());
    assert_eq!(output, "hi -35\nhi -620\n");

    // test virtualized binary
    let (output, exit_status) = virtualize_and_run(
        "two_functions",
        vec!["two_functions::calc".to_owned(), "two_functions::calc_2".to_owned()]
    );

    assert!(exit_status.success());
    assert_eq!(output, "hi -35\nhi -620\n");
}


fn virtualize_and_run(binary_name: &str, functions: Vec<String>) -> (String, ExitStatus) {
    obfuscator::virtualize_file(
        format!("testbins\\{binary_name}\\target\\release\\{binary_name}.exe").as_str(),
        format!("testbins\\{binary_name}\\target\\{binary_name}.map").as_str(),
        format!("testbins\\{binary_name}\\target\\release\\{binary_name}_vrt.exe").as_str(),
        functions
    );

    run_binary(&format!("testbins\\{binary_name}\\target\\release\\{binary_name}_vrt.exe"))
}

fn build_and_run(binary_name: &str) -> (String, ExitStatus) {
    let test_bin = TestBinary::relative_to_parent(
        binary_name,
        &PathBuf::from_iter(["testbins",binary_name, "Cargo.toml"])
    ).with_profile("release").build().expect("error building test binary");

    run_binary(test_bin.to_str().unwrap())
}

fn run_binary(binary_name: &str) -> (String, ExitStatus) {
    let mut test_bin_subproc = std::process::Command::new(binary_name)
        .stdout(Stdio::piped())
        .spawn().expect("error running test binary");

    let output = test_bin_subproc.wait_with_output()
        .expect("error waiting for test binary");

    (String::from_utf8(output.stdout).unwrap_or_default(), output.status)
}