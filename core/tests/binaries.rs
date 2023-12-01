use std::io::Write;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use test_binary::TestBinary;
use guardian::Obfuscator;

#[test]
fn binary_hello_world() {
    // build and test normal binary
    let (output, exit_status) = build_and_run("hello_world", None);

    assert_eq!(output, "hi -18\nhi 82\n");
    assert!(exit_status.success());

    // test virtualized binary
    let (output, exit_status) = virtualize_and_run(
        "hello_world",
        vec!["hello_world::calc".to_owned()],
        None
    );

    assert_eq!(output, "hi -18\nhi 82\n");
    assert!(exit_status.success());
}

#[test]
fn binary_license_check() {
    // build and test normal binary
    let (output, exit_status) = build_and_run("license_check", Some("s3cretp@ss"));

    assert_eq!(output, "enter password: yay!\n");
    assert!(exit_status.success());

    // test virtualized binary
    let (output, exit_status) = virtualize_and_run(
        "license_check",
        vec!["license_check::license_check".to_owned()],
        Some("s3cretp@ss")
    );

    assert_eq!(output, "enter password: yay!\n");
    assert!(exit_status.success());
}

#[test]
fn binary_two_functions() {
    // build and test normal binary
    let (output, exit_status) = build_and_run("two_functions", None);

    assert!(exit_status.success());
    assert_eq!(output, "hi -35\nhi -620\n");

    // test virtualized binary
    let (output, exit_status) = virtualize_and_run(
        "two_functions",
        vec!["two_functions::calc".to_owned(), "two_functions::calc_2".to_owned()],
        None
    );

    assert!(exit_status.success());
    assert_eq!(output, "hi -35\nhi -620\n");
}


fn virtualize_and_run(binary_name: &str, functions: Vec<String>, input: Option<&str>) -> (String, ExitStatus) {
    let mut obfuscator = Obfuscator::new(
        format!("testbins\\{binary_name}\\target\\release\\{binary_name}.exe"),
        format!("testbins\\{binary_name}\\target\\release\\{binary_name}_vrt.exe")
    ).unwrap().with_map_file(format!("testbins\\{binary_name}\\target\\{binary_name}.map"));
    obfuscator.use_obfuscation(true);
    obfuscator.add_functions(functions).unwrap();
    obfuscator.virtualize().unwrap();

    run_binary(&format!("testbins\\{binary_name}\\target\\release\\{binary_name}_vrt.exe"), input)
}

fn build_and_run(binary_name: &str, input: Option<&str>) -> (String, ExitStatus) {
    let test_bin = TestBinary::relative_to_parent(
        binary_name,
        &PathBuf::from_iter(["testbins",binary_name, "Cargo.toml"])
    ).with_profile("release").build().expect("error building test binary");

    run_binary(test_bin.to_str().unwrap(), input)
}

fn run_binary(binary_name: &str, input: Option<&str>) -> (String, ExitStatus) {
    let test_bin_subproc = std::process::Command::new(binary_name)
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn().expect("error running test binary");

    if let Some(input) = input {
        test_bin_subproc.stdin.as_ref().take().unwrap()
            .write(input.as_bytes())
            .unwrap();
    }

    let output = test_bin_subproc.wait_with_output()
        .expect("error waiting for test binary");

    (String::from_utf8(output.stdout).unwrap_or_default(), output.status)
}