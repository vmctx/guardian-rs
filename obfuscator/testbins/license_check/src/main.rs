use std::arch::asm;
use std::io::{stdin, stdout, Write};
use obfstr::hash;


fn main() {
    let mut password = String::new();
    print!("enter password: ");
    stdout().flush().unwrap();
    stdin().read_line(&mut password).unwrap();

    license_check(password.trim_end());
}

#[inline(never)]
fn license_check(pass: &str) {
    if obfstr::hash(pass) == hash!("s3cretp@ss") {
        println!("yay!");
    } else {
        println!("nuh uh, {pass} is incorrect");
    }
}