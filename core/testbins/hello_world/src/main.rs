use std::arch::asm;

fn main() {
    let a = -7;
    let b = 5;
    let result = calc(a, b);
    println!("hi {}", result);
    let result = calc(result, b - result);
    println!("hi {}", result);
}

#[inline(never)]
fn calc(a: i32, b: i32) -> i32 {
    let mut result = 0;
    for i in a..b {
        result += i;
    }
    result
}