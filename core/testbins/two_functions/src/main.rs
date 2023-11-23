use std::arch::asm;
use std::hint::black_box;

fn main() {
    let a = -7;
    let b = 5;
    let result = black_box(calc(a, b));
    println!("hi {}", result);
    let result = black_box(calc_2( result,  b - result));
    println!("hi {}", result);
}

#[inline(never)]
fn calc(a: i32, b: i32) -> i32 {
    let mut result = 0;
    result += black_box(a * b - result);
    result
}

#[inline(never)]
fn calc_2(a: i32, b: i32) -> i32 {
    let mut result = 0;
    for i in a..a+b {
        result += i;
    }
    result
}