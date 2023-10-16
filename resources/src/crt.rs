use libc::c_void;

#[allow(non_snake_case)]
pub type size_t = usize;

extern "C" {
    fn mini_memcpy(
        dest: *mut c_void,
        src: *const c_void,
        count: usize,
    ) -> *const c_void;
    fn mini_memmove(
        dest: *mut c_void,
        src: *const c_void,
        count: usize,
    ) -> *const c_void;
    fn mini_memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32;
    fn mini_memset(s: *mut u8, c: u8, n: usize) -> *mut u8;
}

#[no_mangle]
unsafe extern "C" fn memcpy(
    dest: *mut c_void,
    src: *const c_void,
    count: usize,
) -> *const c_void {
    mini_memcpy(dest, src, count)
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn memmove(
    dest: *mut c_void,
    src: *const c_void,
    count: usize,
) -> *const c_void {
    mini_memmove(dest, src, count)
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
    mini_memcmp(s1, s2, n)
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn memset(s: *mut u8, c: u8, n: usize) -> *mut u8 {
    mini_memset(s, c, n)
}