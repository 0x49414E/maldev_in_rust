use std::thread::Thread;

use winapi::shared::ntdef::{HANDLE, NULL};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::processthreadsapi::{GetCurrentProcessId, OpenThread};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, 
    TH32CS_SNAPTHREAD, 
    THREADENTRY32,
    Thread32First,
    Thread32Next
};
use winapi::um::winnt::THREAD_ALL_ACCESS;
use winapi::shared::minwindef::FALSE;

fn main() {
    println!("Hello, world!");
}

fn GetLocalThreadHandle(
    main_thread_id: usize,
    mut thread_id: usize,
    mut h_thread: HANDLE
) -> bool {

    unsafe {

        let mut current_pid = GetCurrentProcessId();
        let mut snapshot : HANDLE = NULL;
        let mut thr : THREADENTRY32 = std::mem::zeroed();
    
        thr.dwSize = size_of::<THREADENTRY32>() as u32;

        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

        match snapshot {
            INVALID_HANDLE_VALUE => {
                panic!()
            },
            _ => {}
        }

        if Thread32First(snapshot, &mut thr as *mut THREADENTRY32) == 0 {
            panic!()
        }

        loop {
            match Thread32Next(snapshot, &mut thr as *mut THREADENTRY32) {
                0 => {
                    break
                },
                _ => {
                    if thr.th32OwnerProcessID == current_pid && thr.th32ThreadID != main_thread_id.try_into().unwrap() {
                        thread_id = thr.th32ThreadID as usize;
                        h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, thr.th32ThreadID);

                        if h_thread == NULL {
                            panic!()
                        }
                    }
                }
            }
        }

        true
    }
}