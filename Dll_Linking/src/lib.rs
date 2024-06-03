extern crate winapi;

use std::ffi::CString;
use std::ptr::null_mut;
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::winnt::LPCSTR;

type AddFunctionPointer = unsafe extern "system" fn(usize, usize) -> usize;

pub fn main() {
    let dll_name = CString::new("part1-dllcreation.dll").expect("CString::new failed");
    let h_module = LoadLibraryA(dll_name.as_ptr() as LPCSTR);
    let func_name = "add";
    let pAdd : AddFunctionPointer = unsafe {std::mem::transmute(GetProcAddress(h_module,func_name.as_ptr() as LPCSTR)) };


    let result = pAdd(2, 2);
    println!("add(2, 2) = {}", result);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        main();
    }
}
