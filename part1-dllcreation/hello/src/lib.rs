extern crate winapi;
use winapi::um::winnt::*;
use winapi::shared::minwindef::HINSTANCE;
use winapi::um::winuser::MessageBoxA;
use winapi::shared::windef::HWND;
use std::ffi::CString;

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(
    dll_module: HINSTANCE,
    call_reason: u32,
    _: *mut()
) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => attach(),
        DLL_PROCESS_DETACH => detach(),
        _ => ()
    }
    true
}

fn attach() {
    unsafe {
        // Create a message box
        MessageBoxA(0 as HWND,
                    unsafe { CString::new("ZOMG").unwrap().as_ptr() },
                    unsafe { CString::new("hello.dll").unwrap().as_ptr() },
                    Default::default()
        );
    };
}

fn detach() {
    unsafe {
        // Create a message box
        MessageBoxA(0 as HWND,
                    unsafe { CString::new("GOODBYE!").unwrap().as_ptr() },
                    unsafe { CString::new("hello.dll").unwrap().as_ptr() },
                    Default::default()
        );
    };
}

#[no_mangle]
pub extern fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
