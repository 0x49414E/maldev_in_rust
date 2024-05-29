use std::fmt::Write;
use std::ffi::{CStr,CString};
use std::os::raw::{c_char,c_void,c_ulong};
use std::winapi::shared::ntdef::{NTSTATUS,PVOID};
use winapi::um::libloaderapi::{GetProcAddress, GetModuleHandleA};

type fnRtlEthernetStringToAddressA = extern "system" fn(
    *const c_char,
    *mut *const c_char,
    PVOID,
    ) -> NTSTATUS;

// GenerateMAC function to create a MAC address string
fn generate_mac(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> String {
    let mut output = String::with_capacity(64);
    write!(&mut output, "{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}", a, b, c, d, e, f).unwrap();
    output
}

fn generate_mac_output(pShellcode: &[u8], buffer: &mut Vec<String>) -> bool {
    let len = pShellcode.len();

    match len % 6 {
        0 => {},
        _ => return false,
    }

    for i in (0..len).step_by(6) {
        let mac = generate_mac(pShellcode[i], pShellcode[i+1],pShellcode[i+2],pShellcode[i+3],
                               pShellcode[i+4],pShellcode[i+5]);
        buffer.push(mac);
    }
    
    true
}

fn mac_deobfuscation(MacArray: &Vec<String>, pp_d_address: &mut *mut u8, p_d_size: &mut usize) -> bool {
    let numberOfElements = (*MacArray).len();
    let sBuffSize = numberOfElements * 6;
    let Terminator : *const c_char = std::ptr::null();
    let mut STATUS : NTSTATUS = std::mem::zeroed::<NTSTATUS>();

    let handle = unsafe { GetModuleHandleA(CString::new("ntdll.dll").unwrap().as_ptr()) };

    let pRtlEthernetStringToAddressA : fnRtlEthernetStringToAddressA = unsafe { std::mem::transmute(GetProcAddress(handle, CString::new("RtlEthernetStringToAddressA").unwrap().as_ptr() )) };

    let layout = std::alloc::Layout::array::<u8>(sBuffSize).unwrap();
    let p_buffer = unsafe { std::alloc::alloc(layout) as *mut u8 };

    let tmp_buffer = p_buffer;

    for i in 0..numberOfElements {
        STATUS = unsafe { pRtlEthernetStringToAddressA(MacArray[i], &mut Terminator, tmp_buffer as PVOID)};
        
        if STATUS != 0x0 {
            eprintln!(
                "[!] RtlEthernetStringToAddressA With Error 0x{:0.8X}", 
                STATUS,
            );
            // Deallocate the buffer in case of error
            unsafe { std::alloc::dealloc(p_buffer, layout) };
            return false;    
        }

        tmp_buffer = tmp_buffer.add(6);
    }

    *pp_d_address = p_buffer;
    *p_d_size = sBuffSize;

    true
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let text = "helloto".to_string();
        let text = text.as_bytes();
        let mac_obfuscated_text = generate_mac(text[0],text[1],text[2],text[3],text[4],text[5]);

        let mut text = "hello world!";
        let mut text = text.as_bytes();
        let mut buffer = Vec::new();
        generate_mac_output(&text, &mut buffer);
        println!("{:?}", buffer);

        let mut deobfuscated_addr : *mut u8 = std::ptr::null_mut();
        let mut deobfuscated_size : usize = 0;

        mac_deobfuscation(&buffer, &mut deobfuscated_addr, &mut deobfuscated_size);

        let deobfuscated_slice = std::slice::from_raw_parts(deobfuscated_addr,deobfuscated_size);

        let h = String::from_utf8(deobfuscated_slice.to_vec()).unwrap();
    }
}
