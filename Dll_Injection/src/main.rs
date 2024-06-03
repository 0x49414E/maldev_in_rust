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
        Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
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

    /// Path to the dll
    #[arg(short, long)]
    dll: String,
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

fn dll_inject(pid: &u32, dll: &str) {
    let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, *pid) };

    let p_address = unsafe { VirtualAllocEx(process, std::ptr::null_mut(), dll.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };

    if p_address.is_null() {
        warn("Couldn't allocate the memory to the process!");
        std::process::exit(0x000100);
    }

    match unsafe { WriteProcessMemory(process, p_address, dll.as_ptr() as _,dll.len(),std::ptr::null_mut()) } {
        0 => {
            warn(format!("WriteProcessMemory failed with error {:?}", std::io::Error::last_os_error()));
            std::process::exit(0x000100);
        },
        _ => (),
    };

    let k32_address = unsafe { GetModuleHandleA("KERNEL32.DLL\0".as_ptr()) };

    if k32_address == 0 {
        warn("Couldn't get k32 address!");
        panic!();
    }
    let loadlib_address = unsafe {
        GetProcAddress(k32_address, "LoadLibraryA\0".as_ptr()) };

    let thread = unsafe { CreateRemoteThread(process,std::ptr::null_mut(),0,Some(std::mem::transmute(loadlib_address)),p_address,0,std::ptr::null_mut())};

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
    let dll_path = args.dll;

    let mut pid : u32 = 0;
    enumerate_process(&process_name, &mut pid);
    dll_inject(&pid, &dll_path);

    info(format!("PID: {:?}", pid));
}
