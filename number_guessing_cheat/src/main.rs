use std::ffi::OsStr;
use std::ptr::null_mut;
use std::mem;
use std::thread;
use std::time::Duration;
use winapi::um::winnt::{PROCESS_VM_READ, PROCESS_QUERY_INFORMATION, MEMORY_BASIC_INFORMATION};
use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::shared::basetsd::SIZE_T;
use sysinfo::System;
use std::process; // Import std::process for exit functionality

const SIGNATURE: [u8; 10] = *b"TARGET_NUM"; // The signature to look for in memory

#[repr(C)] // Ensure proper layout matching the structure in memory
struct SecretNumberHolder {
    signature: [u8; 10],
    secret_number: u32,
}

fn main() {
    let mut sys = System::new_all();

    loop {
        sys.refresh_all();
        let process = sys.processes_by_name(OsStr::new("game.exe")).next();

        if let Some(process) = process {
            println!("Found game process with PID: {}", process.pid());

            let process_handle = unsafe {
                OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, process.pid().as_u32() as DWORD)
            };

            if process_handle.is_null() {
                println!("Failed to open process handle");
                continue;
            }

            // Get memory ranges used by the process
            let memory_ranges = get_memory_ranges(process_handle);

            // Scan memory for the SecretNumberHolder within each memory region
            for (base_address, size) in &memory_ranges {
                // Scan the entire memory region from base_address to base_address + size
                let start_address = *base_address as usize;
                let end_address = start_address + *size;

                println!(
                    "Scanning memory range from 0x{:X} to 0x{:X}",
                    start_address,
                    end_address
                );

                // Loop over the memory region byte-by-byte to find the signature
                let mut current_address = start_address;
                while current_address < end_address {
                    let mut buffer: [u8; 10] = unsafe { mem::zeroed() };

                    // Read memory at the current address for the signature
                    if read_process_memory(process_handle, current_address as LPVOID, &mut buffer) {
                        // Check if the signature matches
                        if buffer == SIGNATURE {
                            println!("Found signature at address: 0x{:X}", current_address);

                            // Prepare to read the full SecretNumberHolder structure
                            let mut secret_holder: SecretNumberHolder = unsafe { mem::zeroed() };
                            let secret_holder_bytes: &mut [u8] = unsafe {
                                std::slice::from_raw_parts_mut(&mut secret_holder as *mut _ as *mut u8, mem::size_of::<SecretNumberHolder>())
                            };

                            // Read the memory for the entire SecretNumberHolder structure
                            if read_process_memory(process_handle, current_address as LPVOID, secret_holder_bytes) {
                                println!(
                                    "Secret number read from memory: {} at address: 0x{:X}",
                                    secret_holder.secret_number,
                                    current_address
                                );

                                // Exit the program after finding the secret number
                                process::exit(0);
                            }
                        }
                    }

                    current_address += 1; // Move to the next address
                }
            }
        } else {
            println!("Game process not found, retrying...");
        }

        thread::sleep(Duration::from_secs(1)); // Retry every 1 second if game process not found
    }
}

// Function to read memory from a process
fn read_process_memory(process_handle: *mut winapi::ctypes::c_void, address: LPVOID, buffer: &mut [u8]) -> bool {
    let bytes_read = unsafe {
        ReadProcessMemory(
            process_handle,
            address,
            buffer.as_mut_ptr() as LPVOID,
            buffer.len(),
            null_mut()
        )
    };
    bytes_read != 0
}

// Function to get memory ranges of the target process
fn get_memory_ranges(process_handle: *mut winapi::ctypes::c_void) -> Vec<(LPVOID, SIZE_T)> {
    let mut ranges = Vec::new();
    let mut address: LPVOID = 0 as LPVOID;
    let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

    while unsafe { VirtualQueryEx(process_handle, address, &mut mem_info, mem::size_of::<MEMORY_BASIC_INFORMATION>()) } != 0 {
        // Check if the memory region is readable and committed
        if mem_info.State == 0x1000 && mem_info.Protect != 0x2000 { // MEM_COMMIT and PAGE_READWRITE
            ranges.push((mem_info.BaseAddress, mem_info.RegionSize));
        }
        
        // Move to the next memory region
        address = (address as usize + mem_info.RegionSize) as LPVOID; // Move to the next region
    }

    ranges
}
