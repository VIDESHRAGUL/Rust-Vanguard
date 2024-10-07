use std::collections::HashSet;
use std::ffi::OsStr;
use std::mem;
use std::thread;
use std::time::Duration;
use sysinfo::System; // Only import System
use winapi::um::winnt::{PROCESS_VM_READ, PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_READWRITE}; // Import the required constants
use winapi::um::memoryapi::{VirtualQueryEx, ReadProcessMemory};
use winapi::um::processthreadsapi::{OpenProcess, TerminateProcess};
use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::shared::basetsd::SIZE_T;

const GAME_EXECUTABLE_NAME: &str = "game.exe"; // The target game executable

// Define a struct for storing process information
#[derive(Debug)]
struct ProcessInfo {
    name: String,
    purpose: String,
    memory_access: Vec<(LPVOID, SIZE_T)>, // Store accessed memory regions
    parent_pid: Option<u32>, // Store the parent PID
}

fn main() {
    let mut sys = System::new_all();
    
    // HashSet for known safe processes
    let safe_processes: HashSet<String> = [
        "svchost.exe",
        "SearchHost.exe",
        "chrome.exe",
        "PhoneExperienceHost.exe",
        "explorer.exe",
        "StartMenuExperienceHost.exe",
        "AWCC.exe",
        "RuntimeBroker.exe",
        "dllhost.exe",
        "powershell.exe",
        "GameLibraryAppService.exe",
        "SystemSettings.exe",
        "nvcontainer.exe",
        "ApplicationFrameHost.exe",
        "cargo.exe",
        "taskhostw.exe",
        "backgroundTaskHost.exe",
        "NVIDIA Share.exe",
        "Code.exe", // VS Code
        "Razer Synapse Service Process.exe",
        "SecurityHealthSystray.exe",
        "LocationNotificationWindows.exe",
        // Add more known safe processes as needed
    ].iter().map(|&s| s.to_string()).collect(); // Collect into HashSet<String>

    let mut detected_processes: HashSet<u32> = HashSet::new(); // To store detected PIDs
    let mut accessing_processes: Vec<ProcessInfo> = Vec::new(); // Vector to store information about processes accessing game memory

    loop {
        sys.refresh_all();
        let game_process = sys.processes_by_name(OsStr::new(GAME_EXECUTABLE_NAME)).next();

        if let Some(game) = game_process {
            println!("Found game process with PID: {}", game.pid());

            // Store game's memory ranges (base address and size)
            let game_memory_ranges = get_game_memory_ranges(game.pid().as_u32()); // Use as_u32() to get the PID as u32

            // Check other processes
            for (pid, process) in sys.processes() {
                // Print all processes
                // Check for the cheat process specifically
                if process.name() == OsStr::new("cheat.exe") {
                    println!("Suspicious process found: cheat.exe (PID: {})", pid);
                    
                    // Attempt to terminate the game process
                    let game_handle = unsafe {
                        OpenProcess(PROCESS_TERMINATE, 0, game.pid().as_u32() as DWORD)
                    };

                    if !game_handle.is_null() {
                        let result = unsafe { TerminateProcess(game_handle, 0) };
                        if result != 0 {
                            println!("Successfully terminated game.exe (PID: {}).", game.pid());
                        } else {
                            println!("Failed to terminate game.exe.");
                        }
                    } else {
                        println!("Failed to get handle for game.exe.");
                    }
                    
                    // Break out of the loop or exit the program as needed
                    return; // Exit the program after terminating the game
                }

                if *pid != game.pid() && !safe_processes.contains(process.name().to_string_lossy().as_ref()) {
                    let process_handle = unsafe {
                        OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid.as_u32() as DWORD)
                    };

                    if !process_handle.is_null() {
                        let memory_ranges = get_memory_ranges(process_handle);
                        let mut accessed_memory: Vec<(LPVOID, SIZE_T)> = Vec::new();

                        // Check for access to game memory
                        for (base_address, size) in memory_ranges {
                            if game_memory_ranges.iter().any(|&(game_base, game_size)| {
                                (base_address as usize) >= (game_base as usize) && 
                                (base_address as usize) < ((game_base as usize) + (game_size as usize))
                            }) {
                                // If we haven't detected this process before, add to the vector
                                if !detected_processes.contains(&pid.as_u32()) {
                                    if is_accessing_memory(process_handle, base_address, size) {
                                        accessed_memory.push((base_address, size)); // Store accessed memory

                                        println!(
                                            "Detected suspicious process trying to read game memory: {} (PID: {})",
                                            process.name().to_string_lossy(),
                                            pid
                                        );

                                        detected_processes.insert(pid.as_u32());
                                        let parent_pid = process.parent().map(|p| p.as_u32()); // Get parent PID

                                        accessing_processes.push(ProcessInfo {
                                            name: process.name().to_string_lossy().to_string(),
                                            purpose: get_process_purpose(process.name().to_string_lossy().as_ref()), // Convert OsStr to &str
                                            memory_access: accessed_memory.clone(),
                                            parent_pid,
                                        }); // Add process info to vector
                                    }
                                }
                            }
                        }

                        // Check for any relationships based on parent PID
                        if let Some(parent) = process.parent() {
                            if parent.as_u32() == game.pid().as_u32() {
                                println!("Suspicious relationship detected: {} (PID: {}) is a child of the game process.", process.name().to_string_lossy(), pid);
                            }
                        }
                    }
                }
            }

            // Print the number of processes accessing the game's memory
            println!("Number of processes accessing game memory: {}", accessing_processes.len());
            if !accessing_processes.is_empty() {
                println!("Processes accessing game memory:");
                for proc_info in &accessing_processes {
                    println!(
                        "Process: {}, Purpose: {}, Memory Accessed: {:?}, Parent PID: {:?}",
                        proc_info.name, proc_info.purpose, proc_info.memory_access, proc_info.parent_pid
                    );
                }
            }

        } else {
            println!("Game process not found, retrying...");
        }

        thread::sleep(Duration::from_secs(1)); // Retry every 1 second
    }
}

// Function to get memory ranges of the target process
fn get_memory_ranges(process_handle: *mut winapi::ctypes::c_void) -> Vec<(LPVOID, SIZE_T)> {
    let mut ranges = Vec::new();
    let mut address: LPVOID = 0 as LPVOID;
    let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

    while unsafe { VirtualQueryEx(process_handle, address, &mut mem_info, mem::size_of::<MEMORY_BASIC_INFORMATION>()) } != 0 {
        // Check if the memory region is readable and committed
        if mem_info.State == MEM_COMMIT && mem_info.Protect != PAGE_READWRITE {
            ranges.push((mem_info.BaseAddress, mem_info.RegionSize));
        }
        
        // Move to the next memory region
        address = (address as usize + mem_info.RegionSize) as LPVOID; // Move to the next region
    }

    ranges
}

// Function to check if a process is accessing memory
fn is_accessing_memory(
    process_handle: *mut winapi::ctypes::c_void,
    base_address: LPVOID,
    size: SIZE_T,
) -> bool {
    let mut bytes_read: i32 = 0;
    let mut buffer = vec![0u8; size as usize];

    unsafe {
        if ReadProcessMemory(
            process_handle,
            base_address as *const winapi::ctypes::c_void,
            buffer.as_mut_ptr() as *mut winapi::ctypes::c_void,
            size,
            &mut bytes_read as *mut i32 as *mut usize,
        ) != 0 && bytes_read != 0 && bytes_read == size.try_into().unwrap()
        {
            // Print the content that has been read from the game's memory
            println!("Read memory content: {:?}", &buffer[..bytes_read as usize]);
            return true;
        }
    }
    
    false
}

// Function to get the purpose of a process based on its name
fn get_process_purpose(process_name: &str) -> String {
    match process_name {
        "svchost.exe" => "System service host".to_string(),
        "chrome.exe" => "Web browser".to_string(),
        "explorer.exe" => "Windows File Explorer".to_string(),
        "powershell.exe" => "Scripting environment".to_string(),
        "game.exe" => "Game executable".to_string(),
        // Add more process purposes as needed
        _ => "Unknown".to_string(),
    }
}

// Function to get game memory ranges
fn get_game_memory_ranges(_pid: u32) -> Vec<(LPVOID, SIZE_T)> {
    // Your logic to retrieve game's memory ranges here...
    // Return a vector of tuples with base addresses and sizes.
    // This should be implemented to retrieve the game's memory regions accurately.
    vec![] // Placeholder; replace with actual implementation
}
