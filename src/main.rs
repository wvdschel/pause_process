#![windows_subsystem = "windows"]
extern crate winapi;

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use winapi::um::errhandlingapi;
use winapi::shared::windef::HWND;
use winapi::shared::windef::POINT;
use winapi::shared::minwindef::UINT;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::WPARAM;
use winapi::shared::minwindef::LPARAM;
use winapi::um::winuser::{self, MSG};
use winapi::um::tlhelp32;
use winapi::um::processthreadsapi;
use winapi::um::handleapi;
use winapi::um::winnt;

type ProcessID = winapi::shared::minwindef::DWORD;
type ThreadID = winapi::shared::minwindef::DWORD;


fn from_u16(s: &[u16]) -> String {
    let pos = s.iter().position(|a| a == &0u16).unwrap_or(s.len());
    let s2: OsString = OsStringExt::from_wide(&s[..pos]);
    s2.to_string_lossy().to_string()
}

#[allow(dead_code)]
fn print_last_error() {
    unsafe {
        println!("Last error: {}", errhandlingapi::GetLastError());
    }
}

fn register_hotkey(id: i32, modifiers: isize, vk: i32) -> Result<(), ()> {
    unsafe {
        if winuser::RegisterHotKey(std::ptr::null_mut(), id, modifiers as u32, vk as u32) != 0 {
            println!("Succesfully registered hotkey {} for keycode {}", id, vk);
            return Ok(());
        } else {
            eprintln!("Failed to register hotkey {} for keycode {}", id, vk);
            return Err(());
        }
    }
}

unsafe fn get_process_id(tid: ThreadID) -> Option<ProcessID> {
    let thread_snapshot = tlhelp32::CreateToolhelp32Snapshot(tlhelp32::TH32CS_SNAPTHREAD, 0);
    let mut res = None;
    let mut thread_entry = tlhelp32::THREADENTRY32 {
        dwSize: std::mem::size_of::<tlhelp32::THREADENTRY32>() as DWORD,
        cntUsage: 0,
        th32ThreadID: 0,
        th32OwnerProcessID: 0,
        tpBasePri: 0,
        tpDeltaPri: 0,
        dwFlags: 0,
    };

    tlhelp32::Thread32First(thread_snapshot, &mut thread_entry);

    loop {
        if thread_entry.th32ThreadID == tid {
            res = Some(thread_entry.th32OwnerProcessID)
        }
        if tlhelp32::Thread32Next(thread_snapshot, &mut thread_entry) == 0 {
            break
        }
    }
    handleapi::CloseHandle(thread_snapshot);

    res
}

struct ProcessInfo {
    pid: ProcessID,
    threads: Vec<ThreadID>,
    window_title: String,
    window_handle: HWND,
}

impl ProcessInfo {
    fn get_focused_process(window_handle: Option<&mut HWND>) -> Result<Self, ()> {
        let hwnd = unsafe { winuser::GetForegroundWindow() };
        if hwnd == std::ptr::null_mut() {
            eprintln!("Failed to determine active window (no window active?)");
            return Err(());
        }

        if let Some(window_handle_ref) = window_handle {
            *window_handle_ref = hwnd;
        }

        let title_len = unsafe { winuser::GetWindowTextLengthW(hwnd) } as usize;
        let mut title_vec = vec![0u16; title_len + 1];
        unsafe { winuser::GetWindowTextW(hwnd, title_vec.as_mut_ptr(), title_len as i32 + 1); }
        let title = from_u16(title_vec.as_slice());

        let tid = unsafe { winuser::GetWindowThreadProcessId(hwnd, std::ptr::null_mut()) };
        if tid == 0 {
            eprintln!("Failed to determine thread ID for window {}", tid);
            return Err(());
        }
        unsafe {
            if let Some(pid) = get_process_id(tid) {
                Ok(Self {
                    pid,
                    threads: vec!(),
                    window_title: title,
                    window_handle: hwnd,
                })
            } else {
                eprintln!("Failed to find PID for thread {}", tid);
                Err(())
            }
        }
    }
}

unsafe fn pause_process(process: &mut ProcessInfo) -> Result<(), ()> {
    if process.pid == processthreadsapi::GetCurrentProcessId() {
        println!("Cowardly refusing to suspend our own process.");
        return Err(());
    }
    println!("Trying to pause {} ({})", process.pid, process.window_title);
    let thread_snapshot = tlhelp32::CreateToolhelp32Snapshot(tlhelp32::TH32CS_SNAPTHREAD, 0);
    let mut thread_entry = tlhelp32::THREADENTRY32 {
        dwSize: std::mem::size_of::<tlhelp32::THREADENTRY32>() as DWORD,
        cntUsage: 0,
        th32ThreadID: 0,
        th32OwnerProcessID: 0,
        tpBasePri: 0,
        tpDeltaPri: 0,
        dwFlags: 0,
    };

    tlhelp32::Thread32First(thread_snapshot, &mut thread_entry);

    loop {
        if thread_entry.th32OwnerProcessID == process.pid {
            let thread_handle = processthreadsapi::OpenThread(winnt::THREAD_ALL_ACCESS,
                                                              0,thread_entry.th32ThreadID);

            if processthreadsapi::SuspendThread(thread_handle) == -1i32 as DWORD {
                eprintln!("Failed to suspend thread {}", thread_entry.th32ThreadID);
            } else {
                process.threads.push(thread_entry.th32ThreadID);
            }
            handleapi::CloseHandle(thread_handle);
        }

        if tlhelp32::Thread32Next(thread_snapshot, &mut thread_entry) == 0 {
            break
        }
    }
    handleapi::CloseHandle(thread_snapshot);
    Ok(())
}

unsafe fn unpause_process(process: &ProcessInfo) -> Result<(), ()> {
    let pid = process.pid;
    println!("Trying to unpause {} ({})", pid, process.window_title);
    let thread_snapshot = tlhelp32::CreateToolhelp32Snapshot(tlhelp32::TH32CS_SNAPTHREAD, 0);
    let mut thread_entry = tlhelp32::THREADENTRY32 {
        dwSize: std::mem::size_of::<tlhelp32::THREADENTRY32>() as DWORD,
        cntUsage: 0,
        th32ThreadID: 0,
        th32OwnerProcessID: 0,
        tpBasePri: 0,
        tpDeltaPri: 0,
        dwFlags: 0,
    };

    for tid in &process.threads {
        tlhelp32::Thread32First(thread_snapshot, &mut thread_entry);
        loop {
            if thread_entry.th32OwnerProcessID == pid && thread_entry.th32ThreadID == *tid {
                let thread_handle = processthreadsapi::OpenThread(winnt::THREAD_ALL_ACCESS,
                                                                  0, thread_entry.th32ThreadID);

                if processthreadsapi::ResumeThread(thread_handle) == -1i32 as DWORD {
                    eprintln!("Failed to resume thread {}", thread_entry.th32ThreadID);
                }
                handleapi::CloseHandle(thread_handle);
                break;
            }

            if tlhelp32::Thread32Next(thread_snapshot, &mut thread_entry) == 0 {
                eprintln!("No more threads to check - didn't find thread {}", tid);
                break
            }
        }
    }
    handleapi::CloseHandle(thread_snapshot);
    Ok(())
}

struct ProcessPauser {
    stopped_process : Option<ProcessInfo>
}

impl ProcessPauser {
    pub fn new() -> Self {
        Self {
            stopped_process: None
        }
    }

    pub fn pause_focused_process(&mut self) {
        unsafe {
            let mut hwnd : HWND = std::ptr::null_mut();
            if let Ok(mut process) = ProcessInfo::get_focused_process(Some(&mut hwnd)) {
                let title = process.window_title.clone();
                let pid = process.pid;
                winuser::ShowWindow(hwnd, winuser::SW_HIDE);
                if let Ok(_) = pause_process(&mut process) {
                    println!("Paused '{}' (pid = {}), press hotkey again to unpause.", title, pid);
                    self.stopped_process = Some(process);
                } else {
                    winuser::ShowWindow(hwnd, winuser::SW_SHOW);
                    eprintln!("Failed to pause '{}' (pid = {})", title, pid)
                }
            } else {
                eprintln!("Failed acquire the focused window's process info.");
            }
        }
    }

    pub fn unpause_paused_process(&mut self) {
        unsafe {
            if let None = self.stopped_process {
                eprintln!("No paused process to resume.");
                return;
            }

            if let Ok(_) = unpause_process(self.stopped_process.as_ref().unwrap()) {
                {
                    let process = self.stopped_process.as_ref().unwrap();
                    winuser::ShowWindow(process.window_handle, winuser::SW_SHOW);
                }
                self.stopped_process = None;
            } else {
                let process = self.stopped_process.as_ref().unwrap();
                eprintln!("Failed to unpause '{}' (pid = {})", process.window_title, process.pid);
            }
        }
    }

    fn message_loop(&mut self) {
        println!("Starting message loop");
        unsafe {
            let mut msg = MSG {
                hwnd : 0 as HWND,
                message : 0 as UINT,
                wParam : 0 as WPARAM,
                lParam : 0 as LPARAM,
                time : 0 as DWORD,
                pt : POINT { x: 0, y: 0, },
            };
            loop {
                let pm = winuser::GetMessageW(&mut msg, 0 as HWND, 0, 0);
                if pm == 0 {
                    println!("Exiting message loop.");
                    break;
                }

                match msg.message {
                    winuser::WM_HOTKEY => {
                        println!("Hotkey pressed");

                        match self.stopped_process {
                            Some(_) => self.unpause_paused_process(),
                            None => self.pause_focused_process(),
                        }
                    },
                    _ => {
                        println!("Received message of type {}", msg.message);
                        winuser::TranslateMessage(&msg);
                        winuser::DispatchMessageW(&msg);
                    }
                }

            }
        }
        println!("Message loop is returning, process will exit.");
        std::process::exit(0);
    }
}

fn main() {
    register_hotkey(1, winuser::MOD_NOREPEAT, winuser::VK_PAUSE).unwrap_or(());
    ProcessPauser::new().message_loop();
    println!("main returning.");
}
