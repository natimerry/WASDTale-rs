#![allow(non_snake_case)]

use core::ffi::c_void;
use core::ptr::null;
use libwinexploit::runtime::exports::{find_dll_base, find_dll_export};
use std::ffi::CString;
use std::mem::transmute_copy;
use windows_sys::w;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;
const MAGIC_NTMR: usize = 0x4E544D52;
static mut KEYBOARD_HOOK: HHOOK = 0;
static mut UNDERTALE_HWND: HWND = 0;

static mut SUPPRESS_W: bool = false;
static mut SUPPRESS_A: bool = false;
static mut SUPPRESS_S: bool = false;
static mut SUPPRESS_D: bool = false;

type LoadLibraryWFn = unsafe extern "system" fn(*const u16) -> *mut c_void;
type SleepFn = unsafe extern "system" fn(u32);

type SendInputFn = unsafe extern "system" fn(u32, *const INPUT, i32) -> u32;
type CallNextHookExFn = unsafe extern "system" fn(HHOOK, i32, WPARAM, LPARAM) -> LRESULT;
type GetForegroundWindowFn = unsafe extern "system" fn() -> HWND;

type SetWindowsHookExAFn = unsafe extern "system" fn(i32, HOOKPROC, HINSTANCE, u32) -> HHOOK;
type UnhookWindowsHookExFn = unsafe extern "system" fn(HHOOK) -> BOOL;

type FindWindowAFn = unsafe extern "system" fn(*const u8, *const u8) -> HWND;

type GetMessageAFn = unsafe extern "system" fn(*mut MSG, HWND, u32, u32) -> BOOL;
type TranslateMessageFn = unsafe extern "system" fn(*const MSG) -> BOOL;
type DispatchMessageAFn = unsafe extern "system" fn(*const MSG) -> LRESULT;


static mut SEND_INPUT: Option<SendInputFn> = None;
static mut CALL_NEXT_HOOK_EX: Option<CallNextHookExFn> = None;
static mut GET_FOREGROUND_WINDOW: Option<GetForegroundWindowFn> = None;


unsafe fn send_key(vk: u16, down: bool) {
    unsafe {
        let mut input: INPUT = core::mem::zeroed();
        input.r#type = INPUT_KEYBOARD;
        input.Anonymous.ki.wVk = vk;
        input.Anonymous.ki.dwFlags = if down { 0 } else { KEYEVENTF_KEYUP };
        input.Anonymous.ki.dwExtraInfo = MAGIC_NTMR;

        SEND_INPUT.unwrap()(1, &input, core::mem::size_of::<INPUT>() as i32);
    }
}

unsafe extern "system" fn keyboard_proc(code: i32, wParam: WPARAM, lParam: LPARAM) -> LRESULT {
    unsafe {
        if code >= 0 {
            let kb = &*(lParam as *const KBDLLHOOKSTRUCT);

            if kb.dwExtraInfo == MAGIC_NTMR {
                return (CALL_NEXT_HOOK_EX.unwrap())(KEYBOARD_HOOK, code, wParam, lParam);
            }

            if (GET_FOREGROUND_WINDOW.unwrap())() == UNDERTALE_HWND {
                let is_down = wParam == WM_KEYDOWN as usize || wParam == WM_SYSKEYDOWN as usize;
                let is_up = wParam == WM_KEYUP as usize || wParam == WM_SYSKEYUP as usize;

                const VK_W: u32 = b'W' as u32;
                const VK_A: u32 = b'A' as u32;
                const VK_S: u32 = b'S' as u32;
                const VK_D: u32 = b'D' as u32;

                match kb.vkCode {
                    VK_W => {
                        if is_down && !SUPPRESS_W {
                            SUPPRESS_W = true;
                            send_key(VK_UP as u16, true);
                        } else if is_up && SUPPRESS_W {
                            SUPPRESS_W = false;
                            send_key(VK_UP as u16, false);
                        }
                    }
                    VK_A => {
                        if is_down && !SUPPRESS_A {
                            SUPPRESS_A = true;
                            send_key(VK_LEFT as u16, true);
                        } else if is_up && SUPPRESS_A {
                            SUPPRESS_A = false;
                            send_key(VK_LEFT as u16, false);
                        }
                    }
                    VK_S => {
                        if is_down && !SUPPRESS_S {
                            SUPPRESS_S = true;
                            send_key(VK_DOWN as u16, true);
                        } else if is_up && SUPPRESS_S {
                            SUPPRESS_S = false;
                            send_key(VK_DOWN as u16, false);
                        }
                    }
                    VK_D => {
                        if is_down && !SUPPRESS_D {
                            SUPPRESS_D = true;
                            send_key(VK_RIGHT as u16, true);
                        } else if is_up && SUPPRESS_D {
                            SUPPRESS_D = false;
                            send_key(VK_RIGHT as u16, false);
                        }
                    }
                    _ => {}
                }
            }
        }
        (CALL_NEXT_HOOK_EX.unwrap())(KEYBOARD_HOOK, code, wParam, lParam)
    }
}

unsafe fn find_dll_base_with_log(dll_name: &str) -> u64 {
    println!("Finding {}:", dll_name);
    let addr = find_dll_base(dll_name).unwrap();
    println!("\t{} base at {:x}", dll_name, addr);
    addr
}

unsafe fn get_export<F: Copy>(name: &str, dll_base: usize, dll_name: &str) -> F {
    let addr = find_dll_export(name, dll_base as u64).unwrap();
    println!("\t{}->{} at {:p}", dll_name, name, addr as *const ());
    unsafe { transmute_copy(&addr) }
}

fn main() {
    unsafe {

        // Your main code
        let kernel32 = find_dll_base_with_log("KERNEL32.DLL");

        let LoadLibraryW: LoadLibraryWFn =
            get_export("LoadLibraryW", kernel32 as usize, "kernel32");
        let Sleep: SleepFn = get_export("Sleep", kernel32 as usize, "kernel32");

        LoadLibraryW(w!("User32.dll"));

        let user32 = find_dll_base_with_log("USER32.DLL");

        let SetWindowsHookExA: SetWindowsHookExAFn =
            get_export("SetWindowsHookExA", user32 as usize, "user32");
        let UnhookWindowsHookEx: UnhookWindowsHookExFn =
            get_export("UnhookWindowsHookEx", user32 as usize, "user32");

        SEND_INPUT = Some(get_export("SendInput", user32 as usize, "user32"));
        CALL_NEXT_HOOK_EX = Some(get_export("CallNextHookEx", user32 as usize, "user32"));
        GET_FOREGROUND_WINDOW = Some(get_export("GetForegroundWindow", user32 as usize, "user32"));

        let FindWindowA: FindWindowAFn = get_export("FindWindowA", user32 as usize, "user32");
        let GetMessageA: GetMessageAFn = get_export("GetMessageA", user32 as usize, "user32");
        let TranslateMessage: TranslateMessageFn =
            get_export("TranslateMessage", user32 as usize, "user32");
        let DispatchMessageA: DispatchMessageAFn =
            get_export("DispatchMessageA", user32 as usize, "user32");


        let mut has_been_printed = false;
        loop {
            if !has_been_printed {
                println!("Waiting for UNDERTALE.exe");
                has_been_printed = true;
            }
            let undertale_cst = CString::new("UNDERTALE").unwrap();
            let undertate_cst_ptr = undertale_cst.as_ptr() as *const u8;
            let local_hwnd = FindWindowA(null(), undertate_cst_ptr);

            if local_hwnd != 0 {
                UNDERTALE_HWND = local_hwnd;
                println!("Found UNDERTALE.exe with HWND: {:#x}", local_hwnd);
                break;
            }
            Sleep(1000);
        }

        print!("Setting windows keyboard hook... ");
        KEYBOARD_HOOK = SetWindowsHookExA(WH_KEYBOARD_LL, Some(keyboard_proc), 0, 0);

        if KEYBOARD_HOOK == 0 {
            println!("Failed to set windows keyboard hook");
            return;
        }
        
        println!("done");
        let mut msg: MSG = core::mem::zeroed();
        while GetMessageA(&mut msg, 0, 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }

        UnhookWindowsHookEx(KEYBOARD_HOOK);
    }
}
