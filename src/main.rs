#![allow(non_snake_case)]

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::ptr::null;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const MAGIC_NTMR: usize = 0x4E544D52;
static mut KEYBOARD_HOOK: HHOOK = 0;
static mut UNDERTALE_HWND: HWND = 0;

static KEYMAP: OnceLock<HashMap<u32, u16>> = OnceLock::new();
static SUPPRESS: OnceLock<[AtomicBool; 256]> = OnceLock::new();

use libwinexploit::winapi::{self, LPINPUT};

unsafe fn send_key(vk: u16, down: bool) {
    unsafe {
        let mut input: INPUT = core::mem::zeroed();
        input.r#type = INPUT_KEYBOARD;
        input.Anonymous.ki.wVk = vk;
        input.Anonymous.ki.dwFlags = if down { 0 } else { KEYEVENTF_KEYUP };
        input.Anonymous.ki.dwExtraInfo = MAGIC_NTMR;

        winapi::SendInput(
            1,
            std::ptr::addr_of_mut!(input) as LPINPUT,
            core::mem::size_of::<INPUT>() as i32,
        );
    }
}

const DEFAULT_KEY_BYTES: &[u8] = include_bytes!("../keys.default.txt");

fn load_keymap() {
    println!("Loading keymap");
    let keys_path = std::env::current_exe().unwrap().with_file_name("keys.txt");

    if !keys_path.exists() {
        println!("Creating default keymap");
        File::create(&keys_path)
            .unwrap()
            .write_all(DEFAULT_KEY_BYTES)
            .unwrap();
    }

    let text = fs::read_to_string(keys_path).expect("failed to read keys.txt");

    let mut map: HashMap<u32, u16> = HashMap::new();

    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (src, dst) = line.split_once(char::is_whitespace).unwrap_or_else(|| {
            panic!("keys.txt:{} invalid format (expected: SRC DST)", lineno + 1)
        });

        let src_vk = vk_from_name(src)
            .unwrap_or_else(|| panic!("keys.txt:{} invalid source key `{}`", lineno + 1, src));

        let dst_vk = vk_from_name(dst)
            .unwrap_or_else(|| panic!("keys.txt:{} invalid target key `{}`", lineno + 1, dst));

        if src_vk >= 256 {
            panic!(
                "keys.txt:{} source VK {} out of range (0–255)",
                lineno + 1,
                src_vk
            );
        }

        println!("MAPPED {src} ({:#04X}) -> {dst} ({:#04X})", src_vk, dst_vk);

        map.insert(src_vk, dst_vk as u16);
    }

    KEYMAP.set(map).expect("KEYMAP already initialized");
    SUPPRESS
        .set(std::array::from_fn(|_| AtomicBool::new(false)))
        .expect("SUPPRESS already initialized");
}

fn vk_from_name(name: &str) -> Option<u32> {
    let s = name.trim().to_uppercase();

    if let Some(hex) = s.strip_prefix("0X") {
        if let Ok(v) = u32::from_str_radix(hex, 16) {
            return Some(v);
        }
    }

    if let Ok(v) = s.parse::<u32>() {
        return Some(v);
    }

    if s.len() == 1 {
        let b = s.as_bytes()[0];
        if b.is_ascii_alphanumeric() {
            return Some(b as u32);
        }
    }

    Some(match s.as_str() {
        "BACKSPACE" => VK_BACK as u32,
        "TAB" => VK_TAB as u32,
        "ENTER" | "RETURN" => VK_RETURN as u32,
        "SHIFT" => VK_SHIFT as u32,
        "CTRL" | "CONTROL" => VK_CONTROL as u32,
        "ALT" => VK_MENU as u32,
        "ESC" | "ESCAPE" => VK_ESCAPE as u32,
        "SPACE" => VK_SPACE as u32,

        "LEFT" => VK_LEFT as u32,
        "UP" => VK_UP as u32,
        "RIGHT" => VK_RIGHT as u32,
        "DOWN" => VK_DOWN as u32,

        "INSERT" => VK_INSERT as u32,
        "DELETE" => VK_DELETE as u32,
        "HOME" => VK_HOME as u32,
        "END" => VK_END as u32,
        "PAGEUP" => VK_PRIOR as u32,
        "PAGEDOWN" => VK_NEXT as u32,

        "F1" => VK_F1 as u32,
        "F2" => VK_F2 as u32,
        "F3" => VK_F3 as u32,
        "F4" => VK_F4 as u32,
        "F5" => VK_F5 as u32,
        "F6" => VK_F6 as u32,
        "F7" => VK_F7 as u32,
        "F8" => VK_F8 as u32,
        "F9" => VK_F9 as u32,
        "F10" => VK_F10 as u32,
        "F11" => VK_F11 as u32,
        "F12" => VK_F12 as u32,

        "LMB" | "MOUSE1" | "LBUTTON" => VK_LBUTTON as u32,
        "RMB" | "MOUSE2" | "RBUTTON" => VK_RBUTTON as u32,
        "MMB" | "MOUSE3" | "MBUTTON" => VK_MBUTTON as u32,
        "MOUSE4" | "XBUTTON1" => VK_XBUTTON1 as u32,
        "MOUSE5" | "XBUTTON2" => VK_XBUTTON2 as u32,

        _ => return None,
    })
}

unsafe extern "system" fn keyboard_proc(code: i32, wParam: WPARAM, lParam: LPARAM) -> LRESULT {
    unsafe {
        if code < 0 {
            return winapi::CallNextHookEx(
                KEYBOARD_HOOK as *mut _,
                code,
                wParam as u64,
                lParam as i64,
            ) as LRESULT;
        }

        let kb = &*(lParam as *const KBDLLHOOKSTRUCT);
        if kb.dwExtraInfo == MAGIC_NTMR {
            return winapi::CallNextHookEx(
                KEYBOARD_HOOK as *mut _,
                code,
                wParam as u64,
                lParam as i64,
            ) as LRESULT;
        }

        let fg_hwnd = winapi::GetForegroundWindow() as HWND;

        if fg_hwnd != UNDERTALE_HWND {
            return winapi::CallNextHookEx(
                KEYBOARD_HOOK as *mut _,
                code,
                wParam as u64,
                lParam as i64,
            ) as LRESULT;
        }

        let is_down = wParam == WM_KEYDOWN as usize || wParam == WM_SYSKEYDOWN as usize;
        let is_up = wParam == WM_KEYUP as usize || wParam == WM_SYSKEYUP as usize;

        let keymap = match KEYMAP.get() {
            Some(m) => m,
            None => {
                return winapi::CallNextHookEx(
                    KEYBOARD_HOOK as *mut _,
                    code,
                    wParam as u64,
                    lParam as i64,
                ) as LRESULT;
            }
        };

        let out_vk = match keymap.get(&kb.vkCode) {
            Some(&vk) => vk,
            None => {
                return winapi::CallNextHookEx(
                    KEYBOARD_HOOK as *mut _,
                    code,
                    wParam as u64,
                    lParam as i64,
                ) as LRESULT;
            }
        };

        let suppress = SUPPRESS.get().unwrap();
        let flag = &suppress[kb.vkCode as usize];

        if is_down {
            if !flag.swap(true, Ordering::SeqCst) {
                send_key(out_vk, true);
            }
            return 1;
        }

        if is_up {
            if flag.swap(false, Ordering::SeqCst) {
                send_key(out_vk, false);
            }
            return 1;
        }

        winapi::CallNextHookEx(KEYBOARD_HOOK as *mut _, code, wParam as u64, lParam as i64)
            as LRESULT
    }
}

fn main() {
    unsafe {
        let mut has_been_printed = false;
        loop {
            if !has_been_printed {
                println!("Waiting for UNDERTALE.exe");
                has_been_printed = true;
            }

            let undertale_cst = CString::new("UNDERTALE").unwrap();
            let local_hwnd = FindWindowA(null(), undertale_cst.as_ptr() as *const u8);

            if local_hwnd != 0 {
                UNDERTALE_HWND = local_hwnd;
                println!("Found UNDERTALE.exe with HWND: {:#x}", local_hwnd);
                load_keymap();
                break;
            }

            std::thread::sleep(std::time::Duration::from_secs(1));
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
