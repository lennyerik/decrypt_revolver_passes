use std::{ptr, slice, str};

use windows::Win32::{
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

        println!(
            "read mem at {:?} sz: {}",
            meminfo.BaseAddress, meminfo.RegionSize
        );

        Some(mem)
    }
}

trait SlicePosition<T> {
    fn position(&self, search: &[T]) -> Option<usize>;
}

impl<T: PartialEq> SlicePosition<T> for &[T] {
    fn position(&self, search: &[T]) -> Option<usize> {
        self.windows(search.len()).position(|win| win == search)
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

    for region in ProcessMemoryRegions::new(revolver_handle) {
        let search = b"pdfpath";
        if let Some(pos) = region.as_slice().position(b"pdfpath") {
            let entry = String::from_utf8_lossy(&region[pos - 10..pos + search.len() + 10]);
            println!("FOUND: {entry}");
            break;
        }
    }

    // MessageBoxA(None, s!("Test"), s!("Test dialog!"), MB_OK);

    Ok(())
}
