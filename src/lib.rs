//! Provides useful functions for reading and writing to another process' memory in windows.
//!
//! # Example
//! 
//! 
//! 

use std::convert::{ TryFrom,};
use std::ffi::c_void;
use std::ptr;
use windows::{Win32::System::Diagnostics::ToolHelp, Win32::Foundation, Win32::System::Threading, Win32::System::Diagnostics::Debug,};
pub struct Process
{
    process_id: Option<u32>,
    handle: Option<Foundation::HANDLE>,
    base_address: Option<u32>,
}   


impl Process {
        fn winchar_array_to_string(&self, winchar: &[Foundation::CHAR]) -> Result<String, ProcError> {
            let mut str_vec: Vec<u8> = Vec::with_capacity(260);
            for c in winchar {
                if c.0 != 0 
                {
                    str_vec.push(c.0);
                } else { break; }
            }

            let str = String::from_utf8(str_vec)?;

            Ok(str)
        }

        pub fn get_process_id(&mut self, process_name: String) -> Result<(), ProcError> {
            let mut entry = ToolHelp::PROCESSENTRY32::default();
            let size: usize = std::mem::size_of::<ToolHelp::PROCESSENTRY32>();
            entry.dwSize = u32::try_from(size)?;
            unsafe {
                let snapshot: Foundation::HANDLE = ToolHelp::CreateToolhelp32Snapshot(ToolHelp::TH32CS_SNAPPROCESS, 0);
                snapshot.ok()?;
                
                if ToolHelp::Process32First(snapshot, &mut entry) == true
                {
                    loop {
                        let name = self.winchar_array_to_string(&entry.szExeFile)?;
                        
                        if name == process_name
                        {
                            self.process_id = Some(entry.th32ProcessID);
                            Foundation::CloseHandle(snapshot);
                            return Ok(());
                        }

                        if ToolHelp::Process32Next(snapshot, &mut entry) != true
                        {
                            Foundation::CloseHandle(snapshot);
                            return Err(ProcError::WinError(windows::core::Error::from_win32()));
                        }
                    }
                }
                Foundation::CloseHandle(snapshot);
                return Err(ProcError::WinError(windows::core::Error::from_win32()));
            }
        }
        
        pub fn get_base_address(&mut self, module_name: String) -> Result<(), ProcError> {
            let mut entry = ToolHelp::MODULEENTRY32::default();
            let size: usize = std::mem::size_of::<ToolHelp::MODULEENTRY32>();
            entry.dwSize = u32::try_from(size)?;
            unsafe {
                if let Some(process_id) = self.process_id
                {
                    let snapshot: Foundation::HANDLE = ToolHelp::CreateToolhelp32Snapshot(ToolHelp::TH32CS_SNAPMODULE, process_id);
                    snapshot.ok()?;

                    if ToolHelp::Module32First(snapshot, &mut entry) == true
                    {
                        loop {
                            let name = self.winchar_array_to_string(&entry.szModule)?;

                            if name == module_name
                            {
                                self.base_address = Some(entry.modBaseAddr as u32);
                                Foundation::CloseHandle(snapshot);
                                return Ok(());
                            }

                            if ToolHelp::Module32Next(snapshot, &mut entry) != true
                            {                               
                                Foundation::CloseHandle(snapshot);
                                return Err(ProcError::WinError(windows::core::Error::from_win32()));
                            }
                        }
                    }
                    Foundation::CloseHandle(snapshot);
                    return Err(ProcError::WinError(windows::core::Error::from_win32()));
                }
                else
                {
                    return Err(ProcError::ProcIDError);
                }
            }
        }

        pub fn get_handle(&mut self, access: Threading::PROCESS_ACCESS_RIGHTS) -> Result<(), ProcError> {
            unsafe {
                match self.process_id {
                    Some(x) => self.handle = Some(Threading::OpenProcess(access, Foundation::BOOL::from(false), x)),
                    None => return Err(ProcError::ProcIDError),
                }
            }
            Ok(())
        }

        pub fn close_handle(&mut self) -> () {
            if let Some(hnd) = self.handle {
                if !hnd.is_invalid()
                {
                    unsafe {
                        Foundation::CloseHandle(hnd);
                    }
                }
            }
        }

        pub fn read<T: Default>(&self, address: u64) -> Result<T, ProcError> {
            let mut x: T = T::default();
            let mut bytes_read: usize = 0;            
            unsafe { 
                let result: Foundation::BOOL = Debug::ReadProcessMemory(self.handle, 
                                                                        address as *const c_void, 
                                                                        ptr::addr_of_mut!(x) as *mut c_void,
                                                                        std::mem::size_of::<T>(), 
                                                                        &mut bytes_read); 
            
                match result.as_bool() {
                    true => return Ok(x),
                    false => {
                        dbg!(bytes_read);
                        return Err(ProcError::WinError(windows::core::Error::from_win32()))},
                }
            };  
        }

        pub fn write<T: Default>(&self, address: u64, value: T) -> Result<(), ProcError> {
            let mut bytes_written: usize = 0;
            unsafe {
                let result: Foundation::BOOL = Debug::WriteProcessMemory(self.handle,
                                                                         address as *const c_void, 
                                                                         ptr::addr_of!(value) as *mut c_void, 
                                                                         std::mem::size_of::<T>(), 
                                                                         &mut bytes_written);

                match result.as_bool() {
                    true => return Ok(()),
                    false => return Err(ProcError::WinError(windows::core::Error::from_win32())),
                }
            };
        }
}

impl Default for Process {
    fn default() -> Self {
        Process {process_id: None, handle: None, base_address: None} 
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.close_handle();
    }
}

impl std::fmt::Debug for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "\n")?;
        if let Some(process_id) = self.process_id {
            write!(f, "process_id: {}\n", process_id)?;
        }
        else
        {
            write!(f, "process_id: None\n")?;
        }

        if let Some(handle) = self.handle {
            if !handle.is_invalid()
            {
                write!(f, "handle: valid\n")?;
            }
            else
            {
                write!(f, "handle: invalid\n")?;
            }
        }
        else
        {
            write!(f, "handle: None\n")?;
        }

        if let Some(base_address) = self.base_address {
            write!(f, "base_address: {}\n", base_address)?;
        }
        else
        {
            write!(f, "base_address: None\n")?;
        }

        Ok(())
    }
}


impl std::fmt::Display for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "\n")?;
        if let Some(process_id) = self.process_id {
            write!(f, "process_id: {}\n", process_id)?;
        }
        else
        {
            write!(f, "process_id: None\n")?;
        }

        if let Some(handle) = self.handle {
            if !handle.is_invalid()
            {
                write!(f, "handle: valid\n")?;
            }
            else
            {
                write!(f, "handle: invalid\n")?;
            }
        }
        else
        {
            write!(f, "handle: None\n")?;
        }

        if let Some(base_address) = self.base_address {
            write!(f, "base_address: {}\n", base_address)?;
        }
        else
        {
            write!(f, "base_address: None\n")?;
        }

        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ProcError
{
    #[error(transparent)]
    WinError(#[from] windows::core::Error),

    #[error(transparent)]
    ConvertError(#[from] std::num::TryFromIntError),
    
    #[error(transparent)]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),

    #[error("There is no process ID associated with the Process struct. First call Process::get_process_id")]
    ProcIDError,
}


#[cfg(test)]
    #[test]
    fn it_works() -> Result<(), ProcError> {
        let mut proc_test = Process::default();
        proc_test.get_process_id(String::from("brave.exe"))?;
        proc_test.get_handle(Threading::PROCESS_VM_READ)?;
        proc_test.get_base_address(String::from("brave.exe"))?;

        // dbg!(proc_test);
        if let Some(base_address) = proc_test.base_address
        {
            dbg!(proc_test.process_id);
            let x: i64 = 3;
            let x: i32 = proc_test.read(9460301 + 0x100)?;
        }

        // let addr: u64 = 0xABCDEF1234;
        // let ptr: *const c_void = addr as *const c_void;
        // dbg!(addr);
        // dbg!(ptr);
        // proc_test.Read<i32>()

        Ok(())
    }
