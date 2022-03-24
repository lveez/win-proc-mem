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
        /// Converts a Foundation::CHAR array from windows into a String
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

        /// Checks to see if the Process::handle is valid
        fn check_handle(&self) -> Result<(), ProcError> {
            let mut exit_code: u32 = 0;
            if let Some(handle) = self.handle {
                if handle.is_invalid() { 
                    return Err(ProcError::WinError(windows::core::Error::from_win32())); 
                } else {
                    let result = unsafe { Threading::GetExitCodeProcess(handle, &mut exit_code) };
                    if !result.as_bool() { 
                        return Err(ProcError::WinError(windows::core::Error::from_win32())); 
                    } else if exit_code != 259 {
                        return Err(ProcError::ProcessClosedError(exit_code));
                    } else {
                        return Ok(());
                    }
                }
            } else {
                return Err(ProcError::NoHandleError);
            }
        }

        /// Returns the process ID for the process with a chosen name.
        /// 
        /// The process name should be the name of the .exe that the game is run with, 
        /// to find it you can go into Task Manager -> Details and find the correct .exe.
        /// Will error if unable to get the process ID, using dbg!() will give the error
        /// code and a description of the error. 
        /// 
        /// Returns () if successful, and a ProcError if not. The result is stored in
        /// Process::process_id.
        pub fn get_process_id(&mut self, process_name: String) -> Result<(), ProcError> {
            let mut entry = ToolHelp::PROCESSENTRY32::default();
            let size: usize = std::mem::size_of::<ToolHelp::PROCESSENTRY32>();
            entry.dwSize = u32::try_from(size)?;
            let snapshot: Foundation::HANDLE = unsafe { ToolHelp::CreateToolhelp32Snapshot(ToolHelp::TH32CS_SNAPPROCESS, 0) };
            snapshot.ok()?;
            
            if unsafe { ToolHelp::Process32First(snapshot, &mut entry) == true }
            {
                loop {
                    let name = self.winchar_array_to_string(&entry.szExeFile)?;
                    
                    if name == process_name
                    {
                        self.process_id = Some(entry.th32ProcessID);
                        unsafe { Foundation::CloseHandle(snapshot) };
                        return Ok(());
                    }

                    if unsafe { ToolHelp::Process32Next(snapshot, &mut entry) != true }
                    {
                        unsafe { Foundation::CloseHandle(snapshot) };
                        return Err(ProcError::WinError(windows::core::Error::from_win32()));
                    }
                }
            }
            unsafe { Foundation::CloseHandle(snapshot) };
            return Err(ProcError::WinError(windows::core::Error::from_win32()));
        }
        
        /// Returns the base address of a module in the process with
        /// the current process ID. 
        /// 
        /// Will error if unable to get the base address, using 
        /// dbg!() will give the error code and a description of the error.
        pub fn get_base_address(&mut self, module_name: String) -> Result<(), ProcError> {
            let mut entry = ToolHelp::MODULEENTRY32::default();
            let size: usize = std::mem::size_of::<ToolHelp::MODULEENTRY32>();
            entry.dwSize = u32::try_from(size)?;
            if let Some(process_id) = self.process_id
            {
                let snapshot: Foundation::HANDLE = unsafe {ToolHelp::CreateToolhelp32Snapshot(ToolHelp::TH32CS_SNAPMODULE, process_id) };
                snapshot.ok()?;

                if unsafe { ToolHelp::Module32First(snapshot, &mut entry) == true }
                {
                    loop {
                        let name = self.winchar_array_to_string(&entry.szModule)?;

                        if name == module_name
                        {
                            self.base_address = Some(entry.modBaseAddr as u32);
                            unsafe { Foundation::CloseHandle(snapshot) };
                            return Ok(());
                        }

                        if unsafe { ToolHelp::Module32Next(snapshot, &mut entry) != true }
                        {                               
                            unsafe { Foundation::CloseHandle(snapshot) };
                            return Err(ProcError::WinError(windows::core::Error::from_win32()));
                        }
                    }
                }
                unsafe { Foundation::CloseHandle(snapshot) };
                return Err(ProcError::WinError(windows::core::Error::from_win32()));
            }
            else
            {
                return Err(ProcError::ProcIDError);
            }
        }

        /// Gets a handle to the current Process::process_id.
        /// 
        /// Returns () if successful, or a ProcError if not. The result is stored in 
        /// Process::handle.
        pub fn get_handle(&mut self, access: Threading::PROCESS_ACCESS_RIGHTS) -> Result<(), ProcError> {
            
            match self.process_id {
                Some(x) => self.handle = Some( unsafe { Threading::OpenProcess(access, Foundation::BOOL::from(false), x) }),
                None => return Err(ProcError::ProcIDError),
            }
            Ok(())
        }

        /// Closes the current handle to the process.
        /// 
        /// Should not have to be called unless there is a specific reason to close
        /// the handle, as Drop is implemented and calls Process::close_handle().
        pub fn close_handle(&mut self) -> () {
            if let Some(hnd) = self.handle {
                if !hnd.is_invalid()
                {
                    unsafe { Foundation::CloseHandle(hnd) };
                }
            }
        }

        /// Reads the memory at the ***absolute*** address in the target process.
        /// 
        /// Function is not marked as unsafe, however if the expected type `T` is
        /// not at the address then the value read will not be what is expected.
        /// 
        /// Returns a tuple containing either: the value read and the number of bytes 
        /// read, or the error and the number of bytes read. The bytes read is mostly
        /// useful for debugging. Call dbg!() on the error to get the error code
        /// and a description of the error.
        pub fn read<T: Default>(&self, address: u32) -> (Result<T, ProcError>, usize) {
            match self.check_handle() {
                Ok(()) => (),
                Err(e) => return (Err(e), 0),
            }
            
            let mut value: T = T::default();
            let mut bytes_read: usize = 0; 
            let result: Foundation::BOOL = unsafe { Debug::ReadProcessMemory(self.handle, 
                                                                             address as *const c_void, 
                                                                             ptr::addr_of_mut!(value) as *mut c_void,
                                                                             std::mem::size_of::<T>(), 
                                                                             &mut bytes_read) };
        
            match result.as_bool() {
                true => return (Ok(value), bytes_read),
                false => {
                    dbg!(bytes_read);
                    return (Err(ProcError::WinError(windows::core::Error::from_win32())), bytes_read)},
            }
        }

        /// Writes a value at the ***absolute*** address in the target process.
        /// 
        /// Function is not marked as unsafe, however if not used properly could
        /// break the target process. It causes no risk to the calling process
        /// however.
        /// 
        /// Returns the bytes written or a ProcError. Call dbg!() on the error 
        /// to get the error code and a description of the error.
        pub fn write<T: Default>(&self, address: u32, value: T) -> Result<usize, ProcError> {
            match self.check_handle() {
                Ok(()) => (),
                Err(e) => return Err(e),
            }
            
            let mut bytes_written: usize = 0;
            let result: Foundation::BOOL = unsafe { Debug::WriteProcessMemory(self.handle,
                                                                              address as *const c_void, 
                                                                              ptr::addr_of!(value) as *mut c_void, 
                                                                              std::mem::size_of::<T>(), 
                                                                              &mut bytes_written) };

            match result.as_bool() {
                true => return Ok(bytes_written),
                false => return Err(ProcError::WinError(windows::core::Error::from_win32())),
            }
        }

        /// Patches out a set of bytes with 0x90, the NOP instruction for Intel x86
        pub fn patch(&self, address: u32, num_bytes: usize) -> Result<usize, ProcError> {
            match self.check_handle() {
                Ok(()) => (),
                Err(e) => return Err(e),
            }
            
            let value = vec![0x90; num_bytes];

            let mut bytes_written: usize = 0;
            let result: Foundation::BOOL = unsafe { Debug::WriteProcessMemory(self.handle,
                                                                              address as *const c_void, 
                                                                              ptr::addr_of!(value[0]) as *mut c_void, 
                                                                              num_bytes, 
                                                                              &mut bytes_written) };

            match result.as_bool() {
                true => return Ok(bytes_written),
                false => return Err(ProcError::WinError(windows::core::Error::from_win32())),
            }
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

    /// Process::process_id is None, first call Process::get_process_id.
    #[error("There is no process ID associated with the Process struct. First call Process::get_process_id")]
    ProcIDError,
    
    /// Process::handle is None, first call Process::get_handle.
    #[error("There is no handle associated with the Process struct. First call Process::get_handle")]
    NoHandleError,

    /// The target process has been closed.
    #[error("The target process has been closed with exit code {0}.")]
    ProcessClosedError(u32),
}


#[cfg(test)]
    #[test]
    fn it_works() -> Result<(), ProcError> {
        // let mut proc_test = Process::default();
        // proc_test.get_process_id(String::from("Spotify.exe"))?;
        // proc_test.get_handle(Threading::PROCESS_ALL_ACCESS)?;
        // proc_test.get_base_address(String::from("Spotify.exe"))?;
        // std::thread::sleep_ms(1000);
        // let mut x: u32 = 0;
        // // dbg!(proc_test);
        // if let Some(handle) = proc_test.handle
        // {
        //     unsafe { dbg!(Threading::GetExitCodeProcess(handle, &mut x)); }
        //     dbg!(x);
        // }

        dbg!(vec!(0x90; 10));

        // let addr: u64 = 0xABCDEF1234;
        // let ptr: *const c_void = addr as *const c_void;
        // dbg!(addr);
        // dbg!(ptr);
        // proc_test.Read<i32>()

        Ok(())
    }
