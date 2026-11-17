use crate::arm::backend::Backend;
use crate::error::Result;
use crate::memory::MemoryManager;
use std::any::Any;

/// Opaque file handle in the guest VFS.
pub trait FileIO {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn write(&mut self, data: &[u8]) -> Result<usize>;
    fn lseek(&mut self, offset: i64, whence: i32) -> Result<i64>;
    fn close(&mut self) -> Result<()> {
        Ok(())
    }
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Resolves guest file paths to [`FileIO`] implementations.
pub trait IOResolver {
    fn resolve(&mut self, path: &str, oflags: u32) -> Result<Option<Box<dyn FileIO>>>;
}

/// Virtual file system interface for emulated OSes.
pub trait FileSystem {
    fn open(&mut self, path: &str, oflags: u32) -> Result<i32>;
    fn close(&mut self, fd: i32) -> Result<()>;
    fn get(&mut self, fd: i32) -> Option<&mut Box<dyn FileIO>>;
    fn add_io_resolver(&mut self, resolver: Box<dyn IOResolver>);
}

/// Minimal in-memory file helper for testing `FileSystem`.
pub struct SliceFileIO {
    data: Vec<u8>,
    pos: usize,
}

impl SliceFileIO {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }
}

impl FileIO for SliceFileIO {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let rem = self.data.len().saturating_sub(self.pos);
        let n = rem.min(buf.len());
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }

    fn write(&mut self, data: &[u8]) -> Result<usize> {
        let end = self.pos + data.len();
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        self.data[self.pos..end].copy_from_slice(data);
        self.pos = end;
        Ok(data.len())
    }

    fn lseek(&mut self, offset: i64, whence: i32) -> Result<i64> {
        let base = match whence {
            0 => 0i64,
            1 => self.pos as i64,
            2 => self.data.len() as i64,
            _ => return Ok(-1),
        };
        let next = (base + offset).max(0) as usize;
        self.pos = next;
        Ok(next as i64)
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Context passed to syscall handlers.
pub struct SyscallContext<'a> {
    pub backend: &'a mut dyn Backend,
    pub memory: &'a mut MemoryManager,
}
