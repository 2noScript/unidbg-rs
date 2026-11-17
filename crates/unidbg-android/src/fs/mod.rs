use std::any::Any;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use unidbg_api::error::Result;
use unidbg_api::file::{FileIO, FileSystem, IOResolver, SliceFileIO};
use unidbg_api::memory::MemoryMap;

/// Shared capture buffer for guest `stdout` / `stderr`.
#[derive(Clone, Default)]
pub struct StdBuffer {
    inner: Rc<RefCell<Vec<u8>>>,
}

impl StdBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn take_string(&self) -> String {
        let bytes = std::mem::take(&mut *self.inner.borrow_mut());
        String::from_utf8_lossy(&bytes).into_owned()
    }

    pub fn as_string(&self) -> String {
        String::from_utf8_lossy(&self.inner.borrow()).into_owned()
    }
}

pub struct StdOutIO {
    buf: StdBuffer,
}

impl StdOutIO {
    pub fn new(buf: StdBuffer) -> Self {
        Self { buf }
    }
}

impl FileIO for StdOutIO {
    fn read(&mut self, _buf: &mut [u8]) -> Result<usize> {
        Ok(0)
    }

    fn write(&mut self, data: &[u8]) -> Result<usize> {
        self.buf.inner.borrow_mut().extend_from_slice(data);
        Ok(data.len())
    }

    fn lseek(&mut self, _offset: i64, _whence: i32) -> Result<i64> {
        Ok(-1)
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Real host file backed [`FileIO`].
pub struct SimpleFileIO {
    file: File,
}

impl SimpleFileIO {
    pub fn open(path: impl AsRef<Path>, oflags: u32) -> Result<Self> {
        const O_WRONLY: u32 = 1;
        const O_RDWR: u32 = 2;
        const O_CREAT: u32 = 0o100;
        const O_TRUNC: u32 = 0o1000;
        const O_APPEND: u32 = 0o2000;

        let acc = oflags & 3;
        let read = acc == 0 || acc == O_RDWR;
        let write = acc == O_WRONLY || acc == O_RDWR;
        let file = OpenOptions::new()
            .read(read)
            .write(write)
            .create((oflags & O_CREAT) != 0)
            .truncate((oflags & O_TRUNC) != 0)
            .append((oflags & O_APPEND) != 0)
            .open(path)?;
        Ok(Self { file })
    }
}

impl FileIO for SimpleFileIO {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.file.read(buf)?)
    }

    fn write(&mut self, data: &[u8]) -> Result<usize> {
        Ok(self.file.write(data)?)
    }

    fn lseek(&mut self, offset: i64, whence: i32) -> Result<i64> {
        let pos = match whence {
            0 => SeekFrom::Start(offset as u64),
            1 => SeekFrom::Current(offset),
            2 => SeekFrom::End(offset),
            _ => return Ok(-1),
        };
        Ok(self.file.seek(pos)? as i64)
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// `/dev/urandom` & `/dev/random` deterministic-or-PRNG source.
pub struct RandomFileIO {
    state: u64,
}

impl RandomFileIO {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x9e37_79b9_7f4a_7c15 } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

impl FileIO for RandomFileIO {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(buf.len())
    }

    fn write(&mut self, data: &[u8]) -> Result<usize> {
        Ok(data.len())
    }

    fn lseek(&mut self, _offset: i64, _whence: i32) -> Result<i64> {
        Ok(0)
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// `/dev/null` and `/dev/zero`.
pub struct NullZeroFileIO {
    is_zero: bool,
}

impl FileIO for NullZeroFileIO {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.is_zero {
            buf.fill(0);
            Ok(buf.len())
        } else {
            Ok(0)
        }
    }

    fn write(&mut self, data: &[u8]) -> Result<usize> {
        Ok(data.len())
    }

    fn lseek(&mut self, _offset: i64, _whence: i32) -> Result<i64> {
        Ok(0)
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Shared in-memory pipe (`pipe2`).
pub struct PipeFileIO {
    buf: Rc<RefCell<VecDeque<u8>>>,
    is_write_end: bool,
}

impl PipeFileIO {
    pub fn pair() -> (Self, Self) {
        let buf = Rc::new(RefCell::new(VecDeque::new()));
        (
            Self {
                buf: buf.clone(),
                is_write_end: false,
            },
            Self {
                buf,
                is_write_end: true,
            },
        )
    }
}

impl FileIO for PipeFileIO {
    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        if self.is_write_end {
            return Ok(0);
        }
        let mut q = self.buf.borrow_mut();
        let n = out.len().min(q.len());
        for slot in out.iter_mut().take(n) {
            *slot = q.pop_front().unwrap();
        }
        Ok(n)
    }

    fn write(&mut self, data: &[u8]) -> Result<usize> {
        if !self.is_write_end {
            return Ok(0);
        }
        self.buf.borrow_mut().extend(data);
        Ok(data.len())
    }

    fn lseek(&mut self, _offset: i64, _whence: i32) -> Result<i64> {
        Ok(-29) // -ESPIPE
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Android Linux Virtual File System (`LinuxFileSystem`).
pub struct LinuxFileSystem {
    root_dir: Option<PathBuf>,
    fds: HashMap<i32, Box<dyn FileIO>>,
    next_fd: i32,
    resolvers: Vec<Box<dyn IOResolver>>,
    pub stdout: StdBuffer,
    pub stderr: StdBuffer,
    maps_snapshot: Vec<MemoryMap>,
    proc_name: String,
}

impl LinuxFileSystem {
    pub fn new(root_dir: Option<PathBuf>, proc_name: impl Into<String>) -> Self {
        let stdout = StdBuffer::new();
        let stderr = StdBuffer::new();
        let mut fds: HashMap<i32, Box<dyn FileIO>> = HashMap::new();
        fds.insert(0, Box::new(SliceFileIO::new(Vec::new())));
        fds.insert(1, Box::new(StdOutIO::new(stdout.clone())));
        fds.insert(2, Box::new(StdOutIO::new(stderr.clone())));
        Self {
            root_dir,
            fds,
            next_fd: 3,
            resolvers: Vec::new(),
            stdout,
            stderr,
            maps_snapshot: Vec::new(),
            proc_name: proc_name.into(),
        }
    }

    pub fn add_resolver(&mut self, resolver: Box<dyn IOResolver>) {
        self.resolvers.push(resolver);
    }

    pub fn update_maps(&mut self, maps: Vec<MemoryMap>) {
        self.maps_snapshot = maps;
    }

    pub fn insert_fd(&mut self, io: Box<dyn FileIO>) -> i32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.fds.insert(fd, io);
        fd
    }

    pub fn create_pipe(&mut self) -> (i32, i32) {
        let (r, w) = PipeFileIO::pair();
        let rfd = self.insert_fd(Box::new(r));
        let wfd = self.insert_fd(Box::new(w));
        (rfd, wfd)
    }

    fn format_maps(&self) -> Vec<u8> {
        let mut out = String::new();
        for m in &self.maps_snapshot {
            let r = if m.perm.bits() & 1 != 0 { 'r' } else { '-' };
            let w = if m.perm.bits() & 2 != 0 { 'w' } else { '-' };
            let x = if m.perm.bits() & 4 != 0 { 'x' } else { '-' };
            out.push_str(&format!(
                "{:08x}-{:08x} {r}{w}{x}p 00000000 00:00 0\n",
                m.base,
                m.base + m.size as u64
            ));
        }
        out.into_bytes()
    }
}

impl FileSystem for LinuxFileSystem {
    fn open(&mut self, path: &str, oflags: u32) -> Result<i32> {
        for resolver in &mut self.resolvers {
            if let Some(io) = resolver.resolve(path, oflags)? {
                return Ok(self.insert_fd(io));
            }
        }

        let io: Box<dyn FileIO> = match path {
            "/dev/urandom" | "/dev/random" => Box::new(RandomFileIO::new(0x1234_5678)),
            "/dev/null" => Box::new(NullZeroFileIO { is_zero: false }),
            "/dev/zero" => Box::new(NullZeroFileIO { is_zero: true }),
            "/proc/self/maps" => Box::new(SliceFileIO::new(self.format_maps())),
            "/proc/self/cmdline" => {
                let mut v = self.proc_name.as_bytes().to_vec();
                v.push(0);
                Box::new(SliceFileIO::new(v))
            }
            "/proc/cpuinfo" => Box::new(SliceFileIO::new(
                b"processor\t: 0\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32\n"
                    .to_vec(),
            )),
            "/proc/meminfo" => Box::new(SliceFileIO::new(
                b"MemTotal:        4096000 kB\nMemFree:         2048000 kB\n".to_vec(),
            )),
            _ => {
                if let Some(root) = &self.root_dir {
                    let rel = path.trim_start_matches('/');
                    let host_path = root.join(rel);
                    if host_path.is_file() || (oflags & 0o100) != 0 {
                        Box::new(SimpleFileIO::open(host_path, oflags)?)
                    } else {
                        return Ok(-2); // -ENOENT
                    }
                } else {
                    return Ok(-2); // -ENOENT
                }
            }
        };
        Ok(self.insert_fd(io))
    }

    fn close(&mut self, fd: i32) -> Result<()> {
        if fd > 2 {
            self.fds.remove(&fd);
        }
        Ok(())
    }

    fn get(&mut self, fd: i32) -> Option<&mut Box<dyn FileIO>> {
        self.fds.get_mut(&fd)
    }

    fn add_io_resolver(&mut self, resolver: Box<dyn IOResolver>) {
        self.resolvers.push(resolver);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unidbg_api::arm::backend::MemoryPerm;

    #[test]
    fn vfs_maps_urandom_and_pipe() {
        let mut fs = LinuxFileSystem::new(None, "com.example.app");
        fs.update_maps(vec![MemoryMap {
            base: 0x4000_0000,
            size: 0x2000,
            perm: MemoryPerm::READ | MemoryPerm::EXEC,
        }]);

        let maps_fd = fs.open("/proc/self/maps", 0).unwrap();
        assert!(maps_fd >= 3);
        let mut buf = [0u8; 128];
        let n = fs.get(maps_fd).unwrap().read(&mut buf).unwrap();
        let s = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(s.contains("40000000-40002000 r-xp"));

        let rand_fd = fs.open("/dev/urandom", 0).unwrap();
        let mut rbuf = [0u8; 16];
        assert_eq!(fs.get(rand_fd).unwrap().read(&mut rbuf).unwrap(), 16);
        assert!(rbuf.iter().any(|&b| b != 0));

        let (rfd, wfd) = fs.create_pipe();
        assert_eq!(fs.get(wfd).unwrap().write(b"ping").unwrap(), 4);
        let mut pbuf = [0u8; 8];
        assert_eq!(fs.get(rfd).unwrap().read(&mut pbuf).unwrap(), 4);
        assert_eq!(&pbuf[..4], b"ping");
    }
}
