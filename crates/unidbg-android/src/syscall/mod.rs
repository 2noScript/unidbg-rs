pub mod arm32;
pub mod arm64;

use crate::fs::LinuxFileSystem;
use std::cell::RefCell;
use std::rc::Rc;
use unidbg_api::arm::backend::{Arm64Reg, ArmReg, Backend, MemoryPerm};
use unidbg_api::arm::Arch;
use unidbg_api::error::{Result, UnidbgError};
use unidbg_api::file::FileSystem;
use unidbg_api::memory::{Memory, MemoryManager};
use unidbg_api::pointer::UnidbgPointer;
use unidbg_api::spi::SyscallHandler;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;

/// A queued thread created via `clone` (`pthread_create`).
#[derive(Debug, Clone)]
pub struct ClonedThread {
    pub tid: u32,
    pub fn_addr: u64,
    pub arg: u64,
    pub ctid: u64,
    pub tls: u64,
}

/// Shared Android Linux syscall handler (`AndroidSyscallHandler`).
pub struct AndroidSyscallHandler {
    arch: Arch,
    fs: Rc<RefCell<LinuxFileSystem>>,
    pid: u32,
    tid: u32,
    pub(crate) pending_threads: Rc<RefCell<Vec<ClonedThread>>>,
    pub(crate) in_spawned_thread: Rc<RefCell<bool>>,
}

impl AndroidSyscallHandler {
    pub fn new(arch: Arch, fs: Rc<RefCell<LinuxFileSystem>>, pid: u32) -> Self {
        Self {
            arch,
            fs,
            pid,
            tid: pid,
            pending_threads: Rc::new(RefCell::new(Vec::new())),
            in_spawned_thread: Rc::new(RefCell::new(false)),
        }
    }

    pub fn with_thread_state(
        arch: Arch,
        fs: Rc<RefCell<LinuxFileSystem>>,
        pid: u32,
        pending_threads: Rc<RefCell<Vec<ClonedThread>>>,
        in_spawned_thread: Rc<RefCell<bool>>,
    ) -> Self {
        Self {
            arch,
            fs,
            pid,
            tid: pid,
            pending_threads,
            in_spawned_thread,
        }
    }

    fn ptr_size(&self) -> usize {
        if self.arch == Arch::Arm64 { 8 } else { 4 }
    }

    fn prot_to_perm(prot: u64) -> MemoryPerm {
        let mut perm = MemoryPerm::NONE;
        if prot & PROT_READ != 0 {
            perm |= MemoryPerm::READ;
        }
        if prot & PROT_WRITE != 0 {
            perm |= MemoryPerm::WRITE;
        }
        if prot & PROT_EXEC != 0 {
            perm |= MemoryPerm::EXEC;
        }
        perm
    }

    pub(crate) fn sys_read(&mut self, backend: &mut dyn Backend, fd: i32, buf_addr: u64, count: usize) -> Result<i64> {
        let mut fs = self.fs.borrow_mut();
        let Some(io) = fs.get(fd) else {
            return Ok(-9); // -EBADF
        };
        let mut tmp = vec![0u8; count];
        let n = io.read(&mut tmp)?;
        if n > 0 {
            backend.mem_write(buf_addr, &tmp[..n])?;
        }
        Ok(n as i64)
    }

    pub(crate) fn sys_write(&mut self, backend: &dyn Backend, fd: i32, buf_addr: u64, count: usize) -> Result<i64> {
        let mut tmp = vec![0u8; count];
        backend.mem_read(buf_addr, &mut tmp)?;
        let mut fs = self.fs.borrow_mut();
        let Some(io) = fs.get(fd) else {
            return Ok(-9); // -EBADF
        };
        let n = io.write(&tmp)?;
        Ok(n as i64)
    }

    pub(crate) fn sys_openat(&mut self, backend: &dyn Backend, memory: &MemoryManager, _dirfd: i32, path_addr: u64, oflags: u32) -> Result<i64> {
        let path = UnidbgPointer::new(path_addr, self.ptr_size()).read_cstr(backend)?;
        let mut fs = self.fs.borrow_mut();
        fs.update_maps(memory.memory_maps());
        let fd = fs.open(&path, oflags)?;
        Ok(fd as i64)
    }

    pub(crate) fn sys_close(&mut self, fd: i32) -> Result<i64> {
        self.fs.borrow_mut().close(fd)?;
        Ok(0)
    }

    pub(crate) fn sys_lseek(&mut self, fd: i32, offset: i64, whence: i32) -> Result<i64> {
        let mut fs = self.fs.borrow_mut();
        let Some(io) = fs.get(fd) else {
            return Ok(-9);
        };
        io.lseek(offset, whence)
    }

    pub(crate) fn sys_mmap(&mut self, backend: &mut dyn Backend, memory: &mut MemoryManager, addr: u64, len: usize, prot: u64) -> Result<i64> {
        let mapped = memory.mmap(backend, addr, len, Self::prot_to_perm(prot))?;
        Ok(mapped as i64)
    }

    pub(crate) fn sys_mprotect(&mut self, backend: &mut dyn Backend, memory: &mut MemoryManager, addr: u64, len: usize, prot: u64) -> Result<i64> {
        memory.mprotect(backend, addr, len, Self::prot_to_perm(prot))?;
        Ok(0)
    }

    pub(crate) fn sys_munmap(&mut self, backend: &mut dyn Backend, memory: &mut MemoryManager, addr: u64, len: usize) -> Result<i64> {
        memory.munmap(backend, addr, len)?;
        Ok(0)
    }

    pub(crate) fn sys_brk(&mut self, backend: &mut dyn Backend, memory: &mut MemoryManager, addr: u64) -> Result<i64> {
        Ok(memory.brk(backend, addr)? as i64)
    }

    pub(crate) fn sys_uname(&self, backend: &mut dyn Backend, buf_addr: u64) -> Result<i64> {
        // struct utsname: 5 fields * 65 bytes = 325 (plus domainname 65 = 390)
        let mut uts = [0u8; 390];
        let fields: [(&str, usize); 5] = [
            ("Linux", 0),
            ("localhost", 65),
            ("5.15.0-android", 130),
            ("#1 SMP PREEMPT", 195),
            (if self.arch == Arch::Arm64 { "aarch64" } else { "armv7l" }, 260),
        ];
        for (val, off) in fields {
            let bytes = val.as_bytes();
            uts[off..off + bytes.len()].copy_from_slice(bytes);
        }
        backend.mem_write(buf_addr, &uts)?;
        Ok(0)
    }

    pub(crate) fn sys_clock_gettime(&self, backend: &mut dyn Backend, tp_addr: u64) -> Result<i64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        if self.arch == Arch::Arm64 {
            backend.mem_write(tp_addr, &(now.as_secs() as u64).to_le_bytes())?;
            backend.mem_write(tp_addr + 8, &(now.subsec_nanos() as u64).to_le_bytes())?;
        } else {
            backend.mem_write(tp_addr, &(now.as_secs() as u32).to_le_bytes())?;
            backend.mem_write(tp_addr + 4, &now.subsec_nanos().to_le_bytes())?;
        }
        Ok(0)
    }

    pub(crate) fn sys_gettimeofday(&self, backend: &mut dyn Backend, tv_addr: u64) -> Result<i64> {
        if tv_addr != 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            if self.arch == Arch::Arm64 {
                backend.mem_write(tv_addr, &(now.as_secs() as u64).to_le_bytes())?;
                backend.mem_write(tv_addr + 8, &(now.subsec_micros() as u64).to_le_bytes())?;
            } else {
                backend.mem_write(tv_addr, &(now.as_secs() as u32).to_le_bytes())?;
                backend.mem_write(tv_addr + 4, &now.subsec_micros().to_le_bytes())?;
            }
        }
        Ok(0)
    }

    pub(crate) fn sys_fstat(&mut self, backend: &mut dyn Backend, fd: i32, stat_addr: u64) -> Result<i64> {
        let mut fs = self.fs.borrow_mut();
        let Some(io) = fs.get(fd) else {
            return Ok(-9); // -EBADF
        };
        let st_size = match io.lseek(0, 1) {
            Ok(cur) if cur >= 0 => {
                let end = io.lseek(0, 2).unwrap_or(0).max(0) as u64;
                let _ = io.lseek(cur, 0);
                end
            }
            _ => 0,
        };
        Self::write_arm64_stat(backend, stat_addr, st_size, 0o100644)?;
        Ok(0)
    }

    pub(crate) fn sys_newfstatat(&mut self, backend: &mut dyn Backend, _dirfd: i32, path_addr: u64, stat_addr: u64) -> Result<i64> {
        let path = UnidbgPointer::new(path_addr, self.ptr_size()).read_cstr(backend)?;
        let mut fs = self.fs.borrow_mut();
        let fd = fs.open(&path, 0)?;
        if fd < 0 {
            return Ok(fd as i64);
        }
        let st_size = if let Some(io) = fs.get(fd) {
            io.lseek(0, 2).unwrap_or(0).max(0) as u64
        } else {
            0
        };
        let _ = fs.close(fd);
        Self::write_arm64_stat(backend, stat_addr, st_size, 0o100644)?;
        Ok(0)
    }

    fn write_arm64_stat(backend: &mut dyn Backend, stat_addr: u64, st_size: u64, st_mode: u32) -> Result<()> {
        if stat_addr == 0 {
            return Ok(());
        }
        let mut buf = [0u8; 128];
        buf[0x00..0x08].copy_from_slice(&1u64.to_le_bytes()); // st_dev
        buf[0x08..0x10].copy_from_slice(&1u64.to_le_bytes()); // st_ino
        buf[0x10..0x14].copy_from_slice(&st_mode.to_le_bytes()); // st_mode
        buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // st_nlink
        buf[0x18..0x1c].copy_from_slice(&1000u32.to_le_bytes()); // st_uid
        buf[0x1c..0x20].copy_from_slice(&1000u32.to_le_bytes()); // st_gid
        buf[0x30..0x38].copy_from_slice(&st_size.to_le_bytes()); // st_size
        buf[0x38..0x3c].copy_from_slice(&4096i32.to_le_bytes()); // st_blksize
        let blocks = (st_size + 511) / 512;
        buf[0x40..0x48].copy_from_slice(&blocks.to_le_bytes()); // st_blocks
        backend.mem_write(stat_addr, &buf)
    }

    pub(crate) fn next_tid(&mut self) -> u32 {
        self.tid = self.tid.saturating_add(1);
        self.tid
    }

    pub(crate) fn sys_getrandom(&mut self, backend: &mut dyn Backend, buf_addr: u64, len: usize) -> Result<i64> {
        let mut fs = self.fs.borrow_mut();
        let fd = fs.open("/dev/urandom", 0)?;
        let mut buf = vec![0u8; len];
        let n = fs.get(fd).unwrap().read(&mut buf)?;
        fs.close(fd)?;
        backend.mem_write(buf_addr, &buf[..n])?;
        Ok(n as i64)
    }

    pub(crate) fn sys_pipe2(&mut self, backend: &mut dyn Backend, fds_addr: u64) -> Result<i64> {
        let (rfd, wfd) = self.fs.borrow_mut().create_pipe();
        backend.mem_write(fds_addr, &rfd.to_le_bytes())?;
        backend.mem_write(fds_addr + 4, &wfd.to_le_bytes())?;
        Ok(0)
    }

    pub(crate) fn sys_set_tls(&mut self, backend: &mut dyn Backend, tls: u64) -> Result<i64> {
        match self.arch {
            Arch::Arm64 => backend.reg_write(Arm64Reg::TpidrEl0 as u32, tls)?,
            Arch::Arm32 => backend.reg_write(ArmReg::C13C0_3 as u32, tls)?,
        }
        Ok(0)
    }
}

impl SyscallHandler for AndroidSyscallHandler {
    fn handle(&mut self, backend: &mut dyn Backend, memory: &mut MemoryManager) -> Result<()> {
        match self.arch {
            Arch::Arm64 => arm64::dispatch(self, backend, memory),
            Arch::Arm32 => arm32::dispatch(self, backend, memory),
        }
        .map_err(|e| match e {
            UnidbgError::StopEmulator(_) => e,
            other => other,
        })
    }
}
