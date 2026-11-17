use crate::elf_loader::AndroidElfLoader;
use std::cell::RefCell;
use std::rc::Rc;
use unidbg_api::arm::backend::{Arm64Reg, ArmReg, Backend};
use unidbg_api::arm::Arch;
use unidbg_api::error::Result;
use unidbg_api::memory::{Memory, MemoryManager};
use unidbg_api::pointer::UnidbgPointer;
use unidbg_api::svc::{Svc, SvcResult};

/// Emulated `dlsym(handle, symbol)` SVC handler (replaces `ArmLD` / `ArmLD64` dlsym).
pub struct DlSymSvc {
    arch: Arch,
    loader: Rc<RefCell<AndroidElfLoader>>,
}

impl DlSymSvc {
    pub fn new(arch: Arch, loader: Rc<RefCell<AndroidElfLoader>>) -> Self {
        Self { arch, loader }
    }
}

impl Svc for DlSymSvc {
    fn name(&self) -> &str {
        "dlsym"
    }

    fn handle(&mut self, backend: &mut dyn Backend, _memory: &mut MemoryManager) -> Result<SvcResult> {
        let ptr_sz = if self.arch == Arch::Arm64 { 8 } else { 4 };
        let sym_addr = match self.arch {
            Arch::Arm64 => backend.reg_read(Arm64Reg::X1 as u32)?,
            Arch::Arm32 => backend.reg_read(ArmReg::R1 as u32)?,
        };
        let name = UnidbgPointer::new(sym_addr, ptr_sz).read_cstr(backend)?;
        let addr = self.loader.borrow().find_symbol(&name).unwrap_or(0);
        Ok(SvcResult::Return(addr))
    }
}

/// Emulated `dlopen(filename, flag)` SVC handler.
pub struct DlOpenSvc {
    arch: Arch,
    loader: Rc<RefCell<AndroidElfLoader>>,
}

impl DlOpenSvc {
    pub fn new(arch: Arch, loader: Rc<RefCell<AndroidElfLoader>>) -> Self {
        Self { arch, loader }
    }
}

impl Svc for DlOpenSvc {
    fn name(&self) -> &str {
        "dlopen"
    }

    fn handle(&mut self, backend: &mut dyn Backend, _memory: &mut MemoryManager) -> Result<SvcResult> {
        let ptr_sz = if self.arch == Arch::Arm64 { 8 } else { 4 };
        let name_addr = match self.arch {
            Arch::Arm64 => backend.reg_read(Arm64Reg::X0 as u32)?,
            Arch::Arm32 => backend.reg_read(ArmReg::R0 as u32)?,
        };
        if name_addr == 0 {
            return Ok(SvcResult::Return(1));
        }
        let name = UnidbgPointer::new(name_addr, ptr_sz).read_cstr(backend)?;
        let base = self
            .loader
            .borrow()
            .find_module(&name)
            .map(|m| m.base)
            .unwrap_or(0);
        Ok(SvcResult::Return(base))
    }
}

pub struct MallocSvc(pub Arch);
impl Svc for MallocSvc {
    fn name(&self) -> &str { "malloc" }
    fn handle(&mut self, backend: &mut dyn Backend, memory: &mut MemoryManager) -> Result<SvcResult> {
        let size = match self.0 {
            Arch::Arm64 => backend.reg_read(Arm64Reg::X0 as u32)? as usize,
            Arch::Arm32 => backend.reg_read(ArmReg::R0 as u32)? as usize,
        };
        let block = memory.malloc(backend, size.max(1), true)?;
        Ok(SvcResult::Return(block.addr))
    }
}

pub struct CallocSvc(pub Arch);
impl Svc for CallocSvc {
    fn name(&self) -> &str { "calloc" }
    fn handle(&mut self, backend: &mut dyn Backend, memory: &mut MemoryManager) -> Result<SvcResult> {
        let (nmemb, size) = match self.0 {
            Arch::Arm64 => (
                backend.reg_read(Arm64Reg::X0 as u32)? as usize,
                backend.reg_read(Arm64Reg::X1 as u32)? as usize,
            ),
            Arch::Arm32 => (
                backend.reg_read(ArmReg::R0 as u32)? as usize,
                backend.reg_read(ArmReg::R1 as u32)? as usize,
            ),
        };
        let total = nmemb.saturating_mul(size).max(1);
        let block = memory.malloc(backend, total, true)?;
        let zeros = vec![0u8; total];
        backend.mem_write(block.addr, &zeros)?;
        Ok(SvcResult::Return(block.addr))
    }
}

pub struct FreeSvc;
impl Svc for FreeSvc {
    fn name(&self) -> &str { "free" }
    fn handle(&mut self, _backend: &mut dyn Backend, _memory: &mut MemoryManager) -> Result<SvcResult> {
        Ok(SvcResult::Void)
    }
}

pub struct ReallocSvc(pub Arch);
impl Svc for ReallocSvc {
    fn name(&self) -> &str { "realloc" }
    fn handle(&mut self, backend: &mut dyn Backend, memory: &mut MemoryManager) -> Result<SvcResult> {
        let (ptr, size) = match self.0 {
            Arch::Arm64 => (
                backend.reg_read(Arm64Reg::X0 as u32)?,
                backend.reg_read(Arm64Reg::X1 as u32)? as usize,
            ),
            Arch::Arm32 => (
                backend.reg_read(ArmReg::R0 as u32)?,
                backend.reg_read(ArmReg::R1 as u32)? as usize,
            ),
        };
        if size == 0 {
            return Ok(SvcResult::Return(0));
        }
        let block = memory.malloc(backend, size, true)?;
        if ptr != 0 {
            let old_sz = memory.alloc_size(ptr).unwrap_or(size);
            let copy_len = old_sz.min(size);
            if copy_len > 0 {
                let mut tmp = vec![0u8; copy_len];
                if backend.mem_read(ptr, &mut tmp).is_ok() {
                    backend.mem_write(block.addr, &tmp)?;
                }
            }
        }
        Ok(SvcResult::Return(block.addr))
    }
}
