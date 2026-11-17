use crate::error::Result;
use bitflags::bitflags;

bitflags! {
    /// Memory protection flags (matches Unicorn/POSIX PROT_* bits).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MemoryPerm: u32 {
        const NONE  = 0;
        const READ  = 1 << 0;
        const WRITE = 1 << 1;
        const EXEC  = 1 << 2;
        const ALL   = Self::READ.bits() | Self::WRITE.bits() | Self::EXEC.bits();
    }
}

/// ARM32 general-purpose and system registers.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArmReg {
    R0 = 0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
    R11,
    R12,
    SP,
    LR,
    PC,
    CPSR,
    C13C0_3,
}

/// AArch64 general-purpose and system registers.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arm64Reg {
    X0 = 100,
    X1,
    X2,
    X3,
    X4,
    X5,
    X6,
    X7,
    X8,
    X9,
    X10,
    X11,
    X12,
    X13,
    X14,
    X15,
    X16,
    X17,
    X18,
    X19,
    X20,
    X21,
    X22,
    X23,
    X24,
    X25,
    X26,
    X27,
    X28,
    X29,
    X30,
    SP,
    PC,
    NZCV,
    TpidrEl0,
    TpidrroEl0,
    CpacrEl1,
}

/// Opaque handle for an installed backend hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HookId(pub u64);

/// Memory access event kind delivered to memory hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemAccessType {
    Read,
    Write,
    Fetch,
    ReadUnmapped,
    WriteUnmapped,
    FetchUnmapped,
    ReadProt,
    WriteProt,
    FetchProt,
}

pub type CodeHookFn = Box<dyn FnMut(u64, u32)>;
pub type MemHookFn = Box<dyn FnMut(MemAccessType, u64, usize, i64) -> bool>;
pub type IntrHookFn = Box<dyn FnMut(u32) -> bool>;

/// Opaque saved CPU register context.
pub trait BackendContext {
    fn as_any(&self) -> &dyn std::any::Any;
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

/// Low-level CPU emulation backend abstraction (Unicorn, Dynarmic, Hypervisor, KVM).
pub trait Backend {
    fn reg_read(&self, reg: u32) -> Result<u64>;
    fn reg_write(&mut self, reg: u32, value: u64) -> Result<()>;

    fn reg_read_vec(&self, reg: u32) -> Result<u128>;
    fn reg_write_vec(&mut self, reg: u32, value: u128) -> Result<()>;

    fn mem_read(&self, addr: u64, buf: &mut [u8]) -> Result<()>;
    fn mem_write(&mut self, addr: u64, data: &[u8]) -> Result<()>;

    fn mem_map(&mut self, addr: u64, size: usize, perm: MemoryPerm) -> Result<()>;
    fn mem_unmap(&mut self, addr: u64, size: usize) -> Result<()>;
    fn mem_protect(&mut self, addr: u64, size: usize, perm: MemoryPerm) -> Result<()>;

    fn emu_start(&mut self, begin: u64, until: u64, timeout: u64, count: usize) -> Result<()>;
    fn emu_stop(&mut self) -> Result<()>;

    fn context_alloc(&self) -> Result<Box<dyn BackendContext>>;
    fn context_save(&self, ctx: &mut dyn BackendContext) -> Result<()>;
    fn context_restore(&mut self, ctx: &dyn BackendContext) -> Result<()>;

    fn hook_add_code(&mut self, begin: u64, end: u64, cb: CodeHookFn) -> Result<HookId>;
    fn hook_add_mem(&mut self, begin: u64, end: u64, cb: MemHookFn) -> Result<HookId>;
    fn hook_add_intr(&mut self, cb: IntrHookFn) -> Result<HookId>;
    fn hook_del(&mut self, id: HookId) -> Result<()>;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::error::UnidbgError;
    use std::collections::HashMap;

    pub struct MockContext;
    impl BackendContext for MockContext {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
            self
        }
    }

    pub struct MockBackend {
        regs: HashMap<u32, u64>,
        vecs: HashMap<u32, u128>,
        mem: HashMap<u64, Vec<u8>>,
    }

    impl MockBackend {
        pub fn new() -> Self {
            Self {
                regs: HashMap::new(),
                vecs: HashMap::new(),
                mem: HashMap::new(),
            }
        }
    }

    impl Backend for MockBackend {
        fn reg_read(&self, reg: u32) -> Result<u64> {
            Ok(*self.regs.get(&reg).unwrap_or(&0))
        }

        fn reg_write(&mut self, reg: u32, value: u64) -> Result<()> {
            self.regs.insert(reg, value);
            Ok(())
        }

        fn reg_read_vec(&self, reg: u32) -> Result<u128> {
            Ok(*self.vecs.get(&reg).unwrap_or(&0))
        }

        fn reg_write_vec(&mut self, reg: u32, value: u128) -> Result<()> {
            self.vecs.insert(reg, value);
            Ok(())
        }

        fn mem_read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            for (base, page) in &self.mem {
                let end = base + page.len() as u64;
                if addr >= *base && addr + buf.len() as u64 <= end {
                    let off = (addr - *base) as usize;
                    buf.copy_from_slice(&page[off..off + buf.len()]);
                    return Ok(());
                }
            }
            Err(UnidbgError::InvalidMemoryAccess {
                addr,
                size: buf.len(),
                perm: MemoryPerm::READ,
            })
        }

        fn mem_write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
            for (base, page) in &mut self.mem {
                let end = base + page.len() as u64;
                if addr >= *base && addr + data.len() as u64 <= end {
                    let off = (addr - *base) as usize;
                    page[off..off + data.len()].copy_from_slice(data);
                    return Ok(());
                }
            }
            Err(UnidbgError::InvalidMemoryAccess {
                addr,
                size: data.len(),
                perm: MemoryPerm::WRITE,
            })
        }

        fn mem_map(&mut self, addr: u64, size: usize, _perm: MemoryPerm) -> Result<()> {
            self.mem.insert(addr, vec![0u8; size]);
            Ok(())
        }

        fn mem_unmap(&mut self, addr: u64, _size: usize) -> Result<()> {
            self.mem.remove(&addr);
            Ok(())
        }

        fn mem_protect(&mut self, _addr: u64, _size: usize, _perm: MemoryPerm) -> Result<()> {
            Ok(())
        }

        fn emu_start(&mut self, _begin: u64, _until: u64, _timeout: u64, _count: usize) -> Result<()> {
            Ok(())
        }

        fn emu_stop(&mut self) -> Result<()> {
            Ok(())
        }

        fn context_alloc(&self) -> Result<Box<dyn BackendContext>> {
            Ok(Box::new(MockContext))
        }

        fn context_save(&self, _ctx: &mut dyn BackendContext) -> Result<()> {
            Ok(())
        }

        fn context_restore(&mut self, _ctx: &dyn BackendContext) -> Result<()> {
            Ok(())
        }

        fn hook_add_code(&mut self, _begin: u64, _end: u64, _cb: CodeHookFn) -> Result<HookId> {
            Ok(HookId(1))
        }

        fn hook_add_mem(&mut self, _begin: u64, _end: u64, _cb: MemHookFn) -> Result<HookId> {
            Ok(HookId(2))
        }

        fn hook_add_intr(&mut self, _cb: IntrHookFn) -> Result<HookId> {
            Ok(HookId(3))
        }

        fn hook_del(&mut self, _id: HookId) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn mock_backend_regs_and_memory() {
        let mut backend = MockBackend::new();
        backend.reg_write(Arm64Reg::X0 as u32, 0xdeadbeef).unwrap();
        assert_eq!(backend.reg_read(Arm64Reg::X0 as u32).unwrap(), 0xdeadbeef);

        backend.mem_map(0x1000, 0x1000, MemoryPerm::ALL).unwrap();
        backend.mem_write(0x1010, b"unidbg-rs").unwrap();
        let mut buf = [0u8; 9];
        backend.mem_read(0x1010, &mut buf).unwrap();
        assert_eq!(&buf, b"unidbg-rs");
    }
}
