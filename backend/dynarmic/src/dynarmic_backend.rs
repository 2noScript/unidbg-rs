use unidbg_api::arm::backend::{
    Backend, BackendContext, CodeHookFn, HookId, IntrHookFn, MemHookFn, MemoryPerm,
};
use unidbg_api::arm::Arch;
use unidbg_api::error::{Result, UnidbgError};

#[cfg(has_dynarmic)]
mod ffi {
    use super::*;
    use std::ffi::c_void;
    use unidbg_api::arm::backend::Arm64Reg;

    #[repr(C)]
    pub struct UnidbgDynarmic {
        _private: [u8; 0],
    }

    extern "C" {
        fn unidbg_dynarmic_create(is_64bit: i32) -> *mut UnidbgDynarmic;
        fn unidbg_dynarmic_destroy(ctx: *mut UnidbgDynarmic);
        fn unidbg_dynarmic_mem_map(ctx: *mut UnidbgDynarmic, addr: u64, size: usize, perm: i32) -> i32;
        fn unidbg_dynarmic_mem_unmap(ctx: *mut UnidbgDynarmic, addr: u64, size: usize) -> i32;
        fn unidbg_dynarmic_mem_read(ctx: *mut UnidbgDynarmic, addr: u64, buf: *mut c_void, size: usize) -> i32;
        fn unidbg_dynarmic_mem_write(ctx: *mut UnidbgDynarmic, addr: u64, buf: *const c_void, size: usize) -> i32;
        fn unidbg_dynarmic_reg_read(ctx: *mut UnidbgDynarmic, reg: u32) -> u64;
        fn unidbg_dynarmic_reg_write(ctx: *mut UnidbgDynarmic, reg: u32, value: u64);
        fn unidbg_dynarmic_emu_start(ctx: *mut UnidbgDynarmic, begin: u64, until: u64, count: usize) -> i32;
        fn unidbg_dynarmic_emu_stop(ctx: *mut UnidbgDynarmic);
    }

    /// Dynarmic ARM32/ARM64 JIT backend (`DynarmicBackend`).
    pub struct DynarmicBackend {
        ptr: *mut UnidbgDynarmic,
    }

    impl DynarmicBackend {
        pub fn new(arch: Arch) -> Result<Self> {
            let ptr = unsafe { unidbg_dynarmic_create(if arch == Arch::Arm64 { 1 } else { 0 }) };
            if ptr.is_null() {
                return Err(UnidbgError::Backend("unidbg_dynarmic_create failed".into()));
            }
            Ok(Self { ptr })
        }

        fn map_reg(reg: u32) -> u32 {
            if reg == Arm64Reg::X0 as u32 {
                0
            } else if (Arm64Reg::X1 as u32..=Arm64Reg::X28 as u32).contains(&reg) {
                1 + (reg - Arm64Reg::X1 as u32)
            } else if reg == Arm64Reg::X29 as u32 {
                29
            } else if reg == Arm64Reg::X30 as u32 {
                30
            } else if reg == Arm64Reg::SP as u32 {
                31
            } else if reg == Arm64Reg::PC as u32 {
                32
            } else {
                reg
            }
        }
    }

    impl Drop for DynarmicBackend {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
                unsafe { unidbg_dynarmic_destroy(self.ptr) };
            }
        }
    }

    impl Backend for DynarmicBackend {
        fn reg_read(&self, reg: u32) -> Result<u64> {
            Ok(unsafe { unidbg_dynarmic_reg_read(self.ptr, Self::map_reg(reg)) })
        }
        fn reg_write(&mut self, reg: u32, value: u64) -> Result<()> {
            unsafe { unidbg_dynarmic_reg_write(self.ptr, Self::map_reg(reg), value) };
            Ok(())
        }
        fn reg_read_vec(&self, _reg: u32) -> Result<u128> { Ok(0) }
        fn reg_write_vec(&mut self, _reg: u32, _value: u128) -> Result<()> { Ok(()) }
        fn mem_read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let rc = unsafe { unidbg_dynarmic_mem_read(self.ptr, addr, buf.as_mut_ptr() as *mut c_void, buf.len()) };
            if rc != 0 { return Err(UnidbgError::Backend("dynarmic mem_read failed".into())); }
            Ok(())
        }
        fn mem_write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
            let rc = unsafe { unidbg_dynarmic_mem_write(self.ptr, addr, data.as_ptr() as *const c_void, data.len()) };
            if rc != 0 { return Err(UnidbgError::Backend("dynarmic mem_write failed".into())); }
            Ok(())
        }
        fn mem_map(&mut self, addr: u64, size: usize, perm: MemoryPerm) -> Result<()> {
            let rc = unsafe { unidbg_dynarmic_mem_map(self.ptr, addr, size, perm.bits() as i32) };
            if rc != 0 { return Err(UnidbgError::Backend("dynarmic mem_map failed".into())); }
            Ok(())
        }
        fn mem_unmap(&mut self, addr: u64, size: usize) -> Result<()> {
            let rc = unsafe { unidbg_dynarmic_mem_unmap(self.ptr, addr, size) };
            if rc != 0 { return Err(UnidbgError::Backend("dynarmic mem_unmap failed".into())); }
            Ok(())
        }
        fn mem_protect(&mut self, _addr: u64, _size: usize, _perm: MemoryPerm) -> Result<()> { Ok(()) }
        fn emu_start(&mut self, begin: u64, until: u64, _timeout: u64, count: usize) -> Result<()> {
            let rc = unsafe { unidbg_dynarmic_emu_start(self.ptr, begin, until, count) };
            if rc != 0 { return Err(UnidbgError::Backend("dynarmic emu_start failed".into())); }
            Ok(())
        }
        fn emu_stop(&mut self) -> Result<()> {
            unsafe { unidbg_dynarmic_emu_stop(self.ptr) };
            Ok(())
        }
        fn context_alloc(&self) -> Result<Box<dyn BackendContext>> {
            Err(UnidbgError::Backend("dynarmic context_alloc not implemented".into()))
        }
        fn context_save(&self, _ctx: &mut dyn BackendContext) -> Result<()> {
            Err(UnidbgError::Backend("dynarmic context_save not implemented".into()))
        }
        fn context_restore(&mut self, _ctx: &dyn BackendContext) -> Result<()> {
            Err(UnidbgError::Backend("dynarmic context_restore not implemented".into()))
        }
        fn hook_add_code(&mut self, _begin: u64, _end: u64, _cb: CodeHookFn) -> Result<HookId> {
            Err(UnidbgError::Backend("dynarmic code hooks not implemented".into()))
        }
        fn hook_add_mem(&mut self, _begin: u64, _end: u64, _cb: MemHookFn) -> Result<HookId> {
            Err(UnidbgError::Backend("dynarmic mem hooks not implemented".into()))
        }
        fn hook_add_intr(&mut self, _cb: IntrHookFn) -> Result<HookId> {
            Err(UnidbgError::Backend("dynarmic intr hooks not implemented".into()))
        }
        fn hook_del(&mut self, _id: HookId) -> Result<()> { Ok(()) }
    }
}

#[cfg(has_dynarmic)]
pub use ffi::DynarmicBackend;

#[cfg(not(has_dynarmic))]
/// Dynarmic ARM32/ARM64 JIT backend (`DynarmicBackend`).
/// Links against `libdynarmic.a` when `DYNARMIC_HOME` is configured.
pub struct DynarmicBackend {
    _arch: Arch,
}

#[cfg(not(has_dynarmic))]
impl DynarmicBackend {
    pub fn new(_arch: Arch) -> Result<Self> {
        Err(UnidbgError::Backend(
            "DynarmicBackend requires DYNARMIC_HOME native C++ library".into(),
        ))
    }

    fn unavail(&self) -> UnidbgError {
        UnidbgError::Backend("DynarmicBackend is not initialized".into())
    }
}

#[cfg(not(has_dynarmic))]
impl Backend for DynarmicBackend {
    fn reg_read(&self, _reg: u32) -> Result<u64> { Err(self.unavail()) }
    fn reg_write(&mut self, _reg: u32, _value: u64) -> Result<()> { Err(self.unavail()) }
    fn reg_read_vec(&self, _reg: u32) -> Result<u128> { Err(self.unavail()) }
    fn reg_write_vec(&mut self, _reg: u32, _value: u128) -> Result<()> { Err(self.unavail()) }
    fn mem_read(&self, _addr: u64, _buf: &mut [u8]) -> Result<()> { Err(self.unavail()) }
    fn mem_write(&mut self, _addr: u64, _data: &[u8]) -> Result<()> { Err(self.unavail()) }
    fn mem_map(&mut self, _addr: u64, _size: usize, _perm: MemoryPerm) -> Result<()> { Err(self.unavail()) }
    fn mem_unmap(&mut self, _addr: u64, _size: usize) -> Result<()> { Err(self.unavail()) }
    fn mem_protect(&mut self, _addr: u64, _size: usize, _perm: MemoryPerm) -> Result<()> { Err(self.unavail()) }
    fn emu_start(&mut self, _begin: u64, _until: u64, _timeout: u64, _count: usize) -> Result<()> { Err(self.unavail()) }
    fn emu_stop(&mut self) -> Result<()> { Err(self.unavail()) }
    fn context_alloc(&self) -> Result<Box<dyn BackendContext>> { Err(self.unavail()) }
    fn context_save(&self, _ctx: &mut dyn BackendContext) -> Result<()> { Err(self.unavail()) }
    fn context_restore(&mut self, _ctx: &dyn BackendContext) -> Result<()> { Err(self.unavail()) }
    fn hook_add_code(&mut self, _begin: u64, _end: u64, _cb: CodeHookFn) -> Result<HookId> { Err(self.unavail()) }
    fn hook_add_mem(&mut self, _begin: u64, _end: u64, _cb: MemHookFn) -> Result<HookId> { Err(self.unavail()) }
    fn hook_add_intr(&mut self, _cb: IntrHookFn) -> Result<HookId> { Err(self.unavail()) }
    fn hook_del(&mut self, _id: HookId) -> Result<()> { Err(self.unavail()) }
}
