use unidbg_api::arm::backend::{Backend, BackendContext, CodeHookFn, HookId, IntrHookFn, MemHookFn, MemoryPerm};
use unidbg_api::arm::Arch;
use unidbg_api::error::{Result, UnidbgError};

/// Dynarmic ARM32/ARM64 JIT backend (`DynarmicBackend`).
/// Links against `libdynarmic.a` when `DYNARMIC_HOME` is configured.
pub struct DynarmicBackend {
    _arch: Arch,
}

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
