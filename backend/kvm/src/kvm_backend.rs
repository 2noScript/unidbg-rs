use unidbg_api::arm::backend::{Backend, BackendContext, CodeHookFn, HookId, IntrHookFn, MemHookFn, MemoryPerm};
use unidbg_api::error::{Result, UnidbgError};

/// Linux ARM64 KVM backend (`KvmBackend`).
/// Requires Linux on AArch64 with `/dev/kvm` access.
pub struct KvmBackend;

impl KvmBackend {
    pub fn new() -> Result<Self> {
        #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
        {
            Err(UnidbgError::Backend(
                "KvmBackend is only supported on Linux AArch64".into(),
            ))
        }
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        {
            Err(UnidbgError::Backend(
                "KvmBackend requires /dev/kvm initialization".into(),
            ))
        }
    }

    fn unavail(&self) -> UnidbgError {
        UnidbgError::Backend("KvmBackend is not initialized".into())
    }
}

impl Backend for KvmBackend {
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
