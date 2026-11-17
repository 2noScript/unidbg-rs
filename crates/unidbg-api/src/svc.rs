use crate::arm::backend::Backend;
use crate::error::Result;
use crate::memory::MemoryManager;

/// Result of handling an emulated supervisor call (`SVC`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvcResult {
    /// Write value to `X0` / `R0` and return to caller.
    Return(u64),
    /// Return to caller without modifying `X0` / `R0`.
    Void,
    /// Stop emulation with exit status.
    Stop(i64),
}

/// Supervisor call handler registered in [`crate::arm::svc::ArmSvcMemory`].
pub trait Svc {
    fn name(&self) -> &str {
        "svc"
    }

    fn handle(&mut self, backend: &mut dyn Backend, memory: &mut MemoryManager) -> Result<SvcResult>;
}
