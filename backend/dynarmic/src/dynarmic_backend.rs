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
}
