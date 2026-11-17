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
}
