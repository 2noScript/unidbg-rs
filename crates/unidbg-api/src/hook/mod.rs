use crate::arm::backend::Backend;
use crate::arm::Arch;
use crate::error::{Result, UnidbgError};
use capstone::prelude::*;

/// Inline function hooker (replaces `HookZz` / `Whale` trampoline patching).
pub struct InlineHook;

impl InlineHook {
    /// Inspect instructions at `addr` using Capstone to verify patchability.
    pub fn inspect(arch: Arch, backend: &dyn Backend, addr: u64, count: usize) -> Result<Vec<String>> {
        let cs = match arch {
            Arch::Arm64 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .build(),
            Arch::Arm32 => Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .build(),
        }
        .map_err(|e| UnidbgError::Backend(format!("capstone init failed: {e}")))?;

        let mut buf = vec![0u8; count * 4];
        backend.mem_read(addr & !1, &mut buf)?;
        let insns = cs
            .disasm_count(&buf, addr & !1, count)
            .map_err(|e| UnidbgError::Backend(format!("capstone disasm failed: {e}")))?;

        Ok(insns
            .iter()
            .map(|i| format!("{} {}", i.mnemonic().unwrap_or(""), i.op_str().unwrap_or("")))
            .collect())
    }

    /// Patch the function entry at `target_addr` with an absolute jump to `hook_addr` (e.g. an `Svc` stub).
    /// Returns the original bytes overwritten so the caller can inspect or restore them.
    pub fn replace(arch: Arch, backend: &mut dyn Backend, target_addr: u64, hook_addr: u64) -> Result<Vec<u8>> {
        match arch {
            Arch::Arm64 => {
                // LDR X16, #8 ; BR X16 ; .quad hook_addr (16 bytes)
                let mut orig = vec![0u8; 16];
                backend.mem_read(target_addr, &mut orig)?;
                let mut patch = Vec::with_capacity(16);
                patch.extend_from_slice(&0x5800_0050u32.to_le_bytes()); // ldr x16, #8
                patch.extend_from_slice(&0xd61f_0200u32.to_le_bytes()); // br x16
                patch.extend_from_slice(&hook_addr.to_le_bytes());
                backend.mem_write(target_addr, &patch)?;
                Ok(orig)
            }
            Arch::Arm32 => {
                let addr = target_addr & !1;
                let mut orig = vec![0u8; 8];
                backend.mem_read(addr, &mut orig)?;
                let mut patch = Vec::with_capacity(8);
                // LDR PC, [PC, #-4] ; .word hook_addr (8 bytes)
                patch.extend_from_slice(&0xe51f_f004u32.to_le_bytes());
                patch.extend_from_slice(&(hook_addr as u32).to_le_bytes());
                backend.mem_write(addr, &patch)?;
                Ok(orig)
            }
        }
    }

    /// Restore original bytes overwritten by [`InlineHook::replace`].
    pub fn restore(arch: Arch, backend: &mut dyn Backend, target_addr: u64, orig: &[u8]) -> Result<()> {
        let addr = if arch == Arch::Arm32 { target_addr & !1 } else { target_addr };
        backend.mem_write(addr, orig)
    }
}
