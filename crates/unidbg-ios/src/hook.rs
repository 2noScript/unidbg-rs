use crate::macho_loader::MachOLoader;
use unidbg_api::arm::backend::Backend;
use unidbg_api::arm::Arch;
use unidbg_api::error::Result;
use unidbg_api::hook::InlineHook;
use unidbg_api::pointer::UnidbgPointer;

/// Mach-O symbol rebinding hook (`FishHook`).
pub struct FishHook {
    arch: Arch,
}

impl FishHook {
    pub fn new(arch: Arch) -> Self {
        Self { arch }
    }

    /// Rebind a symbol pointer slot in a loaded [`crate::macho_loader::MachOModule`].
    pub fn rebind_slot(
        &self,
        backend: &mut dyn Backend,
        slot_addr: u64,
        replacement_addr: u64,
    ) -> Result<()> {
        let ptr_sz = if self.arch == Arch::Arm64 { 8 } else { 4 };
        UnidbgPointer::new(slot_addr, ptr_sz).write_pointer(backend, replacement_addr)
    }

    /// Rebind all recorded slots matching `slot_key` across loaded modules.
    pub fn rebind_by_key(
        &self,
        loader: &MachOLoader,
        backend: &mut dyn Backend,
        slot_key: &str,
        replacement_addr: u64,
    ) -> Result<usize> {
        let mut count = 0usize;
        for m in loader.modules() {
            if let Some(slots) = m.symbol_ptrs.get(slot_key) {
                for &slot in slots {
                    self.rebind_slot(backend, slot, replacement_addr)?;
                    count += 1;
                }
            }
        }
        Ok(count)
    }
}

/// Cydia Substrate-style inline hook (`Substrate`).
pub struct Substrate;

impl Substrate {
    pub fn hook_function(
        arch: Arch,
        backend: &mut dyn Backend,
        symbol_addr: u64,
        replace_addr: u64,
    ) -> Result<Vec<u8>> {
        InlineHook::replace(arch, backend, symbol_addr, replace_addr)
    }
}
