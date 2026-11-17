use crate::elf_loader::AndroidElfLoader;
use unidbg_api::arm::backend::Backend;
use unidbg_api::arm::Arch;
use unidbg_api::error::Result;
use unidbg_api::pointer::UnidbgPointer;

/// PLT/GOT hook registration entry.
#[derive(Debug, Clone)]
struct XHookEntry {
    module_filter: String,
    symbol: String,
    callback_addr: u64,
}

/// ELF PLT/GOT hooker (`XHookImpl`).
pub struct XHook {
    arch: Arch,
    entries: Vec<XHookEntry>,
}

impl XHook {
    pub fn new(arch: Arch) -> Self {
        Self {
            arch,
            entries: Vec::new(),
        }
    }

    pub fn register(
        &mut self,
        module_filter: impl Into<String>,
        symbol: impl Into<String>,
        callback_addr: u64,
    ) {
        self.entries.push(XHookEntry {
            module_filter: module_filter.into(),
            symbol: symbol.into(),
            callback_addr,
        });
    }

    /// Apply registered GOT patches to all matching loaded modules. Returns number of patched slots.
    pub fn refresh(&self, loader: &AndroidElfLoader, backend: &mut dyn Backend) -> Result<usize> {
        let ptr_sz = if self.arch == Arch::Arm64 { 8 } else { 4 };
        let mut patched = 0usize;
        for module in loader.modules() {
            for entry in &self.entries {
                if module.name.contains(&entry.module_filter) {
                    if let Some(&got_addr) = module.plt_got.get(&entry.symbol) {
                        UnidbgPointer::new(got_addr, ptr_sz)
                            .write_pointer(backend, entry.callback_addr)?;
                        patched += 1;
                    }
                }
            }
        }
        Ok(patched)
    }
}
