use crate::elf_loader::AndroidElfLoader;
use cpp_demangle::Symbol as CppSymbol;
use unidbg_api::arm::backend::Backend;
use unidbg_api::arm::Arch;
use unidbg_api::error::Result;
use unidbg_api::unwind::{Frame, SimpleArmUnwinder, Unwinder};

/// Android stack unwinder with module/symbol resolution and C++ demangling (`AndroidUnwinder`).
pub struct AndroidUnwinder<'a> {
    inner: SimpleArmUnwinder,
    loader: &'a AndroidElfLoader,
}

impl<'a> AndroidUnwinder<'a> {
    pub fn new(arch: Arch, loader: &'a AndroidElfLoader) -> Self {
        Self {
            inner: SimpleArmUnwinder::new(arch),
            loader,
        }
    }

    pub fn demangle(name: &str) -> Option<String> {
        CppSymbol::new(name).ok().map(|s| s.to_string())
    }

    pub fn unwind(&self, backend: &dyn Backend, max_frames: usize) -> Result<Vec<Frame>> {
        let mut frames = self.inner.unwind(backend, max_frames)?;
        for frame in &mut frames {
            for module in self.loader.modules() {
                if frame.pc >= module.base && frame.pc < module.base + module.size as u64 {
                    frame.module = Some(module.name.clone());
                    let mut best: Option<(&str, u64)> = None;
                    for (sym_name, &sym_addr) in &module.symbols {
                        let raw_addr = sym_addr & !1;
                        if raw_addr <= frame.pc {
                            let dist = frame.pc - raw_addr;
                            if best.map_or(true, |(_, d)| dist < d) {
                                best = Some((sym_name.as_str(), dist));
                            }
                        }
                    }
                    if let Some((sym_name, dist)) = best {
                        frame.symbol = Some(sym_name.to_string());
                        frame.demangled = Self::demangle(sym_name);
                        frame.offset = dist;
                    }
                    break;
                }
            }
        }
        Ok(frames)
    }
}
