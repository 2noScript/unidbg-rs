use goblin::mach::constants::cputype::{CPU_TYPE_ARM, CPU_TYPE_ARM64};
use goblin::mach::load_command::CommandVariant;
use goblin::mach::{Mach, MachO};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use unidbg_api::arm::backend::{Backend, MemoryPerm};
use unidbg_api::arm::Arch;
use unidbg_api::error::{Result, UnidbgError};
use unidbg_api::memory::{align_down, align_up, Memory, MemoryManager, PAGE_SIZE};
use unidbg_api::module::{Module, Symbol};
use unidbg_api::spi::LibraryFile;

/// Loaded Mach-O binary or `.dylib` (`MachOModule`).
#[derive(Debug, Clone)]
pub struct MachOModule {
    pub name: String,
    pub base: u64,
    pub size: usize,
    pub entry_point: u64,
    pub needed_dylibs: Vec<String>,
    pub symbols: HashMap<String, u64>,
    /// Map of symbol name -> pointer slot address in `__la_symbol_ptr` / `__nl_symbol_ptr` / `__got`.
    pub symbol_ptrs: HashMap<String, Vec<u64>>,
}

impl MachOModule {
    pub fn find_symbol_addr(&self, name: &str) -> Option<u64> {
        self.symbols
            .get(name)
            .copied()
            .or_else(|| self.symbols.get(&format!("_{name}")).copied())
    }
}

impl Module for MachOModule {
    fn name(&self) -> &str {
        &self.name
    }

    fn base(&self) -> u64 {
        self.base
    }

    fn size(&self) -> usize {
        self.size
    }

    fn entry_point(&self) -> u64 {
        self.entry_point
    }

    fn find_symbol(&self, name: &str) -> Option<Symbol> {
        self.find_symbol_addr(name).map(|address| Symbol {
            name: name.to_string(),
            address,
        })
    }
}

/// Mach-O file on host filesystem.
pub struct MachOLibraryFile {
    path: PathBuf,
    name: String,
}

impl MachOLibraryFile {
    pub fn new(path: impl AsRef<Path>) -> Self {
        let p = path.as_ref().to_path_buf();
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".to_string());
        Self { path: p, name }
    }
}

impl LibraryFile for MachOLibraryFile {
    fn name(&self) -> &str {
        &self.name
    }

    fn read_bytes(&self) -> Result<Vec<u8>> {
        Ok(std::fs::read(&self.path)?)
    }

    fn resolve_library(&self, _so_name: &str) -> Option<Box<dyn LibraryFile>> {
        None
    }
}

/// Loads Mach-O 32-bit/64-bit executables and `.dylib`s (including Fat/Universal binaries).
pub struct MachOLoader {
    arch: Arch,
    modules: Vec<MachOModule>,
    global_symbols: HashMap<String, u64>,
}

impl MachOLoader {
    pub fn new(arch: Arch) -> Self {
        Self {
            arch,
            modules: Vec::new(),
            global_symbols: HashMap::new(),
        }
    }

    pub fn modules(&self) -> &[MachOModule] {
        &self.modules
    }

    pub fn find_symbol(&self, name: &str) -> Option<u64> {
        self.global_symbols
            .get(name)
            .copied()
            .or_else(|| self.global_symbols.get(&format!("_{name}")).copied())
    }

    fn pick_slice<'a>(&self, raw: &'a [u8], name: &str) -> Result<MachO<'a>> {
        let target_cputype = match self.arch {
            Arch::Arm64 => CPU_TYPE_ARM64,
            Arch::Arm32 => CPU_TYPE_ARM,
        };
        match Mach::parse(raw).map_err(|e| UnidbgError::ElfLoad(format!("macho parse {name}: {e}")))? {
            Mach::Binary(m) => Ok(m),
            Mach::Fat(fat) => {
                let arches = fat.arches().map_err(|e| UnidbgError::ElfLoad(format!("fat arches: {e}")))?;
                for (idx, a) in arches.iter().enumerate() {
                    if a.cputype() == target_cputype {
                        let slice = &raw[a.offset as usize..(a.offset + a.size) as usize];
                        return MachO::parse(slice, 0)
                            .map_err(|e| UnidbgError::ElfLoad(format!("fat slice {idx}: {e}")));
                    }
                }
                Err(UnidbgError::ElfLoad(format!(
                    "{name}: no slice matching {:?}",
                    self.arch
                )))
            }
        }
    }

    pub fn load(
        &mut self,
        file: &dyn LibraryFile,
        backend: &mut dyn Backend,
        memory: &mut MemoryManager,
    ) -> Result<MachOModule> {
        let raw = file.read_bytes()?;
        let macho = self.pick_slice(&raw, file.name())?;

        // Compute vmaddr span across segments (excluding __PAGEZERO)
        let mut min_vm = u64::MAX;
        let mut max_vm = 0u64;
        for seg in &macho.segments {
            let seg_name = seg.name().unwrap_or("");
            if seg_name == "__PAGEZERO" || seg.vmsize == 0 {
                continue;
            }
            min_vm = min_vm.min(seg.vmaddr);
            max_vm = max_vm.max(seg.vmaddr + seg.vmsize);
        }
        if min_vm == u64::MAX {
            return Err(UnidbgError::ElfLoad(format!("{}: no mappable Mach-O segments", file.name())));
        }

        let aligned_min = align_down(min_vm, PAGE_SIZE as u64);
        let aligned_max = align_up(max_vm, PAGE_SIZE as u64);
        let total_size = (aligned_max - aligned_min) as usize;

        let base = memory.mmap(backend, 0, total_size, MemoryPerm::ALL)?;
        let slide = base.wrapping_sub(aligned_min);

        for seg in &macho.segments {
            let seg_name = seg.name().unwrap_or("");
            if seg_name == "__PAGEZERO" || seg.vmsize == 0 {
                continue;
            }
            let file_off = seg.fileoff as usize;
            let file_sz = seg.filesize as usize;
            if file_sz > 0 && file_off + file_sz <= raw.len() {
                backend.mem_write(seg.vmaddr.wrapping_add(slide), &raw[file_off..file_off + file_sz])?;
            }
        }

        // Apply segment permissions
        for seg in &macho.segments {
            let seg_name = seg.name().unwrap_or("");
            if seg_name == "__PAGEZERO" || seg.vmsize == 0 {
                continue;
            }
            let s_start = align_down(seg.vmaddr.wrapping_add(slide), PAGE_SIZE as u64);
            let s_end = align_up(seg.vmaddr.wrapping_add(seg.vmsize).wrapping_add(slide), PAGE_SIZE as u64);
            let mut perm = MemoryPerm::NONE;
            if seg.initprot & 1 != 0 {
                perm |= MemoryPerm::READ;
            }
            if seg.initprot & 2 != 0 {
                perm |= MemoryPerm::WRITE;
            }
            if seg.initprot & 4 != 0 {
                perm |= MemoryPerm::EXEC;
            }
            if perm != MemoryPerm::NONE {
                memory.mprotect(backend, s_start, (s_end - s_start) as usize, perm)?;
            }
        }

        let needed_dylibs: Vec<String> = macho.libs.iter().map(|s| (*s).to_string()).collect();

        // Collect symbols
        let mut symbols = HashMap::new();
        if let Some(syms) = &macho.symbols {
            for (name, nlist) in syms.iter().flatten() {
                if nlist.n_value != 0 && !name.is_empty() {
                    let addr = nlist.n_value.wrapping_add(slide);
                    symbols.insert(name.to_string(), addr);
                    self.global_symbols.entry(name.to_string()).or_insert(addr);
                }
            }
        }
        if let Ok(exports) = macho.exports() {
            for exp in exports {
                if !exp.name.is_empty() {
                    let addr = base.wrapping_add(exp.offset);
                    symbols.entry(exp.name.clone()).or_insert(addr);
                    self.global_symbols.entry(exp.name).or_insert(addr);
                }
            }
        }

        // Record entry point (LC_MAIN)
        let mut entry_point = 0u64;
        for lc in &macho.load_commands {
            if let CommandVariant::Main(main_cmd) = lc.command {
                entry_point = base.wrapping_add(main_cmd.entryoff);
            }
        }

        // Collect symbol pointer slots for FishHook (from __la_symbol_ptr / __nl_symbol_ptr / __got)
        let mut symbol_ptrs: HashMap<String, Vec<u64>> = HashMap::new();
        for seg in &macho.segments {
            if let Ok(sections) = seg.sections() {
                for (sec, _) in sections {
                    let sec_name = sec.name().unwrap_or("");
                    if matches!(sec_name, "__la_symbol_ptr" | "__nl_symbol_ptr" | "__got" | "__auth_got") {
                        let ptr_sz = if self.arch == Arch::Arm64 { 8u64 } else { 4u64 };
                        let count = sec.size / ptr_sz;
                        for idx in 0..count {
                            let slot_addr = sec.addr.wrapping_add(slide) + idx * ptr_sz;
                            symbol_ptrs
                                .entry(format!("{sec_name}#{idx}"))
                                .or_default()
                                .push(slot_addr);
                        }
                    }
                }
            }
        }

        let module = MachOModule {
            name: file.name().to_string(),
            base,
            size: total_size,
            entry_point,
            needed_dylibs,
            symbols,
            symbol_ptrs,
        };
        self.modules.push(module.clone());
        Ok(module)
    }
}
