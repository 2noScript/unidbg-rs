use crate::module::LinuxModule;
use goblin::elf::dynamic::{DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ};
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_DYNAMIC, PT_LOAD, PT_PHDR};
use goblin::elf::reloc::{
    R_AARCH64_ABS64, R_AARCH64_GLOB_DAT, R_AARCH64_IRELATIVE, R_AARCH64_JUMP_SLOT,
    R_AARCH64_RELATIVE, R_ARM_ABS32, R_ARM_GLOB_DAT, R_ARM_IRELATIVE, R_ARM_JUMP_SLOT,
    R_ARM_RELATIVE,
};
use goblin::elf::Elf;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use unidbg_api::arm::backend::{Backend, MemoryPerm};
use unidbg_api::arm::Arch;
use unidbg_api::error::{Result, UnidbgError};
use unidbg_api::memory::{align_down, align_up, Memory, MemoryManager, PAGE_SIZE};
use unidbg_api::spi::LibraryFile;

const DT_RELR: u64 = 36;
const DT_RELRSZ: u64 = 35;

/// ELF file backed by a host filesystem path.
pub struct ElfLibraryFile {
    path: PathBuf,
    name: String,
    search_dirs: Vec<PathBuf>,
}

impl ElfLibraryFile {
    pub fn new(path: impl AsRef<Path>, search_dirs: Vec<PathBuf>) -> Self {
        let p = path.as_ref().to_path_buf();
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown.so".to_string());
        Self {
            path: p,
            name,
            search_dirs,
        }
    }
}

impl LibraryFile for ElfLibraryFile {
    fn name(&self) -> &str {
        &self.name
    }

    fn read_bytes(&self) -> Result<Vec<u8>> {
        Ok(std::fs::read(&self.path)?)
    }

    fn resolve_library(&self, so_name: &str) -> Option<Box<dyn LibraryFile>> {
        for dir in &self.search_dirs {
            let candidate = dir.join(so_name);
            if candidate.is_file() {
                return Some(Box::new(ElfLibraryFile::new(
                    candidate,
                    self.search_dirs.clone(),
                )));
            }
        }
        None
    }
}

/// Loads Android ELF32 and ELF64 binaries & shared objects (`AndroidElfLoader`).
pub struct AndroidElfLoader {
    arch: Arch,
    modules: Vec<LinuxModule>,
    global_symbols: HashMap<String, u64>,
    hooked_symbols: HashMap<String, u64>,
}

impl AndroidElfLoader {
    pub fn new(arch: Arch) -> Self {
        Self {
            arch,
            modules: Vec::new(),
            global_symbols: HashMap::new(),
            hooked_symbols: HashMap::new(),
        }
    }

    pub fn register_hook_symbol(&mut self, name: impl Into<String>, addr: u64) {
        self.hooked_symbols.insert(name.into(), addr);
    }

    pub fn modules(&self) -> &[LinuxModule] {
        &self.modules
    }

    pub fn find_module(&self, name: &str) -> Option<&LinuxModule> {
        self.modules.iter().find(|m| m.name == name)
    }

    pub fn find_symbol(&self, name: &str) -> Option<u64> {
        self.hooked_symbols
            .get(name)
            .copied()
            .or_else(|| self.global_symbols.get(name).copied())
    }

    /// Load an ELF file (and optionally its `DT_NEEDED` dependencies) into guest memory.
    pub fn load(
        &mut self,
        file: &dyn LibraryFile,
        backend: &mut dyn Backend,
        memory: &mut MemoryManager,
        load_needed: bool,
    ) -> Result<LinuxModule> {
        if let Some(existing) = self.find_module(file.name()) {
            return Ok(existing.clone());
        }

        let raw = file.read_bytes()?;
        let elf = Elf::parse(&raw)
            .map_err(|e| UnidbgError::ElfLoad(format!("goblin parse {}: {e}", file.name())))?;

        let expected_64 = self.arch == Arch::Arm64;
        if elf.is_64 != expected_64 {
            return Err(UnidbgError::ElfLoad(format!(
                "{} bitness mismatch: elf.is_64={}, expected={expected_64}",
                file.name(),
                elf.is_64
            )));
        }

        // Compute virtual address span of PT_LOAD segments
        let mut min_vaddr = u64::MAX;
        let mut max_vaddr = 0u64;
        for ph in &elf.program_headers {
            if ph.p_type == PT_LOAD {
                min_vaddr = min_vaddr.min(ph.p_vaddr);
                max_vaddr = max_vaddr.max(ph.p_vaddr + ph.p_memsz);
            }
        }
        if min_vaddr == u64::MAX {
            return Err(UnidbgError::ElfLoad(format!("{}: no PT_LOAD segments", file.name())));
        }

        let aligned_min = align_down(min_vaddr, PAGE_SIZE as u64);
        let aligned_max = align_up(max_vaddr, PAGE_SIZE as u64);
        let total_size = (aligned_max - aligned_min) as usize;

        // Use fixed base for ET_EXEC (non-PIE) or auto-allocate via MemoryManager for ET_DYN
        let is_pie_or_so = elf.header.e_type == goblin::elf::header::ET_DYN;
        let load_bias = if is_pie_or_so {
            let base = memory.mmap(backend, 0, total_size, MemoryPerm::ALL)?;
            base - aligned_min
        } else {
            memory.mmap(backend, aligned_min, total_size, MemoryPerm::ALL)?;
            0
        };
        let module_base = aligned_min + load_bias;

        // Copy PT_LOAD segments & apply page protections
        for ph in &elf.program_headers {
            if ph.p_type != PT_LOAD {
                continue;
            }
            let file_off = ph.p_offset as usize;
            let file_sz = ph.p_filesz as usize;
            if file_off + file_sz > raw.len() {
                return Err(UnidbgError::ElfLoad(format!("{}: PT_LOAD out of bounds", file.name())));
            }
            if file_sz > 0 {
                backend.mem_write(ph.p_vaddr + load_bias, &raw[file_off..file_off + file_sz])?;
            }
        }

        // Apply per-segment permissions after writing
        for ph in &elf.program_headers {
            if ph.p_type != PT_LOAD {
                continue;
            }
            let seg_start = align_down(ph.p_vaddr + load_bias, PAGE_SIZE as u64);
            let seg_end = align_up(ph.p_vaddr + ph.p_memsz + load_bias, PAGE_SIZE as u64);
            let mut perm = MemoryPerm::NONE;
            if ph.p_flags & PF_R != 0 {
                perm |= MemoryPerm::READ;
            }
            if ph.p_flags & PF_W != 0 {
                perm |= MemoryPerm::WRITE;
            }
            if ph.p_flags & PF_X != 0 {
                perm |= MemoryPerm::EXEC;
            }
            memory.mprotect(backend, seg_start, (seg_end - seg_start) as usize, perm)?;
        }

        // Resolve DT_NEEDED dependencies first if requested
        let needed: Vec<String> = elf.libraries.iter().map(|s| (*s).to_string()).collect();
        if load_needed {
            for lib_name in &needed {
                if self.find_module(lib_name).is_none() {
                    if let Some(dep) = file.resolve_library(lib_name) {
                        let _ = self.load(dep.as_ref(), backend, memory, true)?;
                    } else {
                        tracing::debug!(lib = %lib_name, "DT_NEEDED library not found, skipping");
                    }
                }
            }
        }

        // Collect exported symbols
        let mut symbols = HashMap::new();
        for sym in &elf.dynsyms {
            if sym.st_shndx != 0 && sym.st_value != 0 {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        let addr = sym.st_value + load_bias;
                        symbols.insert(name.to_string(), addr);
                        self.global_symbols.entry(name.to_string()).or_insert(addr);
                    }
                }
            }
        }
        for sym in &elf.syms {
            if sym.st_shndx != 0 && sym.st_value != 0 {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        symbols.entry(name.to_string()).or_insert(sym.st_value + load_bias);
                    }
                }
            }
        }

        // Process relocations (dynrelas, dynrels, pltrelocs)
        let plt_got = self.apply_relocs(&elf, load_bias, backend)?;

        // Process DT_RELR if present
        self.apply_dt_relr(&elf, load_bias, backend)?;

        // Collect init functions (.preinit_array, .init, .init_array)
        let init_functions = self.collect_init_functions(&elf, load_bias, backend)?;

        let phdr_addr = elf
            .program_headers
            .iter()
            .find(|ph| ph.p_type == PT_PHDR)
            .map(|ph| ph.p_vaddr + load_bias)
            .unwrap_or(module_base + elf.header.e_phoff);

        let entry_point = if elf.header.e_entry != 0 {
            elf.header.e_entry + load_bias
        } else {
            0
        };

        let module = LinuxModule {
            name: file.name().to_string(),
            base: module_base,
            size: total_size,
            entry_point,
            phdr_addr,
            phnum: elf.header.e_phnum,
            phentsize: elf.header.e_phentsize,
            needed,
            init_functions,
            symbols,
            plt_got,
        };
        self.modules.push(module.clone());
        Ok(module)
    }

    fn write_ptr(&self, backend: &mut dyn Backend, addr: u64, val: u64) -> Result<()> {
        if self.arch == Arch::Arm64 {
            backend.mem_write(addr, &val.to_le_bytes())
        } else {
            backend.mem_write(addr, &(val as u32).to_le_bytes())
        }
    }

    fn read_ptr(&self, backend: &dyn Backend, addr: u64) -> Result<u64> {
        if self.arch == Arch::Arm64 {
            let mut b = [0u8; 8];
            backend.mem_read(addr, &mut b)?;
            Ok(u64::from_le_bytes(b))
        } else {
            let mut b = [0u8; 4];
            backend.mem_read(addr, &mut b)?;
            Ok(u32::from_le_bytes(b) as u64)
        }
    }

    fn apply_relocs(&self, elf: &Elf<'_>, load_bias: u64, backend: &mut dyn Backend) -> Result<HashMap<String, u64>> {
        let mut plt_got = HashMap::new();
        let all_relocs = elf
            .dynrelas
            .iter()
            .chain(elf.dynrels.iter())
            .chain(elf.pltrelocs.iter());

        for reloc in all_relocs {
            let target = reloc.r_offset + load_bias;
            let sym_name = if reloc.r_sym != 0 {
                elf.dynsyms
                    .get(reloc.r_sym)
                    .and_then(|sym| elf.dynstrtab.get_at(sym.st_name))
            } else {
                None
            };
            if let Some(name) = sym_name {
                if reloc.r_type == R_AARCH64_JUMP_SLOT || reloc.r_type == R_ARM_JUMP_SLOT {
                    plt_got.insert(name.to_string(), target);
                }
            }
            let sym_addr = if reloc.r_sym != 0 {
                elf.dynsyms
                    .get(reloc.r_sym)
                    .and_then(|sym| {
                        elf.dynstrtab
                            .get_at(sym.st_name)
                            .and_then(|name| self.find_symbol(name))
                            .or_else(|| {
                                if sym.st_value != 0 {
                                    Some(sym.st_value + load_bias)
                                } else {
                                    None
                                }
                            })
                    })
                    .unwrap_or(0)
            } else {
                0
            };

            let addend = reloc.r_addend.unwrap_or(0);
            match (self.arch, reloc.r_type) {
                (Arch::Arm64, R_AARCH64_RELATIVE) => {
                    let val = (load_bias as i64 + addend) as u64;
                    self.write_ptr(backend, target, val)?;
                }
                (Arch::Arm64, R_AARCH64_GLOB_DAT)
                | (Arch::Arm64, R_AARCH64_JUMP_SLOT)
                | (Arch::Arm64, R_AARCH64_ABS64) => {
                    if sym_addr != 0 {
                        let val = (sym_addr as i64 + addend) as u64;
                        self.write_ptr(backend, target, val)?;
                    }
                }
                (Arch::Arm64, R_AARCH64_IRELATIVE) => {
                    let resolver = (load_bias as i64 + addend) as u64;
                    self.write_ptr(backend, target, resolver)?;
                }
                (Arch::Arm32, R_ARM_RELATIVE) => {
                    let orig = self.read_ptr(backend, target)? as i64;
                    self.write_ptr(backend, target, (load_bias as i64 + orig) as u64)?;
                }
                (Arch::Arm32, R_ARM_GLOB_DAT)
                | (Arch::Arm32, R_ARM_JUMP_SLOT)
                | (Arch::Arm32, R_ARM_ABS32) => {
                    if sym_addr != 0 {
                        let orig = if reloc.r_type == R_ARM_ABS32 {
                            self.read_ptr(backend, target)? as i64
                        } else {
                            0
                        };
                        self.write_ptr(backend, target, (sym_addr as i64 + orig) as u64)?;
                    }
                }
                (Arch::Arm32, R_ARM_IRELATIVE) => {
                    let orig = self.read_ptr(backend, target)? as i64;
                    self.write_ptr(backend, target, (load_bias as i64 + orig) as u64)?;
                }
                _ => {}
            }
        }
        Ok(plt_got)
    }

    fn apply_dt_relr(&self, elf: &Elf<'_>, load_bias: u64, backend: &mut dyn Backend) -> Result<()> {
        let Some(dyn_info) = &elf.dynamic else {
            return Ok(());
        };
        let mut relr_addr = 0u64;
        let mut relr_sz = 0u64;
        for d in &dyn_info.dyns {
            if d.d_tag == DT_RELR {
                relr_addr = d.d_val + load_bias;
            } else if d.d_tag == DT_RELRSZ {
                relr_sz = d.d_val;
            }
        }
        if relr_addr == 0 || relr_sz == 0 {
            return Ok(());
        }
        let ptr_sz = if self.arch == Arch::Arm64 { 8u64 } else { 4u64 };
        let bits_per_word = ptr_sz * 8 - 1;
        let count = relr_sz / ptr_sz;
        let mut where_addr = 0u64;
        for i in 0..count {
            let entry = self.read_ptr(backend, relr_addr + i * ptr_sz)?;
            if entry & 1 == 0 {
                where_addr = entry + load_bias;
                let cur = self.read_ptr(backend, where_addr)?;
                self.write_ptr(backend, where_addr, cur + load_bias)?;
                where_addr += ptr_sz;
            } else {
                let mut bitmap = entry >> 1;
                for bit in 0..bits_per_word {
                    if bitmap & 1 != 0 {
                        let target = where_addr + bit * ptr_sz;
                        let cur = self.read_ptr(backend, target)?;
                        self.write_ptr(backend, target, cur + load_bias)?;
                    }
                    bitmap >>= 1;
                }
                where_addr += bits_per_word * ptr_sz;
            }
        }
        Ok(())
    }

    fn collect_init_functions(
        &self,
        elf: &Elf<'_>,
        load_bias: u64,
        backend: &dyn Backend,
    ) -> Result<Vec<u64>> {
        let mut inits = Vec::new();
        let Some(dyn_info) = &elf.dynamic else {
            return Ok(inits);
        };
        let ptr_sz = if self.arch == Arch::Arm64 { 8u64 } else { 4u64 };
        let mut preinit_arr = 0u64;
        let mut preinit_sz = 0u64;
        let mut init_fn = 0u64;
        let mut init_arr = 0u64;
        let mut init_sz = 0u64;

        for d in &dyn_info.dyns {
            match d.d_tag {
                DT_PREINIT_ARRAY => preinit_arr = d.d_val + load_bias,
                DT_PREINIT_ARRAYSZ => preinit_sz = d.d_val,
                DT_INIT => init_fn = d.d_val + load_bias,
                DT_INIT_ARRAY => init_arr = d.d_val + load_bias,
                DT_INIT_ARRAYSZ => init_sz = d.d_val,
                _ => {}
            }
        }

        let push_array = |inits: &mut Vec<u64>, arr: u64, sz: u64| -> Result<()> {
            if arr != 0 && sz != 0 {
                let n = sz / ptr_sz;
                for i in 0..n {
                    let f = self.read_ptr(backend, arr + i * ptr_sz)?;
                    if f != 0 && f != u64::MAX && (self.arch == Arch::Arm64 || f != u32::MAX as u64) {
                        inits.push(f);
                    }
                }
            }
            Ok(())
        };

        push_array(&mut inits, preinit_arr, preinit_sz)?;
        if init_fn != 0 {
            inits.push(init_fn);
        }
        push_array(&mut inits, init_arr, init_sz)?;
        let _ = elf.program_headers.iter().any(|p| p.p_type == PT_DYNAMIC);
        Ok(inits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use unidbg_api::arm::ArmMode;
    use unidbg_api::module::Module;
    use unidbg_unicorn2::unicorn_backend::UnicornBackend;

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf()
    }

    #[test]
    fn load_real_arm64_so_and_sdk23_libc() {
        let root = repo_root();
        let sdk_lib64 = root.join("unidbg/unidbg-android/src/main/resources/android/sdk23/lib64");
        let target_so = root.join("unidbg/unidbg-android/src/test/resources/example_binaries/arm64-v8a/libtmessages.29.so");

        let mut backend = UnicornBackend::new(Arch::Arm64, ArmMode::Arm64).unwrap();
        let mut memory = MemoryManager::new(Arch::Arm64);
        let mut loader = AndroidElfLoader::new(Arch::Arm64);

        let file = ElfLibraryFile::new(target_so, vec![sdk_lib64]);
        let module = loader.load(&file, &mut backend, &mut memory, true).unwrap();

        assert_eq!(module.name(), "libtmessages.29.so");
        assert!(module.size() > 0);
        assert!(loader.find_module("libc.so").is_some());
        assert!(loader.find_symbol("malloc").is_some());
        assert!(module.find_symbol("JNI_OnLoad").is_some());
        assert!(!memory.memory_maps().is_empty());
    }

    #[test]
    fn load_real_arm32_executable_and_so() {
        let root = repo_root();
        let sdk_lib32 = root.join("unidbg/unidbg-android/src/main/resources/android/sdk23/lib");
        let target_so = root.join("unidbg/unidbg-android/src/test/resources/example_binaries/armeabi-v7a/libnative-lib.so");

        let mut backend = UnicornBackend::new(Arch::Arm32, ArmMode::Arm32).unwrap();
        let mut memory = MemoryManager::new(Arch::Arm32);
        let mut loader = AndroidElfLoader::new(Arch::Arm32);

        let file = ElfLibraryFile::new(target_so, vec![sdk_lib32]);
        let module = loader.load(&file, &mut backend, &mut memory, true).unwrap();

        assert_eq!(module.name(), "libnative-lib.so");
        assert!(loader.find_module("libc.so").is_some());
        assert!(loader.find_symbol("strlen").is_some());
    }
}
