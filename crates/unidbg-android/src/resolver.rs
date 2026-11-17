use crate::elf_loader::ElfLibraryFile;
use std::path::PathBuf;
use unidbg_api::arm::Arch;
use unidbg_api::spi::LibraryFile;

/// Resolves Android system libraries for a given SDK level (e.g. 19, 23).
pub struct AndroidResolver {
    sdk: u32,
    arch: Arch,
    search_dirs: Vec<PathBuf>,
}

impl AndroidResolver {
    pub fn new(sdk: u32, arch: Arch, root_dir: impl Into<PathBuf>) -> Self {
        let root = root_dir.into();
        let lib_sub = if arch == Arch::Arm64 { "lib64" } else { "lib" };
        let sdk_dir = root.join(format!("sdk{sdk}")).join(lib_sub);
        Self {
            sdk,
            arch,
            search_dirs: vec![sdk_dir],
        }
    }

    pub fn sdk(&self) -> u32 {
        self.sdk
    }

    pub fn arch(&self) -> Arch {
        self.arch
    }

    pub fn search_dirs(&self) -> &[PathBuf] {
        &self.search_dirs
    }

    pub fn resolve(&self, name: &str) -> Option<Box<dyn LibraryFile>> {
        for dir in &self.search_dirs {
            let p = dir.join(name);
            if p.is_file() {
                return Some(Box::new(ElfLibraryFile::new(p, self.search_dirs.clone())));
            }
        }
        None
    }
}
