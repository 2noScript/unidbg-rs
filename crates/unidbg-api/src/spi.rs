use crate::error::Result;
use crate::module::Module;
use crate::arm::backend::Backend;
use crate::memory::MemoryManager;

/// Represents an executable/shared library source (ELF, Mach-O, APK entry, etc.).
pub trait LibraryFile {
    fn name(&self) -> &str;
    fn read_bytes(&self) -> Result<Vec<u8>>;
    fn resolve_library(&self, so_name: &str) -> Option<Box<dyn LibraryFile>>;
}

/// Handles OS-level `SVC #0` system calls.
pub trait SyscallHandler {
    fn handle(&mut self, backend: &mut dyn Backend, memory: &mut MemoryManager) -> Result<()>;
}

/// Initializer function (`.init` / `.init_array`).
pub trait InitFunction {
    fn address(&self) -> u64;
}

/// Binary loader interface (implemented by `AndroidElfLoader` and `MachOLoader`).
pub trait Loader {
    fn load(&mut self, file: &dyn LibraryFile, force_call_init: bool) -> Result<Box<dyn Module>>;
}
