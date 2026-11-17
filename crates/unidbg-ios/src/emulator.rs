use crate::macho_loader::{MachOLibraryFile, MachOLoader, MachOModule};
use crate::syscall::DarwinSyscallHandler;
use std::path::Path;
use unidbg_api::arm::backend::{Arm64Reg, ArmReg, Backend, MemoryPerm};
use unidbg_api::arm::{Arch, ArmMode};
use unidbg_api::emulator::{Emulator, EmulatorCore, Family};
use unidbg_api::error::Result;

/// High-level iOS/Darwin emulator (`DarwinEmulator`).
pub struct DarwinEmulator {
    core: EmulatorCore,
    loader: MachOLoader,
    lr_stop_addr: u64,
}

impl DarwinEmulator {
    pub fn new(arch: Arch, name: impl Into<String>, backend: Box<dyn Backend>) -> Result<Self> {
        let family = match arch {
            Arch::Arm32 => Family::Ios32,
            Arch::Arm64 => Family::Ios64,
        };
        let mode = match arch {
            Arch::Arm32 => ArmMode::Arm32,
            Arch::Arm64 => ArmMode::Arm64,
        };
        let mut core = EmulatorCore::new(family, mode, name, backend)?;
        let syscall_handler = DarwinSyscallHandler::new(arch, core.pid());
        core.set_syscall_handler(Box::new(syscall_handler));
        let lr_stop_addr = core.mmap(0, 0x1000, MemoryPerm::READ | MemoryPerm::EXEC)?;

        Ok(Self {
            core,
            loader: MachOLoader::new(arch),
            lr_stop_addr,
        })
    }

    pub fn load_macho(&mut self, path: impl AsRef<Path>) -> Result<MachOModule> {
        let file = MachOLibraryFile::new(path);
        let (backend, memory) = self.core.parts_mut();
        self.loader.load(&file, backend, memory)
    }

    pub fn loader(&self) -> &MachOLoader {
        &self.loader
    }

    pub fn core(&self) -> &EmulatorCore {
        &self.core
    }

    pub fn core_mut(&mut self) -> &mut EmulatorCore {
        &mut self.core
    }

    pub fn loader_and_core_mut(&mut self) -> (&MachOLoader, &mut EmulatorCore) {
        (&self.loader, &mut self.core)
    }

    pub fn call_function(&mut self, addr: u64, args: &[u64]) -> Result<u64> {
        match self.core.arch() {
            Arch::Arm64 => {
                let regs = [Arm64Reg::X0, Arm64Reg::X1, Arm64Reg::X2, Arm64Reg::X3];
                for (i, &v) in args.iter().take(4).enumerate() {
                    self.core.backend_mut().reg_write(regs[i] as u32, v)?;
                }
                self.core
                    .backend_mut()
                    .reg_write(Arm64Reg::X30 as u32, self.lr_stop_addr)?;
            }
            Arch::Arm32 => {
                let regs = [ArmReg::R0, ArmReg::R1, ArmReg::R2, ArmReg::R3];
                for (i, &v) in args.iter().take(4).enumerate() {
                    self.core.backend_mut().reg_write(regs[i] as u32, v)?;
                }
                self.core
                    .backend_mut()
                    .reg_write(ArmReg::LR as u32, self.lr_stop_addr)?;
            }
        }
        self.core.emulate(addr, self.lr_stop_addr)
    }
}
