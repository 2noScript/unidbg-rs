use unidbg_api::arm::backend::{Arm64Reg, ArmReg, Backend};
use unidbg_api::arm::Arch;
use unidbg_api::error::{Result, UnidbgError};
use unidbg_api::memory::MemoryManager;
use unidbg_api::spi::SyscallHandler;

/// Darwin (iOS/macOS) BSD & Mach trap syscall handler (`DarwinSyscallHandler`).
pub struct DarwinSyscallHandler {
    arch: Arch,
    pid: u32,
}

impl DarwinSyscallHandler {
    pub fn new(arch: Arch, pid: u32) -> Self {
        Self { arch, pid }
    }
}

impl SyscallHandler for DarwinSyscallHandler {
    fn handle(&mut self, backend: &mut dyn Backend, _memory: &mut MemoryManager) -> Result<()> {
        match self.arch {
            Arch::Arm64 => {
                let nr = backend.reg_read(Arm64Reg::X16 as u32)? as i64;
                let x0 = backend.reg_read(Arm64Reg::X0 as u32)?;
                let ret: i64 = match nr {
                    1 => return Err(UnidbgError::StopEmulator(x0 as i64)), // exit
                    20 => self.pid as i64,                                 // getpid
                    24 | 25 => 501,                                        // getuid / geteuid (mobile)
                    -26 | -27 | -28 | -29 => 1,                            // mach_reply_port / thread_self / task_self / host_self
                    _ => {
                        tracing::debug!(nr, "unhandled Darwin ARM64 syscall -> 0");
                        0
                    }
                };
                backend.reg_write(Arm64Reg::X0 as u32, ret as u64)?;
            }
            Arch::Arm32 => {
                let nr = backend.reg_read(ArmReg::R12 as u32)? as i32 as i64;
                let r0 = backend.reg_read(ArmReg::R0 as u32)?;
                let ret: i64 = match nr {
                    1 => return Err(UnidbgError::StopEmulator(r0 as i64)),
                    20 => self.pid as i64,
                    24 | 25 => 501,
                    -26 | -27 | -28 | -29 => 1,
                    _ => 0,
                };
                backend.reg_write(ArmReg::R0 as u32, ret as u64)?;
            }
        }
        Ok(())
    }
}
