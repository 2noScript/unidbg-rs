use crate::arm::backend::{Arm64Reg, ArmReg, Backend, MemoryPerm};
use crate::arm::{Arch, ArmMode};
use crate::error::{Result, UnidbgError};
use crate::memory::{Memory, MemoryManager};
use crate::svc::{Svc, SvcResult};
use std::collections::HashMap;

pub const SVC_BASE: u64 = 0xfffe_0000;
pub const SVC_SIZE: usize = 0x10000;

/// Allocates and dispatches synthetic `SVC #imm` trampolines (replaces `ARMSvcMemory`).
pub struct ArmSvcMemory {
    arch: Arch,
    mode: ArmMode,
    base: u64,
    cursor: u64,
    end: u64,
    next_svc_num: u32,
    mapped: bool,
    handlers: HashMap<u32, Box<dyn Svc>>,
}

impl ArmSvcMemory {
    pub fn new(arch: Arch, mode: ArmMode) -> Self {
        Self {
            arch,
            mode,
            base: SVC_BASE,
            cursor: SVC_BASE,
            end: SVC_BASE + SVC_SIZE as u64,
            next_svc_num: 0x100,
            mapped: false,
            handlers: HashMap::new(),
        }
    }

    fn ensure_mapped(&mut self, backend: &mut dyn Backend, memory: &mut MemoryManager) -> Result<()> {
        if !self.mapped {
            memory.mmap(backend, self.base, SVC_SIZE, MemoryPerm::READ | MemoryPerm::EXEC)?;
            self.mapped = true;
        }
        Ok(())
    }

    /// Register a [`Svc`] handler and emit a stub (`SVC #imm; RET` / `BX LR`) in guest memory.
    pub fn register_svc(
        &mut self,
        backend: &mut dyn Backend,
        memory: &mut MemoryManager,
        svc: Box<dyn Svc>,
    ) -> Result<u64> {
        self.ensure_mapped(backend, memory)?;
        let svc_num = self.next_svc_num;
        self.next_svc_num += 1;

        let addr = self.cursor;
        match (self.arch, self.mode) {
            (Arch::Arm64, _) => {
                if addr + 8 > self.end {
                    return Err(UnidbgError::Backend("SVC memory exhausted".into()));
                }
                // SVC #svc_num (0xd4000001 | (imm16 << 5)) ; RET (0xd65f03c0)
                let svc_insn: u32 = 0xd400_0001 | ((svc_num & 0xffff) << 5);
                let ret_insn: u32 = 0xd65f_03c0;
                backend.mem_write(addr, &svc_insn.to_le_bytes())?;
                backend.mem_write(addr + 4, &ret_insn.to_le_bytes())?;
                self.cursor += 8;
                self.handlers.insert(svc_num, svc);
                Ok(addr)
            }
            (Arch::Arm32, ArmMode::Arm32) => {
                if addr + 8 > self.end {
                    return Err(UnidbgError::Backend("SVC memory exhausted".into()));
                }
                // SVC #svc_num (0xef000000 | imm24) ; BX LR (0xe12fff1e)
                let svc_insn: u32 = 0xef00_0000 | (svc_num & 0x00ff_ffff);
                let bx_lr: u32 = 0xe12f_ff1e;
                backend.mem_write(addr, &svc_insn.to_le_bytes())?;
                backend.mem_write(addr + 4, &bx_lr.to_le_bytes())?;
                self.cursor += 8;
                self.handlers.insert(svc_num, svc);
                Ok(addr)
            }
            (Arch::Arm32, ArmMode::Thumb) => {
                if addr + 4 > self.end {
                    return Err(UnidbgError::Backend("SVC memory exhausted".into()));
                }
                let imm8 = (svc_num & 0xff) as u16;
                let svc_insn: u16 = 0xdf00 | imm8;
                let bx_lr: u16 = 0x4770;
                backend.mem_write(addr, &svc_insn.to_le_bytes())?;
                backend.mem_write(addr + 2, &bx_lr.to_le_bytes())?;
                self.cursor += 4;
                self.handlers.insert(svc_num, svc);
                Ok(addr | 1)
            }
            _ => Err(UnidbgError::Backend("unsupported arch/mode for SVC".into())),
        }
    }

    /// Dispatch a synthetic `SVC #svc_num` if registered. Returns `Ok(Some(res))` if handled.
    pub fn dispatch(
        &mut self,
        svc_num: u32,
        backend: &mut dyn Backend,
        memory: &mut MemoryManager,
    ) -> Result<Option<SvcResult>> {
        let Some(handler) = self.handlers.get_mut(&svc_num) else {
            return Ok(None);
        };
        let res = handler.handle(backend, memory)?;
        if let SvcResult::Return(val) = res {
            let ret_reg = match self.arch {
                Arch::Arm64 => Arm64Reg::X0 as u32,
                Arch::Arm32 => ArmReg::R0 as u32,
            };
            backend.reg_write(ret_reg, val)?;
        }
        Ok(Some(res))
    }
}
