use std::collections::HashMap;
use unidbg_api::arm::backend::{
    Arm64Reg, ArmReg, Backend, BackendContext, CodeHookFn, HookId, IntrHookFn, MemAccessType,
    MemHookFn, MemoryPerm,
};
use unidbg_api::arm::{Arch, ArmMode};
use unidbg_api::error::{Result, UnidbgError};
use unicorn_engine::unicorn_const::{Arch as UcArch, HookType, MemType, Mode as UcMode, Prot};
use unicorn_engine::{Context as UcContext, RegisterARM, RegisterARM64, UcHookId, Unicorn};

pub struct UnicornContext(pub UcContext);

impl BackendContext for UnicornContext {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

pub struct UnicornBackend {
    uc: Unicorn<'static, ()>,
    arch: Arch,
    next_hook_id: u64,
    hooks: HashMap<u64, UcHookId>,
}

impl UnicornBackend {
    pub fn new(arch: Arch, mode: ArmMode) -> Result<Self> {
        let (uc_arch, uc_mode) = match (arch, mode) {
            (Arch::Arm32, ArmMode::Arm32) => (UcArch::ARM, UcMode::ARM),
            (Arch::Arm32, ArmMode::Thumb) => (UcArch::ARM, UcMode::THUMB),
            (Arch::Arm64, ArmMode::Arm64) => (UcArch::ARM64, UcMode::ARM),
            _ => {
                return Err(UnidbgError::Backend(format!(
                    "incompatible arch {arch:?} and mode {mode:?}"
                )))
            }
        };

        let mut uc = Unicorn::new(uc_arch, uc_mode)
            .map_err(|e| UnidbgError::Backend(format!("unicorn init failed: {e:?}")))?;

        if arch == Arch::Arm64 {
            // Enable FP/SIMD (CPACR_EL1.FPEN = 0b11) like unidbg's Unicorn2Backend
            let _ = uc.reg_write(RegisterARM64::CPACR_EL1, 0x3 << 20);
        } else {
            // Enable VFP/NEON (CP10/CP11 + FPEXC.EN) on ARM32 like unidbg's Unicorn2Backend
            let _ = uc.reg_write(RegisterARM::C1_C0_2, 0xf0_0000);
            let _ = uc.reg_write(RegisterARM::FPEXC, 0x4000_0000);
        }

        Ok(Self {
            uc,
            arch,
            next_hook_id: 1,
            hooks: HashMap::new(),
        })
    }

    pub fn arch(&self) -> Arch {
        self.arch
    }

    fn map_reg(&self, reg: u32) -> Result<i32> {
        if reg < 100 {
            let r = match reg {
                x if x == ArmReg::R0 as u32 => RegisterARM::R0,
                x if x == ArmReg::R1 as u32 => RegisterARM::R1,
                x if x == ArmReg::R2 as u32 => RegisterARM::R2,
                x if x == ArmReg::R3 as u32 => RegisterARM::R3,
                x if x == ArmReg::R4 as u32 => RegisterARM::R4,
                x if x == ArmReg::R5 as u32 => RegisterARM::R5,
                x if x == ArmReg::R6 as u32 => RegisterARM::R6,
                x if x == ArmReg::R7 as u32 => RegisterARM::R7,
                x if x == ArmReg::R8 as u32 => RegisterARM::R8,
                x if x == ArmReg::R9 as u32 => RegisterARM::R9,
                x if x == ArmReg::R10 as u32 => RegisterARM::R10,
                x if x == ArmReg::R11 as u32 => RegisterARM::R11,
                x if x == ArmReg::R12 as u32 => RegisterARM::R12,
                x if x == ArmReg::SP as u32 => RegisterARM::SP,
                x if x == ArmReg::LR as u32 => RegisterARM::LR,
                x if x == ArmReg::PC as u32 => RegisterARM::PC,
                x if x == ArmReg::CPSR as u32 => RegisterARM::CPSR,
                x if x == ArmReg::C13C0_3 as u32 => RegisterARM::C13_C0_3,
                _ => {
                    return Err(UnidbgError::Backend(format!(
                        "unsupported ARM32 register id {reg}"
                    )))
                }
            };
            Ok(r as i32)
        } else {
            let r = match reg {
                x if x == Arm64Reg::X0 as u32 => RegisterARM64::X0,
                x if x == Arm64Reg::X1 as u32 => RegisterARM64::X1,
                x if x == Arm64Reg::X2 as u32 => RegisterARM64::X2,
                x if x == Arm64Reg::X3 as u32 => RegisterARM64::X3,
                x if x == Arm64Reg::X4 as u32 => RegisterARM64::X4,
                x if x == Arm64Reg::X5 as u32 => RegisterARM64::X5,
                x if x == Arm64Reg::X6 as u32 => RegisterARM64::X6,
                x if x == Arm64Reg::X7 as u32 => RegisterARM64::X7,
                x if x == Arm64Reg::X8 as u32 => RegisterARM64::X8,
                x if x == Arm64Reg::X9 as u32 => RegisterARM64::X9,
                x if x == Arm64Reg::X10 as u32 => RegisterARM64::X10,
                x if x == Arm64Reg::X11 as u32 => RegisterARM64::X11,
                x if x == Arm64Reg::X12 as u32 => RegisterARM64::X12,
                x if x == Arm64Reg::X13 as u32 => RegisterARM64::X13,
                x if x == Arm64Reg::X14 as u32 => RegisterARM64::X14,
                x if x == Arm64Reg::X15 as u32 => RegisterARM64::X15,
                x if x == Arm64Reg::X16 as u32 => RegisterARM64::X16,
                x if x == Arm64Reg::X17 as u32 => RegisterARM64::X17,
                x if x == Arm64Reg::X18 as u32 => RegisterARM64::X18,
                x if x == Arm64Reg::X19 as u32 => RegisterARM64::X19,
                x if x == Arm64Reg::X20 as u32 => RegisterARM64::X20,
                x if x == Arm64Reg::X21 as u32 => RegisterARM64::X21,
                x if x == Arm64Reg::X22 as u32 => RegisterARM64::X22,
                x if x == Arm64Reg::X23 as u32 => RegisterARM64::X23,
                x if x == Arm64Reg::X24 as u32 => RegisterARM64::X24,
                x if x == Arm64Reg::X25 as u32 => RegisterARM64::X25,
                x if x == Arm64Reg::X26 as u32 => RegisterARM64::X26,
                x if x == Arm64Reg::X27 as u32 => RegisterARM64::X27,
                x if x == Arm64Reg::X28 as u32 => RegisterARM64::X28,
                x if x == Arm64Reg::X29 as u32 => RegisterARM64::X29,
                x if x == Arm64Reg::X30 as u32 => RegisterARM64::X30,
                x if x == Arm64Reg::SP as u32 => RegisterARM64::SP,
                x if x == Arm64Reg::PC as u32 => RegisterARM64::PC,
                x if x == Arm64Reg::NZCV as u32 => RegisterARM64::NZCV,
                x if x == Arm64Reg::TpidrEl0 as u32 => RegisterARM64::TPIDR_EL0,
                x if x == Arm64Reg::TpidrroEl0 as u32 => RegisterARM64::TPIDRRO_EL0,
                x if x == Arm64Reg::CpacrEl1 as u32 => RegisterARM64::CPACR_EL1,
                _ => {
                    return Err(UnidbgError::Backend(format!(
                        "unsupported ARM64 register id {reg}"
                    )))
                }
            };
            Ok(r as i32)
        }
    }

    fn map_prot(perm: MemoryPerm) -> Prot {
        let mut prot = Prot::NONE;
        if perm.contains(MemoryPerm::READ) {
            prot |= Prot::READ;
        }
        if perm.contains(MemoryPerm::WRITE) {
            prot |= Prot::WRITE;
        }
        if perm.contains(MemoryPerm::EXEC) {
            prot |= Prot::EXEC;
        }
        prot
    }

    fn map_mem_type(ty: MemType) -> MemAccessType {
        match ty {
            MemType::READ => MemAccessType::Read,
            MemType::WRITE => MemAccessType::Write,
            MemType::FETCH => MemAccessType::Fetch,
            MemType::READ_UNMAPPED => MemAccessType::ReadUnmapped,
            MemType::WRITE_UNMAPPED => MemAccessType::WriteUnmapped,
            MemType::FETCH_UNMAPPED => MemAccessType::FetchUnmapped,
            MemType::READ_PROT => MemAccessType::ReadProt,
            MemType::WRITE_PROT => MemAccessType::WriteProt,
            MemType::FETCH_PROT => MemAccessType::FetchProt,
            _ => MemAccessType::Read,
        }
    }
}

impl Backend for UnicornBackend {
    fn reg_read(&self, reg: u32) -> Result<u64> {
        let uc_reg = self.map_reg(reg)?;
        self.uc
            .reg_read(uc_reg)
            .map_err(|e| UnidbgError::Backend(format!("reg_read failed: {e:?}")))
    }

    fn reg_write(&mut self, reg: u32, value: u64) -> Result<()> {
        let uc_reg = self.map_reg(reg)?;
        self.uc
            .reg_write(uc_reg, value)
            .map_err(|e| UnidbgError::Backend(format!("reg_write failed: {e:?}")))
    }

    fn reg_read_vec(&self, reg: u32) -> Result<u128> {
        let bytes = self
            .uc
            .reg_read_long(reg as i32)
            .map_err(|e| UnidbgError::Backend(format!("reg_read_vec failed: {e:?}")))?;
        let mut arr = [0u8; 16];
        let n = bytes.len().min(16);
        arr[..n].copy_from_slice(&bytes[..n]);
        Ok(u128::from_le_bytes(arr))
    }

    fn reg_write_vec(&mut self, reg: u32, value: u128) -> Result<()> {
        self.uc
            .reg_write_long(reg as i32, &value.to_le_bytes())
            .map_err(|e| UnidbgError::Backend(format!("reg_write_vec failed: {e:?}")))
    }

    fn mem_read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        self.uc
            .mem_read(addr, buf)
            .map_err(|e| UnidbgError::Backend(format!("mem_read({addr:#x}) failed: {e:?}")))
    }

    fn mem_write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        self.uc
            .mem_write(addr, data)
            .map_err(|e| UnidbgError::Backend(format!("mem_write({addr:#x}) failed: {e:?}")))
    }

    fn mem_map(&mut self, addr: u64, size: usize, perm: MemoryPerm) -> Result<()> {
        self.uc
            .mem_map(addr, size as u64, Self::map_prot(perm))
            .map_err(|e| UnidbgError::Backend(format!("mem_map({addr:#x}, {size:#x}) failed: {e:?}")))
    }

    fn mem_unmap(&mut self, addr: u64, size: usize) -> Result<()> {
        self.uc
            .mem_unmap(addr, size as u64)
            .map_err(|e| UnidbgError::Backend(format!("mem_unmap({addr:#x}) failed: {e:?}")))
    }

    fn mem_protect(&mut self, addr: u64, size: usize, perm: MemoryPerm) -> Result<()> {
        self.uc
            .mem_protect(addr, size as u64, Self::map_prot(perm))
            .map_err(|e| UnidbgError::Backend(format!("mem_protect({addr:#x}) failed: {e:?}")))
    }

    fn emu_start(&mut self, begin: u64, until: u64, timeout: u64, count: usize) -> Result<()> {
        self.uc
            .emu_start(begin, until, timeout, count)
            .map_err(|e| UnidbgError::Backend(format!("emu_start({begin:#x}..{until:#x}) failed: {e:?}")))
    }

    fn emu_stop(&mut self) -> Result<()> {
        self.uc
            .emu_stop()
            .map_err(|e| UnidbgError::Backend(format!("emu_stop failed: {e:?}")))
    }

    fn context_alloc(&self) -> Result<Box<dyn BackendContext>> {
        let ctx = self
            .uc
            .context_alloc()
            .map_err(|e| UnidbgError::Backend(format!("context_alloc failed: {e:?}")))?;
        Ok(Box::new(UnicornContext(ctx)))
    }

    fn context_save(&self, ctx: &mut dyn BackendContext) -> Result<()> {
        let uc_ctx = ctx
            .as_any_mut()
            .downcast_mut::<UnicornContext>()
            .ok_or_else(|| UnidbgError::Backend("invalid context type".into()))?;
        self.uc
            .context_save(&mut uc_ctx.0)
            .map_err(|e| UnidbgError::Backend(format!("context_save failed: {e:?}")))
    }

    fn context_restore(&mut self, ctx: &dyn BackendContext) -> Result<()> {
        let uc_ctx = ctx
            .as_any()
            .downcast_ref::<UnicornContext>()
            .ok_or_else(|| UnidbgError::Backend("invalid context type".into()))?;
        self.uc
            .context_restore(&uc_ctx.0)
            .map_err(|e| UnidbgError::Backend(format!("context_restore failed: {e:?}")))
    }

    fn hook_add_code(&mut self, begin: u64, end: u64, mut cb: CodeHookFn) -> Result<HookId> {
        let uc_hook = self
            .uc
            .add_code_hook(begin, end, move |_uc, addr, size| cb(addr, size))
            .map_err(|e| UnidbgError::Backend(format!("hook_add_code failed: {e:?}")))?;
        let id = self.next_hook_id;
        self.next_hook_id += 1;
        self.hooks.insert(id, uc_hook);
        Ok(HookId(id))
    }

    fn hook_add_mem(&mut self, begin: u64, end: u64, mut cb: MemHookFn) -> Result<HookId> {
        let uc_hook = self
            .uc
            .add_mem_hook(HookType::MEM_ALL, begin, end, move |_uc, ty, addr, size, val| {
                cb(Self::map_mem_type(ty), addr, size, val)
            })
            .map_err(|e| UnidbgError::Backend(format!("hook_add_mem failed: {e:?}")))?;
        let id = self.next_hook_id;
        self.next_hook_id += 1;
        self.hooks.insert(id, uc_hook);
        Ok(HookId(id))
    }

    fn hook_add_intr(&mut self, mut cb: IntrHookFn) -> Result<HookId> {
        let uc_hook = self
            .uc
            .add_intr_hook(move |uc, intno| {
                if !cb(intno) {
                    let _ = uc.emu_stop();
                }
            })
            .map_err(|e| UnidbgError::Backend(format!("hook_add_intr failed: {e:?}")))?;
        let id = self.next_hook_id;
        self.next_hook_id += 1;
        self.hooks.insert(id, uc_hook);
        Ok(HookId(id))
    }

    fn hook_del(&mut self, id: HookId) -> Result<()> {
        if let Some(uc_hook) = self.hooks.remove(&id.0) {
            self.uc
                .remove_hook(uc_hook)
                .map_err(|e| UnidbgError::Backend(format!("hook_del failed: {e:?}")))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_destroy_loop() {
        for _ in 0..100 {
            let mut b = UnicornBackend::new(Arch::Arm64, ArmMode::Arm64).unwrap();
            b.mem_map(0x1000, 0x1000, MemoryPerm::ALL).unwrap();
        }
    }

    #[test]
    fn run_arm64_add() {
        let mut backend = UnicornBackend::new(Arch::Arm64, ArmMode::Arm64).unwrap();
        let base = 0x10000u64;
        backend.mem_map(base, 0x1000, MemoryPerm::ALL).unwrap();

        // mov x0, #10   -> 0xd2800140
        // add x0, x0, #32 -> 0x91008000
        let mut code = Vec::new();
        code.extend_from_slice(&0xd2800140u32.to_le_bytes());
        code.extend_from_slice(&0x91008000u32.to_le_bytes());
        backend.mem_write(base, &code).unwrap();

        backend
            .emu_start(base, base + code.len() as u64, 0, 0)
            .unwrap();
        assert_eq!(backend.reg_read(Arm64Reg::X0 as u32).unwrap(), 42);
    }

    #[test]
    fn run_arm32_add() {
        // ARM mode: mov r0, #10 (0xe3a0000a); add r0, r0, #32 (0xe2800020)
        let mut arm = UnicornBackend::new(Arch::Arm32, ArmMode::Arm32).unwrap();
        let base = 0x10000u64;
        arm.mem_map(base, 0x1000, MemoryPerm::ALL).unwrap();
        let mut code = Vec::new();
        code.extend_from_slice(&0xe3a0000au32.to_le_bytes());
        code.extend_from_slice(&0xe2800020u32.to_le_bytes());
        arm.mem_write(base, &code).unwrap();
        arm.emu_start(base, base + code.len() as u64, 0, 0).unwrap();
        assert_eq!(arm.reg_read(ArmReg::R0 as u32).unwrap(), 42);

        // Thumb mode: movs r0, #10 (0x200a); adds r0, #32 (0x3020)
        let mut thumb = UnicornBackend::new(Arch::Arm32, ArmMode::Thumb).unwrap();
        thumb.mem_map(base, 0x1000, MemoryPerm::ALL).unwrap();
        let mut tcode = Vec::new();
        tcode.extend_from_slice(&0x200au16.to_le_bytes());
        tcode.extend_from_slice(&0x3020u16.to_le_bytes());
        thumb.mem_write(base, &tcode).unwrap();
        thumb
            .emu_start(base | 1, base + tcode.len() as u64, 0, 0)
            .unwrap();
        assert_eq!(thumb.reg_read(ArmReg::R0 as u32).unwrap(), 42);
    }
}
