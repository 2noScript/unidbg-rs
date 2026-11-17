use crate::arm::backend::{Arm64Reg, ArmReg, Backend};
use crate::error::Result;
use crate::memory::Memory;
use crate::pointer::UnidbgPointer;

/// Architecture-neutral register context for reading call arguments and core registers.
pub trait RegisterContext {
    fn pc(&self) -> Result<u64>;
    fn lr(&self) -> Result<u64>;
    fn sp(&self) -> Result<u64>;
    fn int_arg(&self, index: usize) -> Result<i32>;
    fn long_arg(&self, index: usize) -> Result<i64>;
    fn u64_arg(&self, index: usize) -> Result<u64>;
    fn ptr_arg(&self, memory: &dyn Memory, index: usize) -> Result<UnidbgPointer>;
    fn reg_read(&self, reg: u32) -> Result<u64>;
    fn reg_write(&mut self, reg: u32, val: u64) -> Result<()>;
}

/// AAPCS32 register context backed by a [`Backend`].
pub struct Arm32Context<'a> {
    backend: &'a mut dyn Backend,
}

impl<'a> Arm32Context<'a> {
    pub fn new(backend: &'a mut dyn Backend) -> Self {
        Self { backend }
    }

    pub fn cpsr(&self) -> Result<u32> {
        Ok(self.backend.reg_read(ArmReg::CPSR as u32)? as u32)
    }

    pub fn is_thumb(&self) -> Result<bool> {
        Ok((self.cpsr()? & (1 << 5)) != 0)
    }
}

impl RegisterContext for Arm32Context<'_> {
    fn pc(&self) -> Result<u64> {
        self.backend.reg_read(ArmReg::PC as u32)
    }

    fn lr(&self) -> Result<u64> {
        self.backend.reg_read(ArmReg::LR as u32)
    }

    fn sp(&self) -> Result<u64> {
        self.backend.reg_read(ArmReg::SP as u32)
    }

    fn int_arg(&self, index: usize) -> Result<i32> {
        Ok(self.u64_arg(index)? as u32 as i32)
    }

    fn long_arg(&self, index: usize) -> Result<i64> {
        let lo = self.u64_arg(index)? as u32 as u64;
        let hi = self.u64_arg(index + 1)? as u32 as u64;
        Ok(((hi << 32) | lo) as i64)
    }

    fn u64_arg(&self, index: usize) -> Result<u64> {
        const REGS: [ArmReg; 4] = [ArmReg::R0, ArmReg::R1, ArmReg::R2, ArmReg::R3];
        if index < REGS.len() {
            self.backend.reg_read(REGS[index] as u32)
        } else {
            let sp = self.sp()?;
            let mut buf = [0u8; 4];
            self.backend.mem_read(sp + ((index - 4) as u64) * 4, &mut buf)?;
            Ok(u32::from_le_bytes(buf) as u64)
        }
    }

    fn ptr_arg(&self, memory: &dyn Memory, index: usize) -> Result<UnidbgPointer> {
        Ok(memory.pointer(self.u64_arg(index)?))
    }

    fn reg_read(&self, reg: u32) -> Result<u64> {
        self.backend.reg_read(reg)
    }

    fn reg_write(&mut self, reg: u32, val: u64) -> Result<()> {
        self.backend.reg_write(reg, val)
    }
}

/// AAPCS64 register context backed by a [`Backend`].
pub struct Arm64Context<'a> {
    backend: &'a mut dyn Backend,
}

impl<'a> Arm64Context<'a> {
    pub fn new(backend: &'a mut dyn Backend) -> Self {
        Self { backend }
    }

    pub fn nzcv(&self) -> Result<u64> {
        self.backend.reg_read(Arm64Reg::NZCV as u32)
    }
}

impl RegisterContext for Arm64Context<'_> {
    fn pc(&self) -> Result<u64> {
        self.backend.reg_read(Arm64Reg::PC as u32)
    }

    fn lr(&self) -> Result<u64> {
        self.backend.reg_read(Arm64Reg::X30 as u32)
    }

    fn sp(&self) -> Result<u64> {
        self.backend.reg_read(Arm64Reg::SP as u32)
    }

    fn int_arg(&self, index: usize) -> Result<i32> {
        Ok(self.u64_arg(index)? as u32 as i32)
    }

    fn long_arg(&self, index: usize) -> Result<i64> {
        Ok(self.u64_arg(index)? as i64)
    }

    fn u64_arg(&self, index: usize) -> Result<u64> {
        const REGS: [Arm64Reg; 8] = [
            Arm64Reg::X0,
            Arm64Reg::X1,
            Arm64Reg::X2,
            Arm64Reg::X3,
            Arm64Reg::X4,
            Arm64Reg::X5,
            Arm64Reg::X6,
            Arm64Reg::X7,
        ];
        if index < REGS.len() {
            self.backend.reg_read(REGS[index] as u32)
        } else {
            let sp = self.sp()?;
            let mut buf = [0u8; 8];
            self.backend.mem_read(sp + ((index - 8) as u64) * 8, &mut buf)?;
            Ok(u64::from_le_bytes(buf))
        }
    }

    fn ptr_arg(&self, memory: &dyn Memory, index: usize) -> Result<UnidbgPointer> {
        Ok(memory.pointer(self.u64_arg(index)?))
    }

    fn reg_read(&self, reg: u32) -> Result<u64> {
        self.backend.reg_read(reg)
    }

    fn reg_write(&mut self, reg: u32, val: u64) -> Result<()> {
        self.backend.reg_write(reg, val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arm::backend::tests::MockBackend;

    #[test]
    fn arm64_and_arm32_register_contexts_read_reg_and_stack_args() {
        let mut b = MockBackend::new();
        b.mem_map(0x1000, 0x1000, crate::arm::backend::MemoryPerm::READ | crate::arm::backend::MemoryPerm::WRITE).unwrap();
        b.reg_write(Arm64Reg::SP as u32, 0x1000).unwrap();
        b.reg_write(Arm64Reg::X0 as u32, 11).unwrap();
        b.reg_write(Arm64Reg::X7 as u32, 88).unwrap();
        b.mem_write(0x1000, &99u64.to_le_bytes()).unwrap();

        let ctx64 = Arm64Context::new(&mut b);
        assert_eq!(ctx64.int_arg(0).unwrap(), 11);
        assert_eq!(ctx64.int_arg(7).unwrap(), 88);
        assert_eq!(ctx64.long_arg(8).unwrap(), 99);

        b.reg_write(ArmReg::SP as u32, 0x1020).unwrap();
        b.reg_write(ArmReg::R0 as u32, 0x1122_3344).unwrap();
        b.reg_write(ArmReg::R1 as u32, 0x5566_7788).unwrap();
        b.mem_write(0x1020, &77u32.to_le_bytes()).unwrap();
        let ctx32 = Arm32Context::new(&mut b);
        assert_eq!(ctx32.int_arg(0).unwrap(), 0x1122_3344);
        assert_eq!(ctx32.long_arg(0).unwrap(), 0x5566_7788_1122_3344);
        assert_eq!(ctx32.int_arg(4).unwrap(), 77);
    }
}
