use crate::arm::backend::{Arm64Reg, ArmReg, Backend};
use crate::arm::Arch;
use crate::error::Result;
use crate::pointer::UnidbgPointer;

/// A single stack frame produced by [`Unwinder::unwind`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub pc: u64,
    pub fp: u64,
    pub module: Option<String>,
    pub symbol: Option<String>,
    pub demangled: Option<String>,
    pub offset: u64,
}

/// Stack unwinder interface (`Unwinder`).
pub trait Unwinder {
    fn unwind(&self, backend: &dyn Backend, max_frames: usize) -> Result<Vec<Frame>>;
}

/// Frame-pointer (`X29`/`R11`) stack unwinder (`SimpleARMUnwinder` / `SimpleARM64Unwinder`).
pub struct SimpleArmUnwinder {
    arch: Arch,
}

impl SimpleArmUnwinder {
    pub fn new(arch: Arch) -> Self {
        Self { arch }
    }
}

impl Unwinder for SimpleArmUnwinder {
    fn unwind(&self, backend: &dyn Backend, max_frames: usize) -> Result<Vec<Frame>> {
        let mut frames = Vec::new();
        let (pc_reg, fp_reg, ptr_sz) = match self.arch {
            Arch::Arm64 => (Arm64Reg::PC as u32, Arm64Reg::X29 as u32, 8usize),
            Arch::Arm32 => (ArmReg::PC as u32, ArmReg::R11 as u32, 4usize),
        };

        let mut pc = backend.reg_read(pc_reg)?;
        let mut fp = backend.reg_read(fp_reg)?;

        for _ in 0..max_frames {
            frames.push(Frame {
                pc,
                fp,
                module: None,
                symbol: None,
                demangled: None,
                offset: 0,
            });
            if fp == 0 {
                break;
            }
            let fp_ptr = UnidbgPointer::new(fp, ptr_sz);
            let Ok(next_fp) = fp_ptr.read_pointer(backend) else {
                break;
            };
            let Ok(lr) = fp_ptr.share(ptr_sz as i64).read_pointer(backend) else {
                break;
            };
            if lr.addr() == 0 || next_fp.addr() <= fp {
                break;
            }
            fp = next_fp.addr();
            pc = lr.addr();
        }
        Ok(frames)
    }
}
