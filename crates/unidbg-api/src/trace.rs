use crate::arm::backend::MemAccessType;
use crate::arm::ArmMode;
use crate::error::{Result, UnidbgError};
use capstone::prelude::*;
use std::cell::RefCell;
use std::rc::Rc;

/// Disassembles executed instructions using Capstone (replaces `AssemblyCodeDumper`).
pub struct AssemblyCodeDumper {
    cs: Capstone,
    records: Rc<RefCell<Vec<String>>>,
}

impl AssemblyCodeDumper {
    pub fn new(mode: ArmMode) -> Result<Self> {
        let cs = match mode {
            ArmMode::Arm64 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .build(),
            ArmMode::Arm32 => Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .build(),
            ArmMode::Thumb => Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Thumb)
                .build(),
        }
        .map_err(|e| UnidbgError::Backend(format!("capstone init failed: {e}")))?;

        Ok(Self {
            cs,
            records: Rc::new(RefCell::new(Vec::new())),
        })
    }

    pub fn disassemble(&self, code: &[u8], addr: u64) -> Result<Vec<String>> {
        let insns = self
            .cs
            .disasm_all(code, addr)
            .map_err(|e| UnidbgError::Backend(format!("capstone disasm failed: {e}")))?;
        let mut out = Vec::with_capacity(insns.len());
        for insn in insns.as_ref() {
            let line = format!(
                "[{:#010x}] {:<8} {}",
                insn.address(),
                insn.mnemonic().unwrap_or(""),
                insn.op_str().unwrap_or("")
            );
            out.push(line);
        }
        Ok(out)
    }

    pub fn record(&self, code: &[u8], addr: u64) -> Result<()> {
        let lines = self.disassemble(code, addr)?;
        let mut rec = self.records.borrow_mut();
        for line in lines {
            tracing::trace!("{line}");
            rec.push(line);
        }
        Ok(())
    }

    pub fn records(&self) -> Vec<String> {
        self.records.borrow().clone()
    }
}

/// Recorded memory access event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryAccessRecord {
    pub access: MemAccessType,
    pub addr: u64,
    pub size: usize,
    pub value: i64,
}

/// Filters and records memory read/write accesses within `[begin, end]`.
#[derive(Clone)]
pub struct TraceMemoryHook {
    begin: u64,
    end: u64,
    records: Rc<RefCell<Vec<MemoryAccessRecord>>>,
}

impl TraceMemoryHook {
    pub fn new(begin: u64, end: u64) -> Self {
        Self {
            begin,
            end,
            records: Rc::new(RefCell::new(Vec::new())),
        }
    }

    pub fn on_access(&self, access: MemAccessType, addr: u64, size: usize, value: i64) {
        if addr >= self.begin && addr <= self.end {
            tracing::trace!(?access, addr = format_args!("{addr:#x}"), size, value, "mem");
            self.records.borrow_mut().push(MemoryAccessRecord {
                access,
                addr,
                size,
                value,
            });
        }
    }

    pub fn records(&self) -> Vec<MemoryAccessRecord> {
        self.records.borrow().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capstone_disassembles_arm64_instructions() {
        let dumper = AssemblyCodeDumper::new(ArmMode::Arm64).unwrap();
        let mut code = Vec::new();
        // mov x0, #10 ; add x0, x0, #32
        code.extend_from_slice(&0xd2800140u32.to_le_bytes());
        code.extend_from_slice(&0x91008000u32.to_le_bytes());

        dumper.record(&code, 0x10000).unwrap();
        let recs = dumper.records();
        assert_eq!(recs.len(), 2);
        assert!(recs[0].contains("mov") && recs[0].contains("x0"));
        assert!(recs[1].contains("add") && recs[1].contains("x0"));
    }

    #[test]
    fn trace_memory_hook_filters_range() {
        let hook = TraceMemoryHook::new(0x2000, 0x20ff);
        hook.on_access(MemAccessType::Write, 0x1000, 4, 1);
        hook.on_access(MemAccessType::Write, 0x2010, 4, 42);
        let recs = hook.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].addr, 0x2010);
        assert_eq!(recs[0].value, 42);
    }
}
