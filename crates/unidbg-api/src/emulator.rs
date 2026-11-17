use crate::arm::backend::{Arm64Reg, ArmReg, Backend, HookId, MemoryPerm};
use crate::arm::svc::ArmSvcMemory;
use crate::arm::{Arch, ArmMode};
use crate::error::{Result, UnidbgError};
use crate::memory::{Memory, MemoryManager};
use crate::spi::SyscallHandler;
use crate::svc::{Svc, SvcResult};
use crate::thread::UniThreadDispatcher;
use crate::trace::{AssemblyCodeDumper, TraceMemoryHook};
use std::cell::Cell;
use std::rc::Rc;

/// Target OS / ABI family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    Android32,
    Android64,
    Ios32,
    Ios64,
}

impl Family {
    pub fn arch(self) -> Arch {
        match self {
            Family::Android32 | Family::Ios32 => Arch::Arm32,
            Family::Android64 | Family::Ios64 => Arch::Arm64,
        }
    }
}

/// Core emulator interface (combines `Emulator` and `AbstractEmulator`).
pub trait Emulator {
    fn arch(&self) -> Arch;
    fn family(&self) -> Family;
    fn pid(&self) -> u32;
    fn name(&self) -> &str;
    fn memory(&self) -> &MemoryManager;
    fn memory_mut(&mut self) -> &mut MemoryManager;
    fn backend(&self) -> &dyn Backend;
    fn backend_mut(&mut self) -> &mut dyn Backend;
    fn emulate(&mut self, begin: u64, until: u64) -> Result<u64>;
}

/// Shared emulator runtime state (no `UnsafeCell`, clean ownership).
pub struct EmulatorCore {
    arch: Arch,
    mode: ArmMode,
    family: Family,
    pid: u32,
    name: String,
    backend: Box<dyn Backend>,
    memory: MemoryManager,
    svc_memory: ArmSvcMemory,
    thread_dispatcher: UniThreadDispatcher,
    syscall_handler: Option<Box<dyn SyscallHandler>>,
    pending_intr: Rc<Cell<Option<u32>>>,
    intr_hook: Option<HookId>,
}

impl EmulatorCore {
    pub fn new(
        family: Family,
        mode: ArmMode,
        name: impl Into<String>,
        mut backend: Box<dyn Backend>,
    ) -> Result<Self> {
        let arch = family.arch();
        let mut memory = MemoryManager::new(arch);
        memory.allocate_stack(backend.as_mut(), 0x10000)?;

        let pending_intr = Rc::new(Cell::new(None));
        let intr_flag = pending_intr.clone();
        let intr_hook = backend.hook_add_intr(Box::new(move |intno| {
            intr_flag.set(Some(intno));
            false // stop emu_start cleanly so EmulatorCore can handle SVC with &mut self
        }))?;

        Ok(Self {
            arch,
            mode,
            family,
            pid: 1000,
            name: name.into(),
            backend,
            memory,
            svc_memory: ArmSvcMemory::new(arch, mode),
            thread_dispatcher: UniThreadDispatcher::new(),
            syscall_handler: None,
            pending_intr,
            intr_hook: Some(intr_hook),
        })
    }

    pub fn set_syscall_handler(&mut self, handler: Box<dyn SyscallHandler>) {
        self.syscall_handler = Some(handler);
    }

    pub fn register_svc(&mut self, svc: Box<dyn Svc>) -> Result<u64> {
        self.svc_memory
            .register_svc(self.backend.as_mut(), &mut self.memory, svc)
    }

    pub fn parts_mut(&mut self) -> (&mut dyn Backend, &mut MemoryManager) {
        (self.backend.as_mut(), &mut self.memory)
    }

    pub fn mmap(&mut self, start: u64, length: usize, perm: MemoryPerm) -> Result<u64> {
        self.memory.mmap(self.backend.as_mut(), start, length, perm)
    }

    pub fn munmap(&mut self, start: u64, length: usize) -> Result<()> {
        self.memory.munmap(self.backend.as_mut(), start, length)
    }

    pub fn mprotect(&mut self, start: u64, length: usize, perm: MemoryPerm) -> Result<()> {
        self.memory.mprotect(self.backend.as_mut(), start, length, perm)
    }

    pub fn thread_dispatcher(&mut self) -> &mut UniThreadDispatcher {
        &mut self.thread_dispatcher
    }

    pub fn trace_code(&mut self, begin: u64, end: u64) -> Result<(HookId, Rc<AssemblyCodeDumper>)> {
        let dumper = Rc::new(AssemblyCodeDumper::new(self.mode)?);
        let d = dumper.clone();
        // Note: code hook logs instruction address & size; full bytes can be read via backend
        let hook_id = self.backend.hook_add_code(
            begin,
            end,
            Box::new(move |addr, size| {
                let _ = d.record(&[], addr);
                tracing::trace!(pc = format_args!("{addr:#x}"), size, "exec");
            }),
        )?;
        Ok((hook_id, dumper))
    }

    pub fn trace_memory(&mut self, begin: u64, end: u64) -> Result<(HookId, TraceMemoryHook)> {
        let tracer = TraceMemoryHook::new(begin, end);
        let t = tracer.clone();
        let hook_id = self.backend.hook_add_mem(
            begin,
            end,
            Box::new(move |access, addr, size, value| {
                t.on_access(access, addr, size, value);
                true
            }),
        )?;
        Ok((hook_id, tracer))
    }

    fn pc_reg(&self) -> u32 {
        match self.arch {
            Arch::Arm32 => ArmReg::PC as u32,
            Arch::Arm64 => Arm64Reg::PC as u32,
        }
    }

    fn ret_reg(&self) -> u32 {
        match self.arch {
            Arch::Arm32 => ArmReg::R0 as u32,
            Arch::Arm64 => Arm64Reg::X0 as u32,
        }
    }

    fn read_svc_imm(&self, pc_after_svc: u64) -> Result<u32> {
        match self.arch {
            Arch::Arm64 => {
                let mut buf = [0u8; 4];
                self.backend.mem_read(pc_after_svc - 4, &mut buf)?;
                let insn = u32::from_le_bytes(buf);
                Ok((insn >> 5) & 0xffff)
            }
            Arch::Arm32 => {
                let mut buf = [0u8; 4];
                if self.mode == ArmMode::Thumb {
                    self.backend.mem_read(pc_after_svc - 2, &mut buf[..2])?;
                    let insn = u16::from_le_bytes([buf[0], buf[1]]);
                    Ok((insn & 0xff) as u32)
                } else {
                    self.backend.mem_read(pc_after_svc - 4, &mut buf)?;
                    let insn = u32::from_le_bytes(buf);
                    Ok(insn & 0x00ff_ffff)
                }
            }
        }
    }
}

impl Drop for EmulatorCore {
    fn drop(&mut self) {
        if let Some(id) = self.intr_hook.take() {
            let _ = self.backend.hook_del(id);
        }
    }
}

impl Emulator for EmulatorCore {
    fn arch(&self) -> Arch {
        self.arch
    }

    fn family(&self) -> Family {
        self.family
    }

    fn pid(&self) -> u32 {
        self.pid
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn memory(&self) -> &MemoryManager {
        &self.memory
    }

    fn memory_mut(&mut self) -> &mut MemoryManager {
        &mut self.memory
    }

    fn backend(&self) -> &dyn Backend {
        self.backend.as_ref()
    }

    fn backend_mut(&mut self) -> &mut dyn Backend {
        self.backend.as_mut()
    }

    fn emulate(&mut self, begin: u64, until: u64) -> Result<u64> {
        let mut pc = begin;
        loop {
            self.pending_intr.set(None);
            self.backend.emu_start(pc, until, 0, 0)?;

            if let Some(intno) = self.pending_intr.take() {
                let cur_pc = self.backend.reg_read(self.pc_reg())?;
                // ARM/ARM64 EXCP_SWI = 2 in QEMU/Unicorn
                if intno == 2 {
                    let imm = self.read_svc_imm(cur_pc)?;
                    if let Some(res) =
                        self.svc_memory
                            .dispatch(imm, self.backend.as_mut(), &mut self.memory)?
                    {
                        if let SvcResult::Stop(code) = res {
                            return Err(UnidbgError::StopEmulator(code));
                        }
                    } else if let Some(handler) = self.syscall_handler.as_mut() {
                        handler.handle(self.backend.as_mut(), &mut self.memory)?;
                    } else {
                        return Err(UnidbgError::UnhandledSyscall(imm as u64));
                    }
                    pc = if self.arch == Arch::Arm32 && self.mode == ArmMode::Thumb {
                        cur_pc | 1
                    } else {
                        cur_pc
                    };
                    if cur_pc == until {
                        break;
                    }
                    continue;
                }
                return Err(UnidbgError::Backend(format!("unhandled interrupt {intno} at {cur_pc:#x}")));
            }
            break;
        }
        self.backend.reg_read(self.ret_reg())
    }
}
