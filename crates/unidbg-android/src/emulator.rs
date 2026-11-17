use crate::elf_loader::{AndroidElfLoader, ElfLibraryFile};
use crate::fs::LinuxFileSystem;
use crate::ld::{CallocSvc, DlOpenSvc, DlSymSvc, FreeSvc, MallocSvc, ReallocSvc};
use crate::module::LinuxModule;
use crate::resolver::AndroidResolver;
use crate::syscall::{AndroidSyscallHandler, ClonedThread};
use crate::system_property::{SystemPropertyGetSvc, SystemPropertyProvider};
use std::cell::RefCell;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use unidbg_api::arm::backend::{Arm64Reg, ArmReg, Backend, MemoryPerm};
use unidbg_api::arm::{Arch, ArmMode};
use unidbg_api::emulator::{Emulator, EmulatorCore, Family};
use unidbg_api::error::Result;
use unidbg_api::spi::LibraryFile;

/// High-level Android emulator (`AndroidEmulator` + `AndroidEmulatorBuilder`).
pub struct AndroidEmulator {
    core: EmulatorCore,
    loader: Rc<RefCell<AndroidElfLoader>>,
    fs: Rc<RefCell<LinuxFileSystem>>,
    resolver: Option<AndroidResolver>,
    lr_stop_addr: u64,
    initialized_modules: HashSet<String>,
    pending_threads: Rc<RefCell<Vec<ClonedThread>>>,
    in_spawned_thread: Rc<RefCell<bool>>,
}

impl AndroidEmulator {
    pub fn builder(arch: Arch) -> AndroidEmulatorBuilder {
        AndroidEmulatorBuilder::new(arch)
    }

    pub fn from_parts(
        arch: Arch,
        proc_name: impl Into<String>,
        root_dir: Option<PathBuf>,
        resolver: Option<AndroidResolver>,
        backend: Box<dyn Backend>,
        sys_props: SystemPropertyProvider,
    ) -> Result<Self> {
        let name = proc_name.into();
        let family = match arch {
            Arch::Arm32 => Family::Android32,
            Arch::Arm64 => Family::Android64,
        };
        let mode = match arch {
            Arch::Arm32 => ArmMode::Arm32,
            Arch::Arm64 => ArmMode::Arm64,
        };
        let mut core = EmulatorCore::new(family, mode, name.clone(), backend)?;
        let fs = Rc::new(RefCell::new(LinuxFileSystem::new(root_dir, name.clone())));
        let pending_threads = Rc::new(RefCell::new(Vec::new()));
        let in_spawned_thread = Rc::new(RefCell::new(false));
        let syscall_handler = AndroidSyscallHandler::with_thread_state(
            arch,
            fs.clone(),
            core.pid(),
            pending_threads.clone(),
            in_spawned_thread.clone(),
        );
        core.set_syscall_handler(Box::new(syscall_handler));

        let loader = Rc::new(RefCell::new(AndroidElfLoader::new(arch)));

        // Register virtual linker & system property SVC hooks
        let dlsym_addr = core.register_svc(Box::new(DlSymSvc::new(arch, loader.clone())))?;
        let dlopen_addr = core.register_svc(Box::new(DlOpenSvc::new(arch, loader.clone())))?;
        let prop_get_addr = core.register_svc(Box::new(SystemPropertyGetSvc::new(arch, sys_props)))?;
        let malloc_addr = core.register_svc(Box::new(MallocSvc(arch)))?;
        let calloc_addr = core.register_svc(Box::new(CallocSvc(arch)))?;
        let free_addr = core.register_svc(Box::new(FreeSvc))?;
        let realloc_addr = core.register_svc(Box::new(ReallocSvc(arch)))?;

        {
            let mut l = loader.borrow_mut();
            l.register_hook_symbol("dlsym", dlsym_addr);
            l.register_hook_symbol("dlopen", dlopen_addr);
            l.register_hook_symbol("__system_property_get", prop_get_addr);
            l.register_hook_symbol("malloc", malloc_addr);
            l.register_hook_symbol("calloc", calloc_addr);
            l.register_hook_symbol("free", free_addr);
            l.register_hook_symbol("realloc", realloc_addr);
        }

        // Dedicated LR stop address so `call_function` returns cleanly
        let lr_stop_addr = core.mmap(0, 0x1000, MemoryPerm::READ | MemoryPerm::EXEC)?;

        // Map a 12 KiB TLS + preinit page (bionic libc reads TPIDR_EL0 / C13_C0_3)
        let tls_addr = core.mmap(0, 0x3000, MemoryPerm::READ | MemoryPerm::WRITE)?;
        let tls_base = tls_addr + 0x200;
        let pthread_ptr = tls_base + 0x200;
        let pid = core.pid();

        // Build KernelArgumentBlock for TLS_SLOT_BIONIC_PREINIT:
        // struct KernelArgumentBlock { uintptr_t argc; char** argv; char** envp; ElfW(auxv_t)* auxv; }
        let prog_name_ptr = tls_addr + 0x2000;
        let mut prog_bytes = name.as_bytes().to_vec();
        prog_bytes.push(0);
        core.backend_mut().mem_write(prog_name_ptr, &prog_bytes)?;

        let random_ptr = tls_addr + 0x2200;
        core.backend_mut().mem_write(random_ptr, &[0x11u8; 16])?;

        let argv_ptr = tls_addr + 0x2300;
        let envp_ptr = tls_addr + 0x2380;
        let auxv_ptr = tls_addr + 0x2400;
        let preinit_ptr = tls_addr + 0x2500;
        let aux_entries: [(u64, u64); 7] = [
            (6, 4096),        // AT_PAGESZ
            (25, random_ptr), // AT_RANDOM
            (11, 1000),       // AT_UID
            (12, 1000),       // AT_EUID
            (13, 1000),       // AT_GID
            (14, 1000),       // AT_EGID
            (0, 0),           // AT_NULL
        ];

        match arch {
            Arch::Arm64 => {
                // TLS_SLOT_SELF (0), TLS_SLOT_THREAD_ID (1), TLS_SLOT_BIONIC_PREINIT (3)
                core.backend_mut().mem_write(tls_base, &tls_base.to_le_bytes())?;
                core.backend_mut().mem_write(tls_base + 8, &pthread_ptr.to_le_bytes())?;
                core.backend_mut().mem_write(tls_base + 24, &preinit_ptr.to_le_bytes())?;
                core.backend_mut().mem_write(pthread_ptr + 0x10, &pid.to_le_bytes())?;

                core.backend_mut().mem_write(argv_ptr, &prog_name_ptr.to_le_bytes())?;
                core.backend_mut().mem_write(argv_ptr + 8, &0u64.to_le_bytes())?;
                core.backend_mut().mem_write(envp_ptr, &0u64.to_le_bytes())?;
                for (i, (k, v)) in aux_entries.iter().enumerate() {
                    let off = (i as u64) * 16;
                    core.backend_mut().mem_write(auxv_ptr + off, &k.to_le_bytes())?;
                    core.backend_mut().mem_write(auxv_ptr + off + 8, &v.to_le_bytes())?;
                }
                for (i, w) in [1u64, argv_ptr, envp_ptr, auxv_ptr].iter().enumerate() {
                    core.backend_mut().mem_write(preinit_ptr + (i as u64) * 8, &w.to_le_bytes())?;
                }
                core.backend_mut().reg_write(Arm64Reg::TpidrEl0 as u32, tls_base)?;
            }
            Arch::Arm32 => {
                core.backend_mut().mem_write(tls_base, &(tls_base as u32).to_le_bytes())?;
                core.backend_mut().mem_write(tls_base + 4, &(pthread_ptr as u32).to_le_bytes())?;
                core.backend_mut().mem_write(tls_base + 12, &(preinit_ptr as u32).to_le_bytes())?;
                core.backend_mut().mem_write(pthread_ptr + 0x0c, &pid.to_le_bytes())?;

                core.backend_mut().mem_write(argv_ptr, &(prog_name_ptr as u32).to_le_bytes())?;
                core.backend_mut().mem_write(argv_ptr + 4, &0u32.to_le_bytes())?;
                core.backend_mut().mem_write(envp_ptr, &0u32.to_le_bytes())?;
                for (i, (k, v)) in aux_entries.iter().enumerate() {
                    let off = (i as u64) * 8;
                    core.backend_mut().mem_write(auxv_ptr + off, &(*k as u32).to_le_bytes())?;
                    core.backend_mut().mem_write(auxv_ptr + off + 4, &(*v as u32).to_le_bytes())?;
                }
                for (i, w) in [1u32, argv_ptr as u32, envp_ptr as u32, auxv_ptr as u32].iter().enumerate() {
                    core.backend_mut().mem_write(preinit_ptr + (i as u64) * 4, &w.to_le_bytes())?;
                }
                core.backend_mut().reg_write(ArmReg::C13C0_3 as u32, tls_base)?;
            }
        }

        Ok(Self {
            core,
            loader,
            fs,
            resolver,
            lr_stop_addr,
            initialized_modules: HashSet::new(),
            pending_threads,
            in_spawned_thread,
        })
    }

    pub fn load_library(&mut self, path: impl AsRef<Path>, load_needed: bool) -> Result<LinuxModule> {
        let search_dirs = self
            .resolver
            .as_ref()
            .map(|r| r.search_dirs().to_vec())
            .unwrap_or_default();
        let file = ElfLibraryFile::new(path, search_dirs);
        self.load_library_file(&file, load_needed)
    }

    pub fn load_library_file(&mut self, file: &dyn LibraryFile, load_needed: bool) -> Result<LinuxModule> {
        let module = {
            let (backend, memory) = self.core.parts_mut();
            self.loader.borrow_mut().load(file, backend, memory, load_needed)?
        };
        Ok(module)
    }

    pub fn call_init_functions(&mut self, module: &LinuxModule) -> Result<()> {
        if self.core.arch() == Arch::Arm64 {
            let pending: Vec<(String, Vec<u64>)> = {
                let loader = self.loader.borrow();
                loader
                    .modules()
                    .iter()
                    .filter(|m| !self.initialized_modules.contains(&m.name))
                    .map(|m| (m.name.clone(), m.init_functions.clone()))
                    .collect()
            };
            for (name, inits) in pending {
                self.initialized_modules.insert(name);
                for init_addr in inits {
                    if init_addr != 0 {
                        let _ = self.call_function(init_addr, &[])?;
                    }
                }
            }
        }
        if self.initialized_modules.insert(module.name.clone()) {
            for &init_addr in &module.init_functions {
                if init_addr != 0 {
                    let _ = self.call_function(init_addr, &[])?;
                }
            }
        }
        Ok(())
    }

    /// Run all queued threads spawned via `clone` (`pthread_create`).
    pub fn run_threads(&mut self) -> Result<usize> {
        use unidbg_api::error::UnidbgError;
        let arch = self.core.arch();
        let mut ran = 0usize;
        loop {
            let next = {
                let mut q = self.pending_threads.borrow_mut();
                if q.is_empty() {
                    None
                } else {
                    Some(q.remove(0))
                }
            };
            let Some(t) = next else { break };
            ran += 1;

            let stack_base = self.core.mmap(0, 0x20000, MemoryPerm::READ | MemoryPerm::WRITE)?;
            let stack_top = (stack_base + 0x20000) & !0xf;

            let (saved_sp, saved_tls) = match arch {
                Arch::Arm64 => (
                    self.core.backend().reg_read(Arm64Reg::SP as u32)?,
                    self.core.backend().reg_read(Arm64Reg::TpidrEl0 as u32)?,
                ),
                Arch::Arm32 => (
                    self.core.backend().reg_read(ArmReg::SP as u32)?,
                    self.core.backend().reg_read(ArmReg::C13C0_3 as u32)?,
                ),
            };

            *self.in_spawned_thread.borrow_mut() = true;
            let res = match arch {
                Arch::Arm64 => {
                    let tls = if t.tls != 0 { t.tls } else { t.arg + 0xb0 };
                    let b = self.core.backend_mut();
                    b.reg_write(Arm64Reg::X0 as u32, t.arg)?;
                    b.reg_write(Arm64Reg::SP as u32, stack_top)?;
                    b.reg_write(Arm64Reg::TpidrEl0 as u32, tls)?;
                    b.reg_write(Arm64Reg::X30 as u32, self.lr_stop_addr)?;
                    self.core.emulate(t.fn_addr, self.lr_stop_addr)
                }
                Arch::Arm32 => {
                    let tls = if t.tls != 0 { t.tls } else { t.arg + 0x48 };
                    let b = self.core.backend_mut();
                    b.reg_write(ArmReg::R0 as u32, t.arg)?;
                    b.reg_write(ArmReg::SP as u32, stack_top)?;
                    b.reg_write(ArmReg::C13C0_3 as u32, tls)?;
                    b.reg_write(ArmReg::LR as u32, self.lr_stop_addr)?;
                    self.core.emulate(t.fn_addr, self.lr_stop_addr)
                }
            };
            *self.in_spawned_thread.borrow_mut() = false;

            match arch {
                Arch::Arm64 => {
                    let b = self.core.backend_mut();
                    b.reg_write(Arm64Reg::SP as u32, saved_sp)?;
                    b.reg_write(Arm64Reg::TpidrEl0 as u32, saved_tls)?;
                }
                Arch::Arm32 => {
                    let b = self.core.backend_mut();
                    b.reg_write(ArmReg::SP as u32, saved_sp)?;
                    b.reg_write(ArmReg::C13C0_3 as u32, saved_tls)?;
                }
            }

            if t.ctid != 0 {
                let _ = self.core.backend_mut().mem_write(t.ctid, &0u32.to_le_bytes());
            }

            match res {
                Ok(_) | Err(UnidbgError::StopEmulator(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(ran)
    }

    /// Execute an ELF executable (`ET_EXEC` / PIE) from `module.entry_point` with `argc/argv/envp/auxv` on stack.
    pub fn call_entry(&mut self, module: &LinuxModule, args: &[&str]) -> Result<i64> {
        use unidbg_api::error::UnidbgError;
        use unidbg_api::memory::Memory;
        use unidbg_api::pointer::UnidbgPointer;

        if module.entry_point == 0 {
            return Err(UnidbgError::ElfLoad(format!("{} has no entry point", module.name)));
        }

        let arch = self.core.arch();
        let ptr_sz = if arch == Arch::Arm64 { 8usize } else { 4usize };
        let mut sp = self.core.memory().stack_point();

        // Write 16 random bytes for AT_RANDOM
        sp -= 16;
        let at_random_addr = sp;
        self.core
            .backend_mut()
            .mem_write(at_random_addr, &[0x11u8; 16])?;

        // Write argv strings on stack
        let mut argv_ptrs = Vec::with_capacity(args.len());
        for &arg in args {
            let len = arg.len() + 1;
            sp -= len as u64;
            UnidbgPointer::new(sp, ptr_sz).write_cstr(self.core.backend_mut(), arg)?;
            argv_ptrs.push(sp);
        }

        // Align stack to 16 bytes
        sp &= !0xf;

        // Build auxv pairs
        let hwcap: u64 = if arch == Arch::Arm64 { 0xff } else { 0x1fb };
        let auxv: [(u64, u64); 8] = [
            (3, module.phdr_addr),           // AT_PHDR
            (4, module.phentsize as u64),    // AT_PHENT
            (5, module.phnum as u64),        // AT_PHNUM
            (6, 0x1000),                     // AT_PAGESZ
            (9, module.entry_point),         // AT_ENTRY
            (16, hwcap),                     // AT_HWCAP
            (25, at_random_addr),            // AT_RANDOM
            (0, 0),                          // AT_NULL
        ];

        // Compute total words to push so final SP is 16-byte aligned:
        // 1 (argc) + argv_ptrs.len() + 1 (NULL) + 1 (envp NULL) + auxv.len() * 2
        let word_count = 1 + argv_ptrs.len() + 1 + 1 + auxv.len() * 2;
        if (word_count * ptr_sz) % 16 != 0 {
            sp -= ptr_sz as u64;
        }

        let push_word = |backend: &mut dyn Backend, sp: &mut u64, val: u64| -> Result<()> {
            *sp -= ptr_sz as u64;
            UnidbgPointer::new(*sp, ptr_sz).write_pointer(backend, val)
        };

        let b = self.core.backend_mut();
        for &(k, v) in auxv.iter().rev() {
            push_word(b, &mut sp, v)?;
            push_word(b, &mut sp, k)?;
        }
        push_word(b, &mut sp, 0)?; // envp NULL
        push_word(b, &mut sp, 0)?; // argv NULL
        for &p in argv_ptrs.iter().rev() {
            push_word(b, &mut sp, p)?;
        }
        push_word(b, &mut sp, args.len() as u64)?;

        let (backend, memory) = self.core.parts_mut();
        memory.set_stack_point(backend, sp)?;

        match self.core.emulate(module.entry_point, self.lr_stop_addr) {
            Ok(v) => Ok(v as i64),
            Err(UnidbgError::StopEmulator(code)) => Ok(code),
            Err(e) => Err(e),
        }
    }

    pub fn find_symbol(&self, name: &str) -> Option<u64> {
        self.loader.borrow().find_symbol(name)
    }

    /// Call a C function at `addr` with integer/pointer arguments (AAPCS32/64).
    pub fn call_function(&mut self, addr: u64, args: &[u64]) -> Result<u64> {
        let arch = self.core.arch();
        match arch {
            Arch::Arm64 => {
                let regs = [
                    Arm64Reg::X0,
                    Arm64Reg::X1,
                    Arm64Reg::X2,
                    Arm64Reg::X3,
                    Arm64Reg::X4,
                    Arm64Reg::X5,
                    Arm64Reg::X6,
                    Arm64Reg::X7,
                ];
                for (i, &val) in args.iter().take(8).enumerate() {
                    self.core.backend_mut().reg_write(regs[i] as u32, val)?;
                }
                if args.len() > 8 {
                    let sp = self.core.backend().reg_read(Arm64Reg::SP as u32)?;
                    let extra = args.len() - 8;
                    let new_sp = (sp - (extra as u64) * 8) & !0xf;
                    for (i, &val) in args[8..].iter().enumerate() {
                        self.core
                            .backend_mut()
                            .mem_write(new_sp + (i as u64) * 8, &val.to_le_bytes())?;
                    }
                    self.core
                        .backend_mut()
                        .reg_write(Arm64Reg::SP as u32, new_sp)?;
                }
                self.core
                    .backend_mut()
                    .reg_write(Arm64Reg::X30 as u32, self.lr_stop_addr)?;
            }
            Arch::Arm32 => {
                let regs = [ArmReg::R0, ArmReg::R1, ArmReg::R2, ArmReg::R3];
                for (i, &val) in args.iter().take(4).enumerate() {
                    self.core.backend_mut().reg_write(regs[i] as u32, val)?;
                }
                if args.len() > 4 {
                    let sp = self.core.backend().reg_read(ArmReg::SP as u32)?;
                    let extra = args.len() - 4;
                    let new_sp = (sp - (extra as u64) * 4) & !0x7;
                    for (i, &val) in args[4..].iter().enumerate() {
                        self.core
                            .backend_mut()
                            .mem_write(new_sp + (i as u64) * 4, &(val as u32).to_le_bytes())?;
                    }
                    self.core
                        .backend_mut()
                        .reg_write(ArmReg::SP as u32, new_sp)?;
                }
                self.core
                    .backend_mut()
                    .reg_write(ArmReg::LR as u32, self.lr_stop_addr)?;
            }
        }
        self.core.emulate(addr, self.lr_stop_addr)
    }

    pub fn core(&self) -> &EmulatorCore {
        &self.core
    }

    pub fn core_mut(&mut self) -> &mut EmulatorCore {
        &mut self.core
    }

    pub fn fs(&self) -> &Rc<RefCell<LinuxFileSystem>> {
        &self.fs
    }

    pub fn loader(&self) -> &Rc<RefCell<AndroidElfLoader>> {
        &self.loader
    }
}

pub struct AndroidEmulatorBuilder {
    arch: Arch,
    proc_name: String,
    root_dir: Option<PathBuf>,
    resolver: Option<AndroidResolver>,
    sys_props: SystemPropertyProvider,
}

impl AndroidEmulatorBuilder {
    pub fn new(arch: Arch) -> Self {
        Self {
            arch,
            proc_name: "com.example.app".to_string(),
            root_dir: None,
            resolver: None,
            sys_props: SystemPropertyProvider::with_defaults(23),
        }
    }

    pub fn for_32_bit() -> Self {
        Self::new(Arch::Arm32)
    }

    pub fn for_64_bit() -> Self {
        Self::new(Arch::Arm64)
    }

    pub fn process_name(mut self, name: impl Into<String>) -> Self {
        self.proc_name = name.into();
        self
    }

    pub fn root_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.root_dir = Some(dir.into());
        self
    }

    pub fn resolver(mut self, resolver: AndroidResolver) -> Self {
        self.sys_props = SystemPropertyProvider::with_defaults(resolver.sdk());
        self.resolver = Some(resolver);
        self
    }

    pub fn build(self, backend: Box<dyn Backend>) -> Result<AndroidEmulator> {
        AndroidEmulator::from_parts(
            self.arch,
            self.proc_name,
            self.root_dir,
            self.resolver,
            backend,
            self.sys_props,
        )
    }
}
