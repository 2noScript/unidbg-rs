#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod darwin_arm64 {
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::ptr;
    use unidbg_api::arm::backend::{
        Arm64Reg, Backend, BackendContext, CodeHookFn, HookId, IntrHookFn, MemHookFn, MemoryPerm,
    };
    use unidbg_api::error::{Result, UnidbgError};

    type HvReturn = i32;
    type HvVcpu = u64;
    const HV_SUCCESS: HvReturn = 0;

    const HV_MEMORY_READ: u64 = 1 << 0;
    const HV_MEMORY_WRITE: u64 = 1 << 1;
    const HV_MEMORY_EXEC: u64 = 1 << 2;

    const HV_EXIT_REASON_EXCEPTION: u32 = 1;

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    struct HvVcpuExitException {
        syndrome: u64,
        virtual_address: u64,
        physical_address: u64,
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    struct HvVcpuExit {
        reason: u32,
        exception: HvVcpuExitException,
    }

    #[link(name = "Hypervisor", kind = "framework")]
    extern "C" {
        fn hv_vm_create(config: *mut c_void) -> HvReturn;
        fn hv_vm_destroy() -> HvReturn;
        fn hv_vm_map(addr: *mut c_void, ipa: u64, size: usize, flags: u64) -> HvReturn;
        fn hv_vm_unmap(ipa: u64, size: usize) -> HvReturn;
        fn hv_vm_protect(ipa: u64, size: usize, flags: u64) -> HvReturn;
        fn hv_vcpu_create(
            vcpu: *mut HvVcpu,
            exit: *mut *const HvVcpuExit,
            config: *mut c_void,
        ) -> HvReturn;
        fn hv_vcpu_destroy(vcpu: HvVcpu) -> HvReturn;
        fn hv_vcpu_run(vcpu: HvVcpu) -> HvReturn;
        fn hv_vcpu_get_reg(vcpu: HvVcpu, reg: u32, value: *mut u64) -> HvReturn;
        fn hv_vcpu_set_reg(vcpu: HvVcpu, reg: u32, value: u64) -> HvReturn;
        fn hv_vcpu_set_trap_debug_exceptions(vcpu: HvVcpu, value: bool) -> HvReturn;
    }

    fn hv_reg(reg: u32) -> Result<u32> {
        match reg {
            x if x == Arm64Reg::X0 as u32 => Ok(0),
            x if x == Arm64Reg::X1 as u32 => Ok(1),
            x if x == Arm64Reg::X2 as u32 => Ok(2),
            x if x == Arm64Reg::X3 as u32 => Ok(3),
            x if x == Arm64Reg::X4 as u32 => Ok(4),
            x if x == Arm64Reg::X5 as u32 => Ok(5),
            x if x == Arm64Reg::X6 as u32 => Ok(6),
            x if x == Arm64Reg::X7 as u32 => Ok(7),
            x if x == Arm64Reg::X8 as u32 => Ok(8),
            x if x == Arm64Reg::X9 as u32 => Ok(9),
            x if x == Arm64Reg::X10 as u32 => Ok(10),
            x if x == Arm64Reg::X11 as u32 => Ok(11),
            x if x == Arm64Reg::X12 as u32 => Ok(12),
            x if x == Arm64Reg::X13 as u32 => Ok(13),
            x if x == Arm64Reg::X14 as u32 => Ok(14),
            x if x == Arm64Reg::X15 as u32 => Ok(15),
            x if x == Arm64Reg::X16 as u32 => Ok(16),
            x if x == Arm64Reg::X17 as u32 => Ok(17),
            x if x == Arm64Reg::X18 as u32 => Ok(18),
            x if x == Arm64Reg::X19 as u32 => Ok(19),
            x if x == Arm64Reg::X20 as u32 => Ok(20),
            x if x == Arm64Reg::X21 as u32 => Ok(21),
            x if x == Arm64Reg::X22 as u32 => Ok(22),
            x if x == Arm64Reg::X23 as u32 => Ok(23),
            x if x == Arm64Reg::X24 as u32 => Ok(24),
            x if x == Arm64Reg::X25 as u32 => Ok(25),
            x if x == Arm64Reg::X26 as u32 => Ok(26),
            x if x == Arm64Reg::X27 as u32 => Ok(27),
            x if x == Arm64Reg::X28 as u32 => Ok(28),
            x if x == Arm64Reg::X29 as u32 => Ok(29),
            x if x == Arm64Reg::X30 as u32 => Ok(30),
            x if x == Arm64Reg::PC as u32 => Ok(31),
            x if x == Arm64Reg::NZCV as u32 => Ok(34), // HV_REG_CPSR
            _ => Err(UnidbgError::Backend(format!("unsupported HV reg {reg}"))),
        }
    }

    fn hv_flags(perm: MemoryPerm) -> u64 {
        let mut f = 0u64;
        if perm.contains(MemoryPerm::READ) {
            f |= HV_MEMORY_READ;
        }
        if perm.contains(MemoryPerm::WRITE) {
            f |= HV_MEMORY_WRITE;
        }
        if perm.contains(MemoryPerm::EXEC) {
            f |= HV_MEMORY_EXEC;
        }
        f
    }

    struct HvContext([u64; 32]);
    impl BackendContext for HvContext {
        fn as_any(&self) -> &dyn std::any::Any { self }
        fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    }

    struct AlignedPage {
        ptr: *mut u8,
        layout: std::alloc::Layout,
    }

    impl AlignedPage {
        fn new(size: usize) -> Result<Self> {
            let aligned_sz = (size + 0x3fff) & !0x3fff;
            let layout = std::alloc::Layout::from_size_align(aligned_sz.max(0x4000), 0x4000)
                .map_err(|e| UnidbgError::Backend(format!("layout: {e}")))?;
            let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
            if ptr.is_null() {
                return Err(UnidbgError::Backend("oom".into()));
            }
            Ok(Self { ptr, layout })
        }

        fn as_slice(&self) -> &[u8] {
            unsafe { std::slice::from_raw_parts(self.ptr, self.layout.size()) }
        }

        fn as_mut_slice(&mut self) -> &mut [u8] {
            unsafe { std::slice::from_raw_parts_mut(self.ptr, self.layout.size()) }
        }
    }

    impl Drop for AlignedPage {
        fn drop(&mut self) {
            unsafe { std::alloc::dealloc(self.ptr, self.layout) };
        }
    }

    /// Apple Silicon `Hypervisor.framework` ARM64 backend (`HypervisorBackend`).
    pub struct HypervisorBackend {
        vcpu: HvVcpu,
        exit: *const HvVcpuExit,
        mappings: HashMap<u64, AlignedPage>,
        intr_hook: Option<IntrHookFn>,
        stopped: bool,
    }

    impl HypervisorBackend {
        pub fn new() -> Result<Self> {
            let ret = unsafe { hv_vm_create(ptr::null_mut()) };
            if ret != HV_SUCCESS {
                return Err(UnidbgError::Backend(format!(
                    "hv_vm_create failed: {ret:#x} (requires com.apple.security.hypervisor entitlement)"
                )));
            }
            let mut vcpu: HvVcpu = 0;
            let mut exit: *const HvVcpuExit = ptr::null();
            let ret = unsafe { hv_vcpu_create(&mut vcpu, &mut exit, ptr::null_mut()) };
            if ret != HV_SUCCESS {
                unsafe { hv_vm_destroy() };
                return Err(UnidbgError::Backend(format!("hv_vcpu_create failed: {ret:#x}")));
            }
            unsafe {
                let _ = hv_vcpu_set_trap_debug_exceptions(vcpu, true);
            }
            Ok(Self {
                vcpu,
                exit,
                mappings: HashMap::new(),
                intr_hook: None,
                stopped: false,
            })
        }
    }

    impl Drop for HypervisorBackend {
        fn drop(&mut self) {
            unsafe {
                let _ = hv_vcpu_destroy(self.vcpu);
                let _ = hv_vm_destroy();
            }
        }
    }

    impl Backend for HypervisorBackend {
        fn reg_read(&self, reg: u32) -> Result<u64> {
            let r = hv_reg(reg)?;
            let mut val = 0u64;
            let ret = unsafe { hv_vcpu_get_reg(self.vcpu, r, &mut val) };
            if ret != HV_SUCCESS {
                return Err(UnidbgError::Backend(format!("hv_vcpu_get_reg failed: {ret:#x}")));
            }
            Ok(val)
        }

        fn reg_write(&mut self, reg: u32, value: u64) -> Result<()> {
            let r = hv_reg(reg)?;
            let ret = unsafe { hv_vcpu_set_reg(self.vcpu, r, value) };
            if ret != HV_SUCCESS {
                return Err(UnidbgError::Backend(format!("hv_vcpu_set_reg failed: {ret:#x}")));
            }
            Ok(())
        }

        fn reg_read_vec(&self, _reg: u32) -> Result<u128> { Ok(0) }
        fn reg_write_vec(&mut self, _reg: u32, _value: u128) -> Result<()> { Ok(()) }

        fn mem_read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            for (base, page) in &self.mappings {
                let s = page.as_slice();
                if addr >= *base && addr + buf.len() as u64 <= *base + s.len() as u64 {
                    let off = (addr - *base) as usize;
                    buf.copy_from_slice(&s[off..off + buf.len()]);
                    return Ok(());
                }
            }
            Err(UnidbgError::InvalidMemoryAccess {
                addr,
                size: buf.len(),
                perm: MemoryPerm::READ,
            })
        }

        fn mem_write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
            for (base, page) in &mut self.mappings {
                let s = page.as_mut_slice();
                if addr >= *base && addr + data.len() as u64 <= *base + s.len() as u64 {
                    let off = (addr - *base) as usize;
                    s[off..off + data.len()].copy_from_slice(data);
                    return Ok(());
                }
            }
            Err(UnidbgError::InvalidMemoryAccess {
                addr,
                size: data.len(),
                perm: MemoryPerm::WRITE,
            })
        }

        fn mem_map(&mut self, addr: u64, size: usize, perm: MemoryPerm) -> Result<()> {
            let backing = AlignedPage::new(size)?;
            let map_sz = backing.as_slice().len();
            let ret = unsafe { hv_vm_map(backing.ptr.cast(), addr, map_sz, hv_flags(perm)) };
            if ret != HV_SUCCESS {
                return Err(UnidbgError::Backend(format!("hv_vm_map failed: {ret:#x}")));
            }
            self.mappings.insert(addr, backing);
            Ok(())
        }

        fn mem_unmap(&mut self, addr: u64, size: usize) -> Result<()> {
            let ret = unsafe { hv_vm_unmap(addr, size) };
            if ret != HV_SUCCESS {
                return Err(UnidbgError::Backend(format!("hv_vm_unmap failed: {ret:#x}")));
            }
            self.mappings.remove(&addr);
            Ok(())
        }

        fn mem_protect(&mut self, addr: u64, size: usize, perm: MemoryPerm) -> Result<()> {
            let ret = unsafe { hv_vm_protect(addr, size, hv_flags(perm)) };
            if ret != HV_SUCCESS {
                return Err(UnidbgError::Backend(format!("hv_vm_protect failed: {ret:#x}")));
            }
            Ok(())
        }

        fn emu_start(&mut self, begin: u64, until: u64, _timeout: u64, _count: usize) -> Result<()> {
            self.stopped = false;
            self.reg_write(Arm64Reg::PC as u32, begin)?;
            loop {
                if self.stopped {
                    break;
                }
                let pc = self.reg_read(Arm64Reg::PC as u32)?;
                if until != 0 && pc == until {
                    break;
                }
                let ret = unsafe { hv_vcpu_run(self.vcpu) };
                if ret != HV_SUCCESS {
                    return Err(UnidbgError::Backend(format!("hv_vcpu_run failed: {ret:#x}")));
                }
                let exit = unsafe { &*self.exit };
                if exit.reason == HV_EXIT_REASON_EXCEPTION {
                    let ec = (exit.exception.syndrome >> 26) & 0x3f;
                    // EC = 0x15 (SVC64), EC = 0x3C (BRK64)
                    if ec == 0x15 {
                        if let Some(cb) = self.intr_hook.as_mut() {
                            if !cb(2) {
                                break;
                            }
                        }
                    } else if ec == 0x3c {
                        break;
                    } else {
                        return Err(UnidbgError::Backend(format!(
                            "hv exception EC={ec:#x} syndrome={:#x}",
                            exit.exception.syndrome
                        )));
                    }
                }
            }
            Ok(())
        }

        fn emu_stop(&mut self) -> Result<()> {
            self.stopped = true;
            Ok(())
        }

        fn context_alloc(&self) -> Result<Box<dyn BackendContext>> {
            Ok(Box::new(HvContext([0u64; 32])))
        }

        fn context_save(&self, ctx: &mut dyn BackendContext) -> Result<()> {
            let c = ctx.as_any_mut().downcast_mut::<HvContext>().unwrap();
            for i in 0..32u32 {
                let mut v = 0;
                unsafe { hv_vcpu_get_reg(self.vcpu, i, &mut v) };
                c.0[i as usize] = v;
            }
            Ok(())
        }

        fn context_restore(&mut self, ctx: &dyn BackendContext) -> Result<()> {
            let c = ctx.as_any().downcast_ref::<HvContext>().unwrap();
            for i in 0..32u32 {
                unsafe { hv_vcpu_set_reg(self.vcpu, i, c.0[i as usize]) };
            }
            Ok(())
        }

        fn hook_add_code(&mut self, _: u64, _: u64, _: CodeHookFn) -> Result<HookId> {
            Ok(HookId(1))
        }
        fn hook_add_mem(&mut self, _: u64, _: u64, _: MemHookFn) -> Result<HookId> {
            Ok(HookId(2))
        }
        fn hook_add_intr(&mut self, cb: IntrHookFn) -> Result<HookId> {
            self.intr_hook = Some(cb);
            Ok(HookId(3))
        }
        fn hook_del(&mut self, _: HookId) -> Result<()> {
            Ok(())
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use darwin_arm64::HypervisorBackend;
