use unidbg_api::arm::backend::{
    Backend, BackendContext, CodeHookFn, HookId, IntrHookFn, MemHookFn, MemoryPerm,
};
use unidbg_api::error::{Result, UnidbgError};

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
/// Linux ARM64 KVM backend (`KvmBackend`).
/// Requires Linux on AArch64 with `/dev/kvm` access.
pub struct KvmBackend;

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
impl KvmBackend {
    pub fn new() -> Result<Self> {
        Err(UnidbgError::Backend(
            "KvmBackend is only supported on Linux AArch64".into(),
        ))
    }

    fn unavail(&self) -> UnidbgError {
        UnidbgError::Backend("KvmBackend is only supported on Linux AArch64".into())
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
impl Backend for KvmBackend {
    fn reg_read(&self, _reg: u32) -> Result<u64> { Err(self.unavail()) }
    fn reg_write(&mut self, _reg: u32, _value: u64) -> Result<()> { Err(self.unavail()) }
    fn reg_read_vec(&self, _reg: u32) -> Result<u128> { Err(self.unavail()) }
    fn reg_write_vec(&mut self, _reg: u32, _value: u128) -> Result<()> { Err(self.unavail()) }
    fn mem_read(&self, _addr: u64, _buf: &mut [u8]) -> Result<()> { Err(self.unavail()) }
    fn mem_write(&mut self, _addr: u64, _data: &[u8]) -> Result<()> { Err(self.unavail()) }
    fn mem_map(&mut self, _addr: u64, _size: usize, _perm: MemoryPerm) -> Result<()> { Err(self.unavail()) }
    fn mem_unmap(&mut self, _addr: u64, _size: usize) -> Result<()> { Err(self.unavail()) }
    fn mem_protect(&mut self, _addr: u64, _size: usize, _perm: MemoryPerm) -> Result<()> { Err(self.unavail()) }
    fn emu_start(&mut self, _begin: u64, _until: u64, _timeout: u64, _count: usize) -> Result<()> { Err(self.unavail()) }
    fn emu_stop(&mut self) -> Result<()> { Err(self.unavail()) }
    fn context_alloc(&self) -> Result<Box<dyn BackendContext>> { Err(self.unavail()) }
    fn context_save(&self, _ctx: &mut dyn BackendContext) -> Result<()> { Err(self.unavail()) }
    fn context_restore(&mut self, _ctx: &dyn BackendContext) -> Result<()> { Err(self.unavail()) }
    fn hook_add_code(&mut self, _begin: u64, _end: u64, _cb: CodeHookFn) -> Result<HookId> { Err(self.unavail()) }
    fn hook_add_mem(&mut self, _begin: u64, _end: u64, _cb: MemHookFn) -> Result<HookId> { Err(self.unavail()) }
    fn hook_add_intr(&mut self, _cb: IntrHookFn) -> Result<HookId> { Err(self.unavail()) }
    fn hook_del(&mut self, _id: HookId) -> Result<()> { Err(self.unavail()) }
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod linux_arm64 {
    use super::*;
    use unidbg_api::arm::backend::Arm64Reg;
    use std::any::Any;
    use std::collections::HashMap;
    use std::ffi::CString;

    // KVM ioctl numbers for Linux aarch64
    const KVMIO: libc::c_ulong = 0xAE;
    const fn iowr(nr: u32, size: usize) -> libc::c_ulong {
        ((3 as libc::c_ulong) << 30) | ((size as libc::c_ulong) << 16) | (KVMIO << 8) | (nr as libc::c_ulong)
    }
    const fn iow(nr: u32, size: usize) -> libc::c_ulong {
        ((1 as libc::c_ulong) << 30) | ((size as libc::c_ulong) << 16) | (KVMIO << 8) | (nr as libc::c_ulong)
    }
    const fn ior(nr: u32, size: usize) -> libc::c_ulong {
        ((2 as libc::c_ulong) << 30) | ((size as libc::c_ulong) << 16) | (KVMIO << 8) | (nr as libc::c_ulong)
    }
    const fn io(nr: u32) -> libc::c_ulong {
        (KVMIO << 8) | (nr as libc::c_ulong)
    }

    const KVM_CREATE_VM: libc::c_ulong = io(0x01);
    const KVM_GET_VCPU_MMAP_SIZE: libc::c_ulong = io(0x04);
    const KVM_CREATE_VCPU: libc::c_ulong = io(0x41);
    const KVM_SET_USER_MEMORY_REGION: libc::c_ulong = iow(0x46, std::mem::size_of::<KvmUserspaceMemoryRegion>());
    const KVM_RUN: libc::c_ulong = io(0x80);
    const KVM_SET_GUEST_DEBUG: libc::c_ulong = iow(0x9b, std::mem::size_of::<KvmGuestDebug>());
    const KVM_GET_ONE_REG: libc::c_ulong = iow(0xab, std::mem::size_of::<KvmOneReg>());
    const KVM_SET_ONE_REG: libc::c_ulong = iow(0xac, std::mem::size_of::<KvmOneReg>());
    const KVM_ARM_VCPU_INIT: libc::c_ulong = iow(0xae, std::mem::size_of::<KvmVcpuInit>());
    const KVM_ARM_PREFERRED_TARGET: libc::c_ulong = ior(0xaf, std::mem::size_of::<KvmVcpuInit>());

    const KVM_GUESTDBG_ENABLE: u32 = 0x0000_0001;
    const KVM_GUESTDBG_USE_SW_BP: u32 = 0x0001_0000;
    const KVM_EXIT_DEBUG: u32 = 4;
    const KVM_EXIT_MMIO: u32 = 6;
    const KVM_EXIT_HLT: u32 = 5;

    // ARM64 ONE_REG IDs: KVM_REG_ARM64 (0x6000_0000_0000_0000) | KVM_REG_SIZE_U64 (0x0030_0000_0000_0000) | KVM_REG_ARM_CORE (0x0010_0000)
    const KVM_REG_ARM64_CORE_U64: u64 = 0x6030_0000_0010_0000;
    const KVM_REG_ARM64_SIMD_U128: u64 = 0x6040_0000_0010_0000;

    #[repr(C)]
    struct KvmUserspaceMemoryRegion {
        slot: u32,
        flags: u32,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct KvmVcpuInit {
        target: u32,
        features: [u32; 7],
    }

    #[repr(C)]
    struct KvmOneReg {
        id: u64,
        addr: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct KvmGuestDebug {
        control: u32,
        pad: u32,
        arch: KvmGuestDebugArch,
    }

    #[repr(C)]
    #[derive(Default)]
    struct KvmGuestDebugArch {
        dbg_bcr: [u64; 16],
        dbg_bvr: [u64; 16],
        dbg_wcr: [u64; 16],
        dbg_wvr: [u64; 16],
    }

    #[repr(C)]
    struct KvmRunHeader {
        request_interrupt_window: u8,
        immediate_exit: u8,
        padding1: [u8; 6],
        exit_reason: u32,
        ready_for_interrupt_injection: u8,
        if_flag: u8,
        flags: u16,
        cr8: u64,
        apic_base: u64,
    }

    struct MemSlot {
        slot: u32,
        guest_addr: u64,
        size: usize,
        host_ptr: *mut u8,
        perm: MemoryPerm,
    }

    pub struct KvmContext {
        regs: [u64; 34], // X0..X30, SP, PC, PSTATE
    }

    impl BackendContext for KvmContext {
        fn as_any(&self) -> &dyn Any { self }
        fn as_any_mut(&mut self) -> &mut dyn Any { self }
    }

    /// Linux ARM64 KVM backend (`KvmBackend`).
    pub struct KvmBackend {
        kvm_fd: libc::c_int,
        vm_fd: libc::c_int,
        vcpu_fd: libc::c_int,
        kvm_run: *mut u8,
        kvm_run_size: usize,
        slots: Vec<MemSlot>,
        next_slot: u32,
        stopped: bool,
        intr_hooks: HashMap<u64, IntrHookFn>,
        next_hook_id: u64,
    }

    impl KvmBackend {
        pub fn new() -> Result<Self> {
            unsafe {
                let path = CString::new("/dev/kvm").unwrap();
                let kvm_fd = libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
                if kvm_fd < 0 {
                    return Err(UnidbgError::Backend("failed to open /dev/kvm".into()));
                }
                let vm_fd = libc::ioctl(kvm_fd, KVM_CREATE_VM, 0 as libc::c_ulong);
                if vm_fd < 0 {
                    libc::close(kvm_fd);
                    return Err(UnidbgError::Backend("KVM_CREATE_VM failed".into()));
                }
                let vcpu_fd = libc::ioctl(vm_fd, KVM_CREATE_VCPU, 0 as libc::c_ulong);
                if vcpu_fd < 0 {
                    libc::close(vm_fd);
                    libc::close(kvm_fd);
                    return Err(UnidbgError::Backend("KVM_CREATE_VCPU failed".into()));
                }

                let mut vcpu_init = KvmVcpuInit::default();
                if libc::ioctl(vm_fd, KVM_ARM_PREFERRED_TARGET, &mut vcpu_init) < 0 {
                    libc::close(vcpu_fd);
                    libc::close(vm_fd);
                    libc::close(kvm_fd);
                    return Err(UnidbgError::Backend("KVM_ARM_PREFERRED_TARGET failed".into()));
                }
                if libc::ioctl(vcpu_fd, KVM_ARM_VCPU_INIT, &vcpu_init) < 0 {
                    libc::close(vcpu_fd);
                    libc::close(vm_fd);
                    libc::close(kvm_fd);
                    return Err(UnidbgError::Backend("KVM_ARM_VCPU_INIT failed".into()));
                }

                let mmap_sz = libc::ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0 as libc::c_ulong);
                if mmap_sz <= 0 {
                    libc::close(vcpu_fd);
                    libc::close(vm_fd);
                    libc::close(kvm_fd);
                    return Err(UnidbgError::Backend("KVM_GET_VCPU_MMAP_SIZE failed".into()));
                }
                let kvm_run = libc::mmap(
                    std::ptr::null_mut(),
                    mmap_sz as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    vcpu_fd,
                    0,
                );
                if kvm_run == libc::MAP_FAILED {
                    libc::close(vcpu_fd);
                    libc::close(vm_fd);
                    libc::close(kvm_fd);
                    return Err(UnidbgError::Backend("mmap kvm_run failed".into()));
                }

                let dbg = KvmGuestDebug {
                    control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP,
                    ..Default::default()
                };
                let _ = libc::ioctl(vcpu_fd, KVM_SET_GUEST_DEBUG, &dbg);

                Ok(Self {
                    kvm_fd,
                    vm_fd,
                    vcpu_fd,
                    kvm_run: kvm_run as *mut u8,
                    kvm_run_size: mmap_sz as usize,
                    slots: Vec::new(),
                    next_slot: 0,
                    stopped: false,
                    intr_hooks: HashMap::new(),
                    next_hook_id: 1,
                })
            }
        }

        fn reg_id(reg: u32) -> Result<u64> {
            // Index in user_pt_regs (each u64 = 2 u32 words in KVM_REG_ARM_CORE)
            let word_idx: u64 = if reg == Arm64Reg::X0 as u32 {
                0
            } else if (Arm64Reg::X1 as u32..=Arm64Reg::X28 as u32).contains(&reg) {
                (1 + (reg - Arm64Reg::X1 as u32)) as u64
            } else if reg == Arm64Reg::X29 as u32 {
                29
            } else if reg == Arm64Reg::X30 as u32 {
                30
            } else if reg == Arm64Reg::SP as u32 {
                31
            } else if reg == Arm64Reg::PC as u32 {
                32
            } else if reg == Arm64Reg::NZCV as u32 {
                33
            } else {
                return Err(UnidbgError::Backend(format!("unsupported KVM ARM64 reg {reg}")));
            };
            Ok(KVM_REG_ARM64_CORE_U64 | (word_idx * 2))
        }

        fn find_slot(&self, addr: u64, len: usize) -> Result<*mut u8> {
            for s in &self.slots {
                let end = s.guest_addr.saturating_add(s.size as u64);
                if addr >= s.guest_addr && addr.saturating_add(len as u64) <= end {
                    let off = (addr - s.guest_addr) as usize;
                    return Ok(unsafe { s.host_ptr.add(off) });
                }
            }
            Err(UnidbgError::InvalidMemoryAccess {
                addr,
                size: len,
                reason: "unmapped KVM guest memory".into(),
            })
        }
    }

    impl Drop for KvmBackend {
        fn drop(&mut self) {
            unsafe {
                if !self.kvm_run.is_null() {
                    libc::munmap(self.kvm_run as *mut libc::c_void, self.kvm_run_size);
                }
                for s in &self.slots {
                    let region = KvmUserspaceMemoryRegion {
                        slot: s.slot,
                        flags: 0,
                        guest_phys_addr: s.guest_addr,
                        memory_size: 0,
                        userspace_addr: 0,
                    };
                    let _ = libc::ioctl(self.vm_fd, KVM_SET_USER_MEMORY_REGION, &region);
                    libc::munmap(s.host_ptr as *mut libc::c_void, s.size);
                }
                libc::close(self.vcpu_fd);
                libc::close(self.vm_fd);
                libc::close(self.kvm_fd);
            }
        }
    }

    impl Backend for KvmBackend {
        fn reg_read(&self, reg: u32) -> Result<u64> {
            let mut val = 0u64;
            let one = KvmOneReg {
                id: Self::reg_id(reg)?,
                addr: (&mut val as *mut u64) as u64,
            };
            let rc = unsafe { libc::ioctl(self.vcpu_fd, KVM_GET_ONE_REG, &one) };
            if rc < 0 {
                return Err(UnidbgError::Backend("KVM_GET_ONE_REG failed".into()));
            }
            Ok(val)
        }

        fn reg_write(&mut self, reg: u32, value: u64) -> Result<()> {
            let one = KvmOneReg {
                id: Self::reg_id(reg)?,
                addr: (&value as *const u64) as u64,
            };
            let rc = unsafe { libc::ioctl(self.vcpu_fd, KVM_SET_ONE_REG, &one) };
            if rc < 0 {
                return Err(UnidbgError::Backend("KVM_SET_ONE_REG failed".into()));
            }
            Ok(())
        }

        fn reg_read_vec(&self, reg: u32) -> Result<u128> {
            let mut val = 0u128;
            let idx = reg.saturating_sub(Arm64Reg::Q0 as u32) as u64;
            // user_fpsimd_state.vregs starts at offset 34 * 2 u32 words = 68
            let one = KvmOneReg {
                id: KVM_REG_ARM64_SIMD_U128 | (68 + idx * 4),
                addr: (&mut val as *mut u128) as u64,
            };
            let rc = unsafe { libc::ioctl(self.vcpu_fd, KVM_GET_ONE_REG, &one) };
            if rc < 0 {
                return Err(UnidbgError::Backend("KVM_GET_ONE_REG SIMD failed".into()));
            }
            Ok(val)
        }

        fn reg_write_vec(&mut self, reg: u32, value: u128) -> Result<()> {
            let idx = reg.saturating_sub(Arm64Reg::Q0 as u32) as u64;
            let one = KvmOneReg {
                id: KVM_REG_ARM64_SIMD_U128 | (68 + idx * 4),
                addr: (&value as *const u128) as u64,
            };
            let rc = unsafe { libc::ioctl(self.vcpu_fd, KVM_SET_ONE_REG, &one) };
            if rc < 0 {
                return Err(UnidbgError::Backend("KVM_SET_ONE_REG SIMD failed".into()));
            }
            Ok(())
        }

        fn mem_read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let ptr = self.find_slot(addr, buf.len())?;
            unsafe {
                std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), buf.len());
            }
            Ok(())
        }

        fn mem_write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
            let ptr = self.find_slot(addr, data.len())?;
            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
            }
            Ok(())
        }

        fn mem_map(&mut self, addr: u64, size: usize, perm: MemoryPerm) -> Result<()> {
            let host_ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if host_ptr == libc::MAP_FAILED {
                return Err(UnidbgError::Backend("KVM host mmap failed".into()));
            }
            let slot = self.next_slot;
            self.next_slot += 1;
            let region = KvmUserspaceMemoryRegion {
                slot,
                flags: 0,
                guest_phys_addr: addr,
                memory_size: size as u64,
                userspace_addr: host_ptr as u64,
            };
            let rc = unsafe { libc::ioctl(self.vm_fd, KVM_SET_USER_MEMORY_REGION, &region) };
            if rc < 0 {
                unsafe { libc::munmap(host_ptr, size) };
                return Err(UnidbgError::Backend("KVM_SET_USER_MEMORY_REGION failed".into()));
            }
            self.slots.push(MemSlot {
                slot,
                guest_addr: addr,
                size,
                host_ptr: host_ptr as *mut u8,
                perm,
            });
            Ok(())
        }

        fn mem_unmap(&mut self, addr: u64, size: usize) -> Result<()> {
            if let Some(pos) = self.slots.iter().position(|s| s.guest_addr == addr && s.size == size) {
                let s = self.slots.remove(pos);
                let region = KvmUserspaceMemoryRegion {
                    slot: s.slot,
                    flags: 0,
                    guest_phys_addr: s.guest_addr,
                    memory_size: 0,
                    userspace_addr: 0,
                };
                unsafe {
                    let _ = libc::ioctl(self.vm_fd, KVM_SET_USER_MEMORY_REGION, &region);
                    libc::munmap(s.host_ptr as *mut libc::c_void, s.size);
                }
            }
            Ok(())
        }

        fn mem_protect(&mut self, addr: u64, size: usize, perm: MemoryPerm) -> Result<()> {
            if let Some(s) = self.slots.iter_mut().find(|s| s.guest_addr == addr && s.size == size) {
                s.perm = perm;
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
                let rc = unsafe { libc::ioctl(self.vcpu_fd, KVM_RUN, 0 as libc::c_ulong) };
                if rc < 0 {
                    return Err(UnidbgError::Backend("KVM_RUN failed".into()));
                }
                let reason = unsafe { (*(self.kvm_run as *const KvmRunHeader)).exit_reason };
                match reason {
                    KVM_EXIT_DEBUG | KVM_EXIT_HLT => break,
                    KVM_EXIT_MMIO => {
                        return Err(UnidbgError::Backend("unexpected KVM_EXIT_MMIO".into()));
                    }
                    other => {
                        return Err(UnidbgError::Backend(format!("KVM exit reason {other}")));
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
            Ok(Box::new(KvmContext { regs: [0; 34] }))
        }

        fn context_save(&self, ctx: &mut dyn BackendContext) -> Result<()> {
            let c = ctx
                .as_any_mut()
                .downcast_mut::<KvmContext>()
                .ok_or_else(|| UnidbgError::Backend("invalid KvmContext".into()))?;
            for (i, slot) in c.regs.iter_mut().enumerate() {
                let id = KVM_REG_ARM64_CORE_U64 | ((i as u64) * 2);
                let one = KvmOneReg {
                    id,
                    addr: (slot as *mut u64) as u64,
                };
                let _ = unsafe { libc::ioctl(self.vcpu_fd, KVM_GET_ONE_REG, &one) };
            }
            Ok(())
        }

        fn context_restore(&mut self, ctx: &dyn BackendContext) -> Result<()> {
            let c = ctx
                .as_any()
                .downcast_ref::<KvmContext>()
                .ok_or_else(|| UnidbgError::Backend("invalid KvmContext".into()))?;
            for (i, &val) in c.regs.iter().enumerate() {
                let id = KVM_REG_ARM64_CORE_U64 | ((i as u64) * 2);
                let one = KvmOneReg {
                    id,
                    addr: (&val as *const u64) as u64,
                };
                let _ = unsafe { libc::ioctl(self.vcpu_fd, KVM_SET_ONE_REG, &one) };
            }
            Ok(())
        }

        fn hook_add_code(&mut self, _begin: u64, _end: u64, _cb: CodeHookFn) -> Result<HookId> {
            Err(UnidbgError::Backend("code hooks are not supported on KVM".into()))
        }

        fn hook_add_mem(&mut self, _begin: u64, _end: u64, _cb: MemHookFn) -> Result<HookId> {
            Err(UnidbgError::Backend("mem hooks are not supported on KVM".into()))
        }

        fn hook_add_intr(&mut self, cb: IntrHookFn) -> Result<HookId> {
            let id = self.next_hook_id;
            self.next_hook_id += 1;
            self.intr_hooks.insert(id, cb);
            Ok(HookId(id))
        }

        fn hook_del(&mut self, id: HookId) -> Result<()> {
            self.intr_hooks.remove(&id.0);
            Ok(())
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use linux_arm64::KvmBackend;
