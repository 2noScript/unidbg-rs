use crate::emulator::AndroidEmulator;
use unidbg_api::arm::backend::{Arm64Reg, ArmReg, Backend};
use unidbg_api::arm::Arch;
use unidbg_api::error::Result;
use unidbg_api::memory::MemoryManager;
use unidbg_api::svc::{Svc, SvcResult};

struct VirtualStubSvc(&'static str, u64);

impl Svc for VirtualStubSvc {
    fn name(&self) -> &str {
        self.0
    }

    fn handle(&mut self, _: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        Ok(SvcResult::Return(self.1))
    }
}

/// Registers virtual `libandroid.so` (`AAssetManager_*`) symbols.
pub struct AndroidModule;

impl AndroidModule {
    pub fn register(emu: &mut AndroidEmulator) -> Result<()> {
        let syms: [(&'static str, u64); 5] = [
            ("AAssetManager_fromJava", 0x1000),
            ("AAssetManager_open", 0x1001),
            ("AAsset_read", 0),
            ("AAsset_getLength", 0),
            ("AAsset_close", 0),
        ];
        for (name, ret) in syms {
            let addr = emu.core_mut().register_svc(Box::new(VirtualStubSvc(name, ret)))?;
            emu.loader().borrow_mut().register_hook_symbol(name, addr);
        }
        Ok(())
    }
}

/// Registers virtual `libjnigraphics.so` (`AndroidBitmap_*`) symbols.
pub struct JniGraphics;

impl JniGraphics {
    pub fn register(emu: &mut AndroidEmulator) -> Result<()> {
        let syms: [(&'static str, u64); 3] = [
            ("AndroidBitmap_getInfo", 0),
            ("AndroidBitmap_lockPixels", 0),
            ("AndroidBitmap_unlockPixels", 0),
        ];
        for (name, ret) in syms {
            let addr = emu.core_mut().register_svc(Box::new(VirtualStubSvc(name, ret)))?;
            emu.loader().borrow_mut().register_hook_symbol(name, addr);
        }
        Ok(())
    }
}

/// Registers virtual `libmediandk.so` symbols (`MediaNdkModule`).
pub struct MediaNdkModule;

impl MediaNdkModule {
    pub fn register(emu: &mut AndroidEmulator) -> Result<()> {
        let syms: [(&'static str, u64); 3] = [
            ("AMediaDrm_createByUUID", 0x2000),
            ("AMediaDrm_getPropertyByteArray", 0),
            ("AMediaDrm_release", 0),
        ];
        for (name, ret) in syms {
            let addr = emu.core_mut().register_svc(Box::new(VirtualStubSvc(name, ret)))?;
            emu.loader().borrow_mut().register_hook_symbol(name, addr);
        }
        Ok(())
    }
}

/// Registers `SystemProperties` (`__system_property_find` / `read`) virtual symbols.
pub struct SystemProperties;

impl SystemProperties {
    pub fn register(emu: &mut AndroidEmulator) -> Result<()> {
        let arch = if emu.loader().borrow().find_symbol("dlsym").is_some() {
            Arch::Arm64
        } else {
            Arch::Arm64
        };
        let _ = arch;
        let find_addr = emu
            .core_mut()
            .register_svc(Box::new(VirtualStubSvc("__system_property_find", 0)))?;
        let read_addr = emu
            .core_mut()
            .register_svc(Box::new(VirtualStubSvc("__system_property_read", 0)))?;
        let mut l = emu.loader().borrow_mut();
        l.register_hook_symbol("__system_property_find", find_addr);
        l.register_hook_symbol("__system_property_read", read_addr);
        let _ = (Arm64Reg::X0, ArmReg::R0);
        Ok(())
    }
}
