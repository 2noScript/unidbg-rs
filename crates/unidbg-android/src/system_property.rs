use std::collections::HashMap;
use unidbg_api::arm::backend::{Arm64Reg, ArmReg, Backend};
use unidbg_api::arm::Arch;
use unidbg_api::error::Result;
use unidbg_api::memory::MemoryManager;
use unidbg_api::pointer::UnidbgPointer;
use unidbg_api::svc::{Svc, SvcResult};

/// Provides Android system properties (`__system_property_get` / `find` / `read`).
#[derive(Clone)]
pub struct SystemPropertyProvider {
    props: HashMap<String, String>,
}

impl SystemPropertyProvider {
    pub fn with_defaults(sdk: u32) -> Self {
        let mut props = HashMap::new();
        props.insert("ro.build.version.sdk".into(), sdk.to_string());
        props.insert("ro.build.version.release".into(), "6.0.1".into());
        props.insert("ro.product.model".into(), "Pixel".into());
        props.insert("ro.product.brand".into(), "google".into());
        props.insert("ro.product.manufacturer".into(), "Google".into());
        Self { props }
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.props.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.props.get(key).map(|s| s.as_str())
    }
}

pub struct SystemPropertyGetSvc {
    arch: Arch,
    provider: SystemPropertyProvider,
}

impl SystemPropertyGetSvc {
    pub fn new(arch: Arch, provider: SystemPropertyProvider) -> Self {
        Self { arch, provider }
    }
}

impl Svc for SystemPropertyGetSvc {
    fn name(&self) -> &str {
        "__system_property_get"
    }

    fn handle(&mut self, backend: &mut dyn Backend, _memory: &mut MemoryManager) -> Result<SvcResult> {
        let ptr_sz = if self.arch == Arch::Arm64 { 8 } else { 4 };
        let (key_addr, val_addr) = match self.arch {
            Arch::Arm64 => (
                backend.reg_read(Arm64Reg::X0 as u32)?,
                backend.reg_read(Arm64Reg::X1 as u32)?,
            ),
            Arch::Arm32 => (
                backend.reg_read(ArmReg::R0 as u32)?,
                backend.reg_read(ArmReg::R1 as u32)?,
            ),
        };
        let key = UnidbgPointer::new(key_addr, ptr_sz).read_cstr(backend)?;
        let len = if let Some(val) = self.provider.get(&key) {
            UnidbgPointer::new(val_addr, ptr_sz).write_cstr(backend, val)?;
            val.len() as u64
        } else {
            UnidbgPointer::new(val_addr, ptr_sz).write_u8(backend, 0)?;
            0
        };
        Ok(SvcResult::Return(len))
    }
}
