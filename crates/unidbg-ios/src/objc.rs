use crate::emulator::DarwinEmulator;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use unidbg_api::arm::backend::{Arm64Reg, Backend};
use unidbg_api::error::Result;
use unidbg_api::memory::MemoryManager;
use unidbg_api::pointer::UnidbgPointer;
use unidbg_api::svc::{Svc, SvcResult};

/// Minimal Objective-C runtime stub (`objc_getClass`, `sel_registerName`, `objc_msgSend`).
#[derive(Default)]
pub struct ObjcState {
    next_id: u64,
    classes: HashMap<String, u64>,
    selectors: HashMap<String, u64>,
    class_names: HashMap<u64, String>,
    selector_names: HashMap<u64, String>,
}

impl ObjcState {
    pub fn new() -> Self {
        Self {
            next_id: 0x8000_0001,
            ..Default::default()
        }
    }

    pub fn get_class(&mut self, name: &str) -> u64 {
        if let Some(&id) = self.classes.get(name) {
            return id;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.classes.insert(name.to_string(), id);
        self.class_names.insert(id, name.to_string());
        id
    }

    pub fn register_sel(&mut self, name: &str) -> u64 {
        if let Some(&id) = self.selectors.get(name) {
            return id;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.selectors.insert(name.to_string(), id);
        self.selector_names.insert(id, name.to_string());
        id
    }
}

pub struct ObjcRuntime {
    pub state: Rc<RefCell<ObjcState>>,
    pub objc_get_class_addr: u64,
    pub sel_register_name_addr: u64,
    pub objc_msg_send_addr: u64,
}

impl ObjcRuntime {
    pub fn init(emu: &mut DarwinEmulator) -> Result<Self> {
        let state = Rc::new(RefCell::new(ObjcState::new()));
        let objc_get_class_addr = emu
            .core_mut()
            .register_svc(Box::new(ObjcGetClassSvc(state.clone())))?;
        let sel_register_name_addr = emu
            .core_mut()
            .register_svc(Box::new(SelRegisterNameSvc(state.clone())))?;
        let objc_msg_send_addr = emu
            .core_mut()
            .register_svc(Box::new(ObjcMsgSendSvc(state.clone())))?;
        Ok(Self {
            state,
            objc_get_class_addr,
            sel_register_name_addr,
            objc_msg_send_addr,
        })
    }
}

struct ObjcGetClassSvc(Rc<RefCell<ObjcState>>);
impl Svc for ObjcGetClassSvc {
    fn name(&self) -> &str {
        "objc_getClass"
    }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let name_addr = backend.reg_read(Arm64Reg::X0 as u32)?;
        let name = UnidbgPointer::new(name_addr, 8).read_cstr(backend)?;
        let id = self.0.borrow_mut().get_class(&name);
        Ok(SvcResult::Return(id))
    }
}

struct SelRegisterNameSvc(Rc<RefCell<ObjcState>>);
impl Svc for SelRegisterNameSvc {
    fn name(&self) -> &str {
        "sel_registerName"
    }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let name_addr = backend.reg_read(Arm64Reg::X0 as u32)?;
        let name = UnidbgPointer::new(name_addr, 8).read_cstr(backend)?;
        let id = self.0.borrow_mut().register_sel(&name);
        Ok(SvcResult::Return(id))
    }
}

struct ObjcMsgSendSvc(Rc<RefCell<ObjcState>>);
impl Svc for ObjcMsgSendSvc {
    fn name(&self) -> &str {
        "objc_msgSend"
    }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let target = backend.reg_read(Arm64Reg::X0 as u32)?;
        let sel = backend.reg_read(Arm64Reg::X1 as u32)?;
        let st = self.0.borrow();
        let cname = st.class_names.get(&target).map(|s| s.as_str()).unwrap_or("<obj>");
        let sname = st.selector_names.get(&sel).map(|s| s.as_str()).unwrap_or("<sel>");
        tracing::debug!(cname, sname, "objc_msgSend");
        Ok(SvcResult::Return(target))
    }
}
