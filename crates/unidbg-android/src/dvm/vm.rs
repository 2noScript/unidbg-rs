use crate::dvm::jni::{AbstractJni, Jni};
use crate::dvm::objects::{DvmClass, DvmField, DvmMethod, DvmObject, DvmObjectData};
use crate::dvm::var_arg::VaList;
use crate::emulator::AndroidEmulator;
use crate::module::LinuxModule;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use unidbg_api::arm::backend::{Arm64Reg, ArmReg, Backend, MemoryPerm};
use unidbg_api::arm::Arch;
use unidbg_api::emulator::Emulator;
use unidbg_api::error::{Result, UnidbgError};
use unidbg_api::memory::{Memory, MemoryManager};
use unidbg_api::pointer::UnidbgPointer;
use unidbg_api::svc::{Svc, SvcResult};

pub const JNI_OK: i64 = 0;
pub const JNI_ERR: i64 = -1;
pub const JNI_VERSION_1_6: i64 = 0x0001_0006;

const JNI_FLAG_CLASS: i64 = 0x7001_0000;
const JNI_FLAG_OBJECT: i64 = 0x7003_0000;

/// Shared Dalvik/ART VM state accessed by JNI SVC handlers.
pub struct DalvikState {
    pub arch: Arch,
    pub java_vm_ptr: u64,
    pub jni_env_ptr: u64,
    next_class_id: i64,
    next_obj_id: i64,
    next_member_id: i64,
    classes_by_name: HashMap<String, i64>,
    classes_by_handle: HashMap<i64, DvmClass>,
    objects: HashMap<i64, DvmObject>,
    global_refs: HashMap<i64, DvmObject>,
    methods: HashMap<i64, DvmMethod>,
    fields: HashMap<i64, DvmField>,
    pub registered_natives: HashMap<(String, String, String), u64>,
    pub verbose: bool,
}

impl DalvikState {
    pub fn new(arch: Arch) -> Self {
        Self {
            arch,
            java_vm_ptr: 0,
            jni_env_ptr: 0,
            next_class_id: 1,
            next_obj_id: 1,
            next_member_id: 1,
            classes_by_name: HashMap::new(),
            classes_by_handle: HashMap::new(),
            objects: HashMap::new(),
            global_refs: HashMap::new(),
            methods: HashMap::new(),
            fields: HashMap::new(),
            registered_natives: HashMap::new(),
            verbose: false,
        }
    }

    pub fn ptr_size(&self) -> usize {
        if self.arch == Arch::Arm64 { 8 } else { 4 }
    }

    pub fn resolve_class(&mut self, name: &str) -> i64 {
        self.resolve_class_with_super(name, None)
    }

    pub fn resolve_class_with_super(&mut self, name: &str, super_class: Option<i64>) -> i64 {
        if let Some(&h) = self.classes_by_name.get(name) {
            if super_class.is_some() {
                if let Some(c) = self.classes_by_handle.get_mut(&h) {
                    c.super_class = super_class;
                }
            }
            return h;
        }
        let handle = JNI_FLAG_CLASS | self.next_class_id;
        self.next_class_id += 1;
        self.classes_by_name.insert(name.to_string(), handle);
        self.classes_by_handle.insert(
            handle,
            DvmClass {
                handle,
                name: name.to_string(),
                super_class,
                methods: HashMap::new(),
                fields: HashMap::new(),
            },
        );
        handle
    }

    pub fn add_local_object(&mut self, class_name: impl Into<String>, data: DvmObjectData) -> i64 {
        let handle = JNI_FLAG_OBJECT | self.next_obj_id;
        self.next_obj_id += 1;
        self.objects.insert(
            handle,
            DvmObject {
                handle,
                class_name: class_name.into(),
                data,
            },
        );
        handle
    }

    pub fn get_object(&self, handle: i64) -> Option<&DvmObject> {
        self.objects.get(&handle).or_else(|| self.global_refs.get(&handle))
    }

    pub fn get_class(&self, handle: i64) -> Option<&DvmClass> {
        self.classes_by_handle.get(&handle)
    }

    fn arg(&self, backend: &dyn Backend, idx: usize) -> Result<u64> {
        match self.arch {
            Arch::Arm64 => {
                let regs = [
                    Arm64Reg::X0,
                    Arm64Reg::X1,
                    Arm64Reg::X2,
                    Arm64Reg::X3,
                    Arm64Reg::X4,
                    Arm64Reg::X5,
                ];
                backend.reg_read(regs[idx] as u32)
            }
            Arch::Arm32 => {
                let regs = [ArmReg::R0, ArmReg::R1, ArmReg::R2, ArmReg::R3];
                if idx < 4 {
                    backend.reg_read(regs[idx] as u32)
                } else {
                    let sp = backend.reg_read(ArmReg::SP as u32)?;
                    let off = ((idx - 4) * 4) as u64;
                    let mut b = [0u8; 4];
                    backend.mem_read(sp + off, &mut b)?;
                    Ok(u32::from_le_bytes(b) as u64)
                }
            }
        }
    }

    fn reg_jint(val: u64, arch: Arch) -> i64 {
        if arch == Arch::Arm64 {
            val as i32 as i64
        } else {
            val as u32 as i32 as i64
        }
    }
}

/// Dalvik/ART VM facade (`DalvikVM` supporting both 32-bit and 64-bit).
#[derive(Clone)]
pub struct DalvikVM {
    pub state: Rc<RefCell<DalvikState>>,
    pub jni: Rc<RefCell<Box<dyn Jni>>>,
}

impl DalvikVM {
    pub fn init(emu: &mut AndroidEmulator) -> Result<Self> {
        let arch = emu.core().arch();
        let ptr_sz = if arch == Arch::Arm64 { 8usize } else { 4usize };
        let state = Rc::new(RefCell::new(DalvikState::new(arch)));
        let jni: Rc<RefCell<Box<dyn Jni>>> = Rc::new(RefCell::new(Box::new(AbstractJni)));
        let vm = Self {
            state: state.clone(),
            jni: jni.clone(),
        };

        // Allocate JavaVM (8-entry table + pointer) and JNIEnv (233-entry table + pointer)
        let vm_table = emu.core_mut().mmap(0, 0x1000, MemoryPerm::READ | MemoryPerm::WRITE)?;
        let env_table = emu.core_mut().mmap(0, 0x2000, MemoryPerm::READ | MemoryPerm::WRITE)?;

        let java_vm_ptr = vm_table + 0x100;
        let jni_env_ptr = env_table + 0x800;

        {
            let mut s = state.borrow_mut();
            s.java_vm_ptr = java_vm_ptr;
            s.jni_env_ptr = jni_env_ptr;
        }

        let write_ptr = |backend: &mut dyn Backend, addr: u64, val: u64| -> Result<()> {
            if ptr_sz == 8 {
                backend.mem_write(addr, &val.to_le_bytes())
            } else {
                backend.mem_write(addr, &(val as u32).to_le_bytes())
            }
        };

        // *JavaVM = vm_table ; *JNIEnv = env_table
        write_ptr(emu.core_mut().backend_mut(), java_vm_ptr, vm_table)?;
        write_ptr(emu.core_mut().backend_mut(), jni_env_ptr, env_table)?;

        let unimpl = emu.core_mut().register_svc(Box::new(UnimplJniSvc(state.clone())))?;
        for i in 0..8u64 {
            write_ptr(emu.core_mut().backend_mut(), vm_table + i * ptr_sz as u64, unimpl)?;
        }
        for i in 0..233u64 {
            write_ptr(emu.core_mut().backend_mut(), env_table + i * ptr_sz as u64, unimpl)?;
        }

        // JavaVM functions
        let get_env = emu.core_mut().register_svc(Box::new(GetEnvSvc(state.clone())))?;
        let attach = emu.core_mut().register_svc(Box::new(AttachThreadSvc(state.clone())))?;
        let ok_svc = emu.core_mut().register_svc(Box::new(JniConstSvc("JNI_OK", JNI_OK as u64)))?;
        write_ptr(emu.core_mut().backend_mut(), vm_table + 3 * ptr_sz as u64, ok_svc)?; // DestroyJavaVM
        write_ptr(emu.core_mut().backend_mut(), vm_table + 4 * ptr_sz as u64, attach)?; // AttachCurrentThread
        write_ptr(emu.core_mut().backend_mut(), vm_table + 5 * ptr_sz as u64, ok_svc)?; // DetachCurrentThread
        write_ptr(emu.core_mut().backend_mut(), vm_table + 6 * ptr_sz as u64, get_env)?; // GetEnv
        write_ptr(emu.core_mut().backend_mut(), vm_table + 7 * ptr_sz as u64, attach)?; // AttachCurrentThreadAsDaemon

        // Core JNIEnv entries (indices match standard jni.h JNINativeInterface)
        let mut set_env = |idx: u64, svc: Box<dyn Svc>| -> Result<()> {
            let addr = emu.core_mut().register_svc(svc)?;
            write_ptr(emu.core_mut().backend_mut(), env_table + idx * ptr_sz as u64, addr)
        };

        set_env(4, Box::new(JniConstSvc("GetVersion", JNI_VERSION_1_6 as u64)))?;
        set_env(6, Box::new(FindClassSvc(vm.clone())))?;
        set_env(10, Box::new(GetSuperclassSvc(state.clone())))?;
        set_env(17, Box::new(JniZeroSvc("ExceptionClear")))?;
        set_env(19, Box::new(JniConstSvc("PushLocalFrame", JNI_OK as u64)))?;
        set_env(20, Box::new(PopLocalFrameSvc(state.clone())))?;
        set_env(21, Box::new(NewGlobalRefSvc(state.clone())))?;
        set_env(22, Box::new(DeleteGlobalRefSvc(state.clone())))?;
        set_env(23, Box::new(DeleteLocalRefSvc))?;
        set_env(24, Box::new(IsSameObjectSvc(state.clone())))?;
        set_env(26, Box::new(JniConstSvc("EnsureLocalCapacity", JNI_OK as u64)))?;
        set_env(29, Box::new(NewObjectVSvc(vm.clone())))?;
        set_env(31, Box::new(GetObjectClassSvc(state.clone())))?;
        set_env(33, Box::new(GetMethodIDSvc(state.clone())))?;
        set_env(35, Box::new(CallObjectMethodVSvc(vm.clone(), false)))?;
        set_env(38, Box::new(CallBooleanMethodVSvc(vm.clone(), false)))?;
        set_env(50, Box::new(CallIntMethodVSvc(vm.clone(), false)))?;
        set_env(56, Box::new(CallLongMethodVSvc(vm.clone(), false)))?;
        set_env(62, Box::new(CallVoidMethodVSvc(vm.clone(), false)))?;
        set_env(94, Box::new(GetFieldIDSvc(state.clone())))?;
        set_env(95, Box::new(GetObjectFieldSvc(vm.clone(), false)))?;
        set_env(113, Box::new(GetMethodIDSvc(state.clone())))?;
        set_env(115, Box::new(CallObjectMethodVSvc(vm.clone(), true)))?;
        set_env(121, Box::new(CallBooleanMethodVSvc(vm.clone(), true)))?;
        set_env(130, Box::new(CallIntMethodVSvc(vm.clone(), true)))?;
        set_env(136, Box::new(CallLongMethodVSvc(vm.clone(), true)))?;
        set_env(142, Box::new(CallVoidMethodVSvc(vm.clone(), true)))?;
        set_env(144, Box::new(GetFieldIDSvc(state.clone())))?;
        set_env(145, Box::new(GetObjectFieldSvc(vm.clone(), true)))?;
        set_env(167, Box::new(NewStringUtfSvc(state.clone())))?;
        set_env(168, Box::new(GetStringUtfLengthSvc(state.clone())))?;
        set_env(169, Box::new(GetStringUtfCharsSvc(state.clone())))?;
        set_env(170, Box::new(JniZeroSvc("ReleaseStringUTFChars")))?;
        set_env(171, Box::new(GetArrayLengthSvc(state.clone())))?;
        set_env(172, Box::new(NewObjectArraySvc(state.clone())))?;
        set_env(173, Box::new(GetObjectArrayElementSvc(state.clone())))?;
        set_env(174, Box::new(SetObjectArrayElementSvc(state.clone())))?;
        set_env(176, Box::new(NewByteArraySvc(state.clone())))?;
        set_env(184, Box::new(GetByteArrayElementsSvc(state.clone())))?;
        set_env(187, Box::new(GetIntArrayElementsSvc(state.clone())))?;
        set_env(192, Box::new(JniZeroSvc("ReleaseByteArrayElements")))?;
        set_env(195, Box::new(JniZeroSvc("ReleaseIntArrayElements")))?;
        set_env(200, Box::new(GetByteArrayRegionSvc(state.clone())))?;
        set_env(208, Box::new(SetByteArrayRegionSvc(state.clone())))?;
        set_env(215, Box::new(RegisterNativesSvc(state.clone())))?;
        set_env(219, Box::new(GetJavaVmSvc(state.clone())))?;
        set_env(228, Box::new(JniZeroSvc("ExceptionCheck")))?;
        set_env(232, Box::new(GetObjectRefTypeSvc(state.clone())))?;

        Ok(vm)
    }

    pub fn set_jni(&self, jni: Box<dyn Jni>) {
        *self.jni.borrow_mut() = jni;
    }

    pub fn set_verbose(&self, verbose: bool) {
        self.state.borrow_mut().verbose = verbose;
    }

    pub fn java_vm_ptr(&self) -> u64 {
        self.state.borrow().java_vm_ptr
    }

    pub fn jni_env_ptr(&self) -> u64 {
        self.state.borrow().jni_env_ptr
    }

    pub fn resolve_class(&self, name: &str) -> i64 {
        self.state.borrow_mut().resolve_class(name)
    }

    pub fn resolve_class_with_super(&self, name: &str, super_handle: i64) -> i64 {
        self.state
            .borrow_mut()
            .resolve_class_with_super(name, Some(super_handle))
    }

    pub fn add_local_string(&self, s: impl Into<String>) -> i64 {
        self.state
            .borrow_mut()
            .add_local_object("java/lang/String", DvmObjectData::String(s.into()))
    }

    pub fn add_local_bytes(&self, bytes: Vec<u8>) -> i64 {
        self.state
            .borrow_mut()
            .add_local_object("[B", DvmObjectData::ByteArray(bytes))
    }

    pub fn get_object(&self, handle: i64) -> Option<DvmObject> {
        self.state.borrow().get_object(handle).cloned()
    }

    pub fn call_jni_onload(&self, emu: &mut AndroidEmulator, module: &LinuxModule) -> Result<i32> {
        let addr = module.find_symbol_addr("JNI_OnLoad").ok_or_else(|| {
            UnidbgError::Jni(format!("JNI_OnLoad not found in {}", module.name))
        })?;
        let vm_ptr = self.java_vm_ptr();
        let ret = emu.call_function(addr, &[vm_ptr, 0])?;
        Ok(ret as i32)
    }
}

struct GetSuperclassSvc(Rc<RefCell<DalvikState>>);
impl Svc for GetSuperclassSvc {
    fn name(&self) -> &str { "GetSuperclass" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let mut s = self.0.borrow_mut();
        let clazz = s.arg(backend, 1)? as i64;
        let ret = if let Some(cls) = s.classes_by_handle.get(&clazz).cloned() {
            if cls.name == "java/lang/Object" {
                0
            } else if let Some(sup) = cls.super_class {
                sup
            } else {
                s.resolve_class("java/lang/Object")
            }
        } else {
            0
        };
        Ok(SvcResult::Return(ret as u64))
    }
}

struct GetObjectRefTypeSvc(Rc<RefCell<DalvikState>>);
impl Svc for GetObjectRefTypeSvc {
    fn name(&self) -> &str { "GetObjectRefType" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let s = self.0.borrow();
        let obj = s.arg(backend, 1)? as i64;
        let ret = if obj == 0 {
            0 // JNIInvalidRefType
        } else if s.global_refs.contains_key(&obj) {
            2 // JNIGlobalRefType
        } else if s.objects.contains_key(&obj) || s.classes_by_handle.contains_key(&obj) {
            1 // JNILocalRefType
        } else {
            0
        };
        Ok(SvcResult::Return(ret))
    }
}

struct UnimplJniSvc(Rc<RefCell<DalvikState>>);
impl Svc for UnimplJniSvc {
    fn name(&self) -> &str { "unimplemented" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let s = self.0.borrow();
        if s.verbose {
            let lr = match s.arch {
                Arch::Arm64 => backend.reg_read(Arm64Reg::X30 as u32).unwrap_or(0),
                Arch::Arm32 => backend.reg_read(ArmReg::LR as u32).unwrap_or(0),
            };
            let x0 = s.arg(backend, 0).unwrap_or(0);
            let x1 = s.arg(backend, 1).unwrap_or(0);
            eprintln!("[JNI unimpl] lr={lr:#x} x0={x0:#x} x1={x1:#x}");
        }
        Ok(SvcResult::Return(0))
    }
}

struct JniZeroSvc(&'static str);
impl Svc for JniZeroSvc {
    fn name(&self) -> &str { self.0 }
    fn handle(&mut self, _: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        Ok(SvcResult::Return(0))
    }
}

struct JniConstSvc(&'static str, u64);
impl Svc for JniConstSvc {
    fn name(&self) -> &str { self.0 }
    fn handle(&mut self, _: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        Ok(SvcResult::Return(self.1))
    }
}

struct PopLocalFrameSvc(Rc<RefCell<DalvikState>>);
impl Svc for PopLocalFrameSvc {
    fn name(&self) -> &str { "PopLocalFrame" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let s = self.0.borrow();
        let res = s.arg(backend, 1)?;
        Ok(SvcResult::Return(res))
    }
}

struct GetEnvSvc(Rc<RefCell<DalvikState>>);
impl Svc for GetEnvSvc {
    fn name(&self) -> &str { "GetEnv" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let s = self.0.borrow();
        let env_ptr_out = s.arg(backend, 1)?;
        if env_ptr_out != 0 {
            UnidbgPointer::new(env_ptr_out, s.ptr_size()).write_pointer(backend, s.jni_env_ptr)?;
        }
        Ok(SvcResult::Return(JNI_OK as u64))
    }
}

struct AttachThreadSvc(Rc<RefCell<DalvikState>>);
impl Svc for AttachThreadSvc {
    fn name(&self) -> &str { "AttachCurrentThread" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let s = self.0.borrow();
        let env_ptr_out = s.arg(backend, 1)?;
        if env_ptr_out != 0 {
            UnidbgPointer::new(env_ptr_out, s.ptr_size()).write_pointer(backend, s.jni_env_ptr)?;
        }
        Ok(SvcResult::Return(JNI_OK as u64))
    }
}

struct GetJavaVmSvc(Rc<RefCell<DalvikState>>);
impl Svc for GetJavaVmSvc {
    fn name(&self) -> &str { "GetJavaVM" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let s = self.0.borrow();
        let vm_out = s.arg(backend, 1)?;
        if vm_out != 0 {
            UnidbgPointer::new(vm_out, s.ptr_size()).write_pointer(backend, s.java_vm_ptr)?;
        }
        Ok(SvcResult::Return(JNI_OK as u64))
    }
}

struct FindClassSvc(DalvikVM);
impl Svc for FindClassSvc {
    fn name(&self) -> &str { "FindClass" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let name = {
            let s = self.0.state.borrow();
            let name_addr = s.arg(backend, 1)?;
            let name = UnidbgPointer::new(name_addr, s.ptr_size()).read_cstr(backend)?;
            if s.verbose {
                eprintln!("[JNI FindClass] {name}");
            }
            name
        };
        let _ = self.0.jni.borrow_mut().find_class(&self.0, &name);
        let handle = self.0.state.borrow_mut().resolve_class(&name);
        Ok(SvcResult::Return(handle as u64))
    }
}

struct GetObjectClassSvc(Rc<RefCell<DalvikState>>);
impl Svc for GetObjectClassSvc {
    fn name(&self) -> &str { "GetObjectClass" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let mut s = self.0.borrow_mut();
        let obj_h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
        let cls_name = s
            .get_object(obj_h)
            .map(|o| o.class_name.clone())
            .unwrap_or_else(|| "java/lang/Object".to_string());
        let cls_h = s.resolve_class(&cls_name);
        Ok(SvcResult::Return(cls_h as u64))
    }
}

struct GetMethodIDSvc(Rc<RefCell<DalvikState>>);
impl Svc for GetMethodIDSvc {
    fn name(&self) -> &str { "GetMethodID" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let mut s = self.0.borrow_mut();
        let cls_h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
        let name_addr = s.arg(backend, 2)?;
        let sig_addr = s.arg(backend, 3)?;
        let mname = UnidbgPointer::new(name_addr, s.ptr_size()).read_cstr(backend)?;
        let msig = UnidbgPointer::new(sig_addr, s.ptr_size()).read_cstr(backend)?;
        let cname = s
            .get_class(cls_h)
            .map(|c| c.name.clone())
            .unwrap_or_else(|| "java/lang/Object".to_string());
        let id = s.next_member_id;
        s.next_member_id += 1;
        s.methods.insert(
            id,
            DvmMethod {
                id,
                class_name: cname,
                name: mname,
                signature: msig,
            },
        );
        Ok(SvcResult::Return(id as u64))
    }
}

struct GetFieldIDSvc(Rc<RefCell<DalvikState>>);
impl Svc for GetFieldIDSvc {
    fn name(&self) -> &str { "GetFieldID" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let mut s = self.0.borrow_mut();
        let cls_h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
        let name_addr = s.arg(backend, 2)?;
        let sig_addr = s.arg(backend, 3)?;
        let fname = UnidbgPointer::new(name_addr, s.ptr_size()).read_cstr(backend)?;
        let fsig = UnidbgPointer::new(sig_addr, s.ptr_size()).read_cstr(backend)?;
        let cname = s
            .get_class(cls_h)
            .map(|c| c.name.clone())
            .unwrap_or_else(|| "java/lang/Object".to_string());
        let id = s.next_member_id;
        s.next_member_id += 1;
        s.fields.insert(
            id,
            DvmField {
                id,
                class_name: cname,
                name: fname,
                signature: fsig,
            },
        );
        Ok(SvcResult::Return(id as u64))
    }
}

struct NewObjectVSvc(DalvikVM);
impl Svc for NewObjectVSvc {
    fn name(&self) -> &str { "NewObjectV" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let (cls, method, args) = {
            let s = self.0.state.borrow();
            let cls_h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
            let mid = DalvikState::reg_jint(s.arg(backend, 2)?, s.arch);
            let va_addr = s.arg(backend, 3)?;
            let Some(cls) = s.get_class(cls_h).cloned() else {
                return Ok(SvcResult::Return(0));
            };
            let Some(method) = s.methods.get(&mid).cloned() else {
                return Ok(SvcResult::Return(0));
            };
            if s.verbose {
                eprintln!("[JNI {}] {}.{}{}", self.name(), method.class_name, method.name, method.signature);
            }
            let args = VaList::read(s.arch, backend, va_addr, &method.signature)?;
            (cls, method, args)
        };
        if let Some(data) = self.0.jni.borrow_mut().new_object_v(&self.0, &cls, &method, &args) {
            let h = self.0.state.borrow_mut().add_local_object(cls.name, data);
            Ok(SvcResult::Return(h as u64))
        } else {
            Ok(SvcResult::Return(0))
        }
    }
}

struct CallObjectMethodVSvc(DalvikVM, bool);
impl Svc for CallObjectMethodVSvc {
    fn name(&self) -> &str { if self.1 { "CallStaticObjectMethodV" } else { "CallObjectMethodV" } }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let (target_h, method, args, verbose) = {
            let s = self.0.state.borrow();
            let target_h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
            let mid = DalvikState::reg_jint(s.arg(backend, 2)?, s.arch);
            let va_addr = s.arg(backend, 3)?;
            let Some(method) = s.methods.get(&mid).cloned() else {
                return Ok(SvcResult::Return(0));
            };
            if s.verbose {
                eprintln!("[JNI {}] {}.{}{}", self.name(), method.class_name, method.name, method.signature);
            }
            let args = VaList::read(s.arch, backend, va_addr, &method.signature)?;
            (target_h, method, args, s.verbose)
        };
        let _ = verbose;
        let res_data = if self.1 {
            let cls = self.0.state.borrow().get_class(target_h).cloned();
            let Some(cls) = cls else {
                return Ok(SvcResult::Return(0));
            };
            self.0.jni.borrow_mut().call_static_object_method_v(&self.0, &cls, &method, &args)
        } else {
            let obj = self.0.state.borrow().get_object(target_h).cloned();
            let Some(obj) = obj else {
                return Ok(SvcResult::Return(0));
            };
            self.0
                .jni
                .borrow_mut()
                .call_object_method_v(&self.0, &obj, &method, &args)
                .or_else(|| {
                    if method.class_name == "java/lang/String"
                        && method.name == "getBytes"
                        && (method.signature == "()[B"
                            || method.signature == "(Ljava/lang/String;)[B")
                    {
                        obj.as_str().map(|text| DvmObjectData::ByteArray(text.as_bytes().to_vec()))
                    } else {
                        None
                    }
                })
        };
        if let Some(data) = res_data {
            let cls_name = match &data {
                DvmObjectData::String(_) => "java/lang/String",
                DvmObjectData::ByteArray(_) => "[B",
                DvmObjectData::IntArray(_) => "[I",
                DvmObjectData::ObjectArray(_) => "[Ljava/lang/Object;",
                DvmObjectData::Boolean(_) => "java/lang/Boolean",
                DvmObjectData::Int(_) => "java/lang/Integer",
                DvmObjectData::Long(_) => "java/lang/Long",
                _ => "java/lang/Object",
            };
            let h = self.0.state.borrow_mut().add_local_object(cls_name, data);
            Ok(SvcResult::Return(h as u64))
        } else {
            Ok(SvcResult::Return(0))
        }
    }
}

struct CallIntMethodVSvc(DalvikVM, bool);
impl Svc for CallIntMethodVSvc {
    fn name(&self) -> &str { if self.1 { "CallStaticIntMethodV" } else { "CallIntMethodV" } }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let (target_h, method, args) = {
            let s = self.0.state.borrow();
            let target_h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
            let mid = DalvikState::reg_jint(s.arg(backend, 2)?, s.arch);
            let va_addr = s.arg(backend, 3)?;
            let Some(method) = s.methods.get(&mid).cloned() else {
                return Ok(SvcResult::Return(0));
            };
            if s.verbose {
                eprintln!("[JNI {}] {}.{}{}", self.name(), method.class_name, method.name, method.signature);
            }
            let args = VaList::read(s.arch, backend, va_addr, &method.signature)?;
            (target_h, method, args)
        };
        let val = if self.1 {
            let cls = self.0.state.borrow().get_class(target_h).cloned();
            let Some(cls) = cls else {
                return Ok(SvcResult::Return(0));
            };
            self.0.jni.borrow_mut().call_static_int_method_v(&self.0, &cls, &method, &args)
        } else {
            let obj = self.0.state.borrow().get_object(target_h).cloned();
            let Some(obj) = obj else {
                return Ok(SvcResult::Return(0));
            };
            if method.class_name == "java/lang/Integer" && method.name == "intValue" {
                obj.as_int().unwrap_or_else(|| self.0.jni.borrow_mut().call_int_method_v(&self.0, &obj, &method, &args))
            } else {
                self.0.jni.borrow_mut().call_int_method_v(&self.0, &obj, &method, &args)
            }
        };
        Ok(SvcResult::Return(val as i64 as u64))
    }
}

struct CallLongMethodVSvc(DalvikVM, bool);
impl Svc for CallLongMethodVSvc {
    fn name(&self) -> &str { if self.1 { "CallStaticLongMethodV" } else { "CallLongMethodV" } }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let (target_h, method, args) = {
            let s = self.0.state.borrow();
            let target_h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
            let mid = DalvikState::reg_jint(s.arg(backend, 2)?, s.arch);
            let va_addr = s.arg(backend, 3)?;
            let Some(method) = s.methods.get(&mid).cloned() else {
                return Ok(SvcResult::Return(0));
            };
            if s.verbose {
                eprintln!("[JNI {}] {}.{}{}", self.name(), method.class_name, method.name, method.signature);
            }
            let args = VaList::read(s.arch, backend, va_addr, &method.signature)?;
            (target_h, method, args)
        };
        let val = if self.1 {
            let cls = self.0.state.borrow().get_class(target_h).cloned();
            let Some(cls) = cls else {
                return Ok(SvcResult::Return(0));
            };
            self.0.jni.borrow_mut().call_static_long_method_v(&self.0, &cls, &method, &args)
        } else {
            let obj = self.0.state.borrow().get_object(target_h).cloned();
            let Some(obj) = obj else {
                return Ok(SvcResult::Return(0));
            };
            if method.class_name == "java/lang/Long" && method.name == "longValue" {
                obj.as_long().unwrap_or_else(|| self.0.jni.borrow_mut().call_long_method_v(&self.0, &obj, &method, &args))
            } else {
                self.0.jni.borrow_mut().call_long_method_v(&self.0, &obj, &method, &args)
            }
        };
        Ok(SvcResult::Return(val as u64))
    }
}

struct CallBooleanMethodVSvc(DalvikVM, bool);
impl Svc for CallBooleanMethodVSvc {
    fn name(&self) -> &str { if self.1 { "CallStaticBooleanMethodV" } else { "CallBooleanMethodV" } }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let (target_h, method, args) = {
            let s = self.0.state.borrow();
            let target_h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
            let mid = DalvikState::reg_jint(s.arg(backend, 2)?, s.arch);
            let va_addr = s.arg(backend, 3)?;
            let Some(method) = s.methods.get(&mid).cloned() else {
                return Ok(SvcResult::Return(0));
            };
            if s.verbose {
                eprintln!("[JNI {}] {}.{}{}", self.name(), method.class_name, method.name, method.signature);
            }
            let args = VaList::read(s.arch, backend, va_addr, &method.signature)?;
            (target_h, method, args)
        };
        let b = if self.1 {
            let cls = self.0.state.borrow().get_class(target_h).cloned();
            let Some(cls) = cls else {
                return Ok(SvcResult::Return(0));
            };
            self.0.jni.borrow_mut().call_static_boolean_method_v(&self.0, &cls, &method, &args)
        } else {
            let obj = self.0.state.borrow().get_object(target_h).cloned();
            let Some(obj) = obj else {
                return Ok(SvcResult::Return(0));
            };
            if method.class_name == "java/lang/Boolean" && method.name == "booleanValue" {
                obj.as_bool().unwrap_or_else(|| self.0.jni.borrow_mut().call_boolean_method_v(&self.0, &obj, &method, &args))
            } else {
                self.0.jni.borrow_mut().call_boolean_method_v(&self.0, &obj, &method, &args)
            }
        };
        Ok(SvcResult::Return(if b { 1 } else { 0 }))
    }
}

struct CallVoidMethodVSvc(DalvikVM, bool);
impl Svc for CallVoidMethodVSvc {
    fn name(&self) -> &str { if self.1 { "CallStaticVoidMethodV" } else { "CallVoidMethodV" } }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let (target_h, method, args) = {
            let s = self.0.state.borrow();
            let target_h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
            let mid = DalvikState::reg_jint(s.arg(backend, 2)?, s.arch);
            let va_addr = s.arg(backend, 3)?;
            let Some(method) = s.methods.get(&mid).cloned() else {
                return Ok(SvcResult::Void);
            };
            if s.verbose {
                eprintln!("[JNI {}] {}.{}{}", self.name(), method.class_name, method.name, method.signature);
            }
            let args = VaList::read(s.arch, backend, va_addr, &method.signature)?;
            (target_h, method, args)
        };
        if self.1 {
            let cls = self.0.state.borrow().get_class(target_h).cloned();
            if let Some(cls) = cls {
                self.0.jni.borrow_mut().call_static_void_method_v(&self.0, &cls, &method, &args);
            }
        } else {
            let obj = self.0.state.borrow().get_object(target_h).cloned();
            if let Some(obj) = obj {
                self.0.jni.borrow_mut().call_void_method_v(&self.0, &obj, &method, &args);
            }
        }
        Ok(SvcResult::Void)
    }
}

struct GetObjectFieldSvc(DalvikVM, bool);
impl Svc for GetObjectFieldSvc {
    fn name(&self) -> &str { if self.1 { "GetStaticObjectField" } else { "GetObjectField" } }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let (target_h, field) = {
            let s = self.0.state.borrow();
            let target_h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
            let fid = DalvikState::reg_jint(s.arg(backend, 2)?, s.arch);
            let Some(field) = s.fields.get(&fid).cloned() else {
                return Ok(SvcResult::Return(0));
            };
            (target_h, field)
        };
        let data = if self.1 {
            let cls = self.0.state.borrow().get_class(target_h).cloned();
            let Some(cls) = cls else {
                return Ok(SvcResult::Return(0));
            };
            self.0.jni.borrow_mut().get_static_object_field(&self.0, &cls, &field)
        } else {
            let obj = self.0.state.borrow().get_object(target_h).cloned();
            let Some(obj) = obj else {
                return Ok(SvcResult::Return(0));
            };
            self.0.jni.borrow_mut().get_object_field(&self.0, &obj, &field)
        };
        if let Some(d) = data {
            let cls_name = match &d {
                DvmObjectData::String(_) => "java/lang/String",
                DvmObjectData::ByteArray(_) => "[B",
                _ => "java/lang/Object",
            };
            let h = self.0.state.borrow_mut().add_local_object(cls_name, d);
            Ok(SvcResult::Return(h as u64))
        } else {
            Ok(SvcResult::Return(0))
        }
    }
}

struct IsSameObjectSvc(Rc<RefCell<DalvikState>>);
impl Svc for IsSameObjectSvc {
    fn name(&self) -> &str { "IsSameObject" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let s = self.0.borrow();
        let a = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
        let b = DalvikState::reg_jint(s.arg(backend, 2)?, s.arch);
        Ok(SvcResult::Return(if a == b { 1 } else { 0 }))
    }
}

struct NewGlobalRefSvc(Rc<RefCell<DalvikState>>);
impl Svc for NewGlobalRefSvc {
    fn name(&self) -> &str { "NewGlobalRef" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let mut s = self.0.borrow_mut();
        let h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
        if let Some(obj) = s.get_object(h).cloned() {
            s.global_refs.insert(h, obj);
            Ok(SvcResult::Return(h as u64))
        } else {
            Ok(SvcResult::Return(h as u64))
        }
    }
}

struct DeleteGlobalRefSvc(Rc<RefCell<DalvikState>>);
impl Svc for DeleteGlobalRefSvc {
    fn name(&self) -> &str { "DeleteGlobalRef" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let mut s = self.0.borrow_mut();
        let h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
        s.global_refs.remove(&h);
        Ok(SvcResult::Void)
    }
}

struct DeleteLocalRefSvc;
impl Svc for DeleteLocalRefSvc {
    fn name(&self) -> &str { "DeleteLocalRef" }
    fn handle(&mut self, _backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        // Local ref deletion must not destroy objects still referenced by arrays/globals/return values.
        Ok(SvcResult::Void)
    }
}

struct NewStringUtfSvc(Rc<RefCell<DalvikState>>);
impl Svc for NewStringUtfSvc {
    fn name(&self) -> &str { "NewStringUTF" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let mut s = self.0.borrow_mut();
        let addr = s.arg(backend, 1)?;
        let text = UnidbgPointer::new(addr, s.ptr_size()).read_cstr(backend)?;
        let h = s.add_local_object("java/lang/String", DvmObjectData::String(text));
        Ok(SvcResult::Return(h as u64))
    }
}

struct GetStringUtfLengthSvc(Rc<RefCell<DalvikState>>);
impl Svc for GetStringUtfLengthSvc {
    fn name(&self) -> &str { "GetStringUTFLength" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let s = self.0.borrow();
        let h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
        let len = s
            .get_object(h)
            .and_then(|o| o.as_str())
            .map(|st| st.len() as u64)
            .unwrap_or(0);
        Ok(SvcResult::Return(len))
    }
}

struct GetStringUtfCharsSvc(Rc<RefCell<DalvikState>>);
impl Svc for GetStringUtfCharsSvc {
    fn name(&self) -> &str { "GetStringUTFChars" }
    fn handle(&mut self, backend: &mut dyn Backend, memory: &mut MemoryManager) -> Result<SvcResult> {
        let s = self.0.borrow();
        let h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
        let ptr_sz = s.ptr_size();
        let Some(text) = s.get_object(h).and_then(|o| o.as_str()).map(|x| x.to_string()) else {
            return Ok(SvcResult::Return(0));
        };
        let block = memory.malloc(backend, text.len() + 1, true)?;
        UnidbgPointer::new(block.addr, ptr_sz).write_cstr(backend, &text)?;
        Ok(SvcResult::Return(block.addr))
    }
}

struct GetArrayLengthSvc(Rc<RefCell<DalvikState>>);
impl Svc for GetArrayLengthSvc {
    fn name(&self) -> &str { "GetArrayLength" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let s = self.0.borrow();
        let h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
        let len = s
            .get_object(h)
            .map(|o| match &o.data {
                DvmObjectData::ByteArray(b) => b.len(),
                DvmObjectData::IntArray(a) => a.len(),
                DvmObjectData::ObjectArray(a) => a.len(),
                _ => 0,
            })
            .unwrap_or(0);
        Ok(SvcResult::Return(len as u64))
    }
}

struct NewObjectArraySvc(Rc<RefCell<DalvikState>>);
impl Svc for NewObjectArraySvc {
    fn name(&self) -> &str { "NewObjectArray" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let mut s = self.0.borrow_mut();
        let len = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch).max(0) as usize;
        let init_h = DalvikState::reg_jint(s.arg(backend, 3)?, s.arch);
        let h = s.add_local_object("[Ljava/lang/Object;", DvmObjectData::ObjectArray(vec![init_h; len]));
        Ok(SvcResult::Return(h as u64))
    }
}

struct GetObjectArrayElementSvc(Rc<RefCell<DalvikState>>);
impl Svc for GetObjectArrayElementSvc {
    fn name(&self) -> &str { "GetObjectArrayElement" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let s = self.0.borrow();
        let arr_h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
        let idx = DalvikState::reg_jint(s.arg(backend, 2)?, s.arch) as usize;
        let elem = s
            .get_object(arr_h)
            .and_then(|o| o.as_object_array())
            .and_then(|arr| arr.get(idx).copied())
            .unwrap_or(0);
        Ok(SvcResult::Return(elem as u64))
    }
}

struct SetObjectArrayElementSvc(Rc<RefCell<DalvikState>>);
impl Svc for SetObjectArrayElementSvc {
    fn name(&self) -> &str { "SetObjectArrayElement" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let mut s = self.0.borrow_mut();
        let arr_h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
        let idx = DalvikState::reg_jint(s.arg(backend, 2)?, s.arch) as usize;
        let val_h = DalvikState::reg_jint(s.arg(backend, 3)?, s.arch);
        if let Some(obj) = s.objects.get_mut(&arr_h) {
            if let DvmObjectData::ObjectArray(ref mut vec) = obj.data {
                if idx < vec.len() {
                    vec[idx] = val_h;
                }
            }
        }
        Ok(SvcResult::Void)
    }
}

struct NewByteArraySvc(Rc<RefCell<DalvikState>>);
impl Svc for NewByteArraySvc {
    fn name(&self) -> &str { "NewByteArray" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let mut s = self.0.borrow_mut();
        let len = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch).max(0) as usize;
        let h = s.add_local_object("[B", DvmObjectData::ByteArray(vec![0u8; len]));
        Ok(SvcResult::Return(h as u64))
    }
}

struct GetByteArrayElementsSvc(Rc<RefCell<DalvikState>>);
impl Svc for GetByteArrayElementsSvc {
    fn name(&self) -> &str { "GetByteArrayElements" }
    fn handle(&mut self, backend: &mut dyn Backend, memory: &mut MemoryManager) -> Result<SvcResult> {
        let s = self.0.borrow();
        let h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
        let Some(bytes) = s.get_object(h).and_then(|o| o.as_bytes()).map(|b| b.to_vec()) else {
            return Ok(SvcResult::Return(0));
        };
        let block = memory.malloc(backend, bytes.len().max(1), true)?;
        backend.mem_write(block.addr, &bytes)?;
        Ok(SvcResult::Return(block.addr))
    }
}

struct GetIntArrayElementsSvc(Rc<RefCell<DalvikState>>);
impl Svc for GetIntArrayElementsSvc {
    fn name(&self) -> &str { "GetIntArrayElements" }
    fn handle(&mut self, backend: &mut dyn Backend, memory: &mut MemoryManager) -> Result<SvcResult> {
        let s = self.0.borrow();
        let h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
        let Some(ints) = s.get_object(h).and_then(|o| match &o.data {
            DvmObjectData::IntArray(v) => Some(v.clone()),
            _ => None,
        }) else {
            return Ok(SvcResult::Return(0));
        };
        let byte_len = (ints.len() * 4).max(4);
        let block = memory.malloc(backend, byte_len, true)?;
        let mut raw = Vec::with_capacity(ints.len() * 4);
        for v in ints {
            raw.extend_from_slice(&v.to_le_bytes());
        }
        if !raw.is_empty() {
            backend.mem_write(block.addr, &raw)?;
        }
        Ok(SvcResult::Return(block.addr))
    }
}

struct GetByteArrayRegionSvc(Rc<RefCell<DalvikState>>);
impl Svc for GetByteArrayRegionSvc {
    fn name(&self) -> &str { "GetByteArrayRegion" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let s = self.0.borrow();
        let h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
        let start = DalvikState::reg_jint(s.arg(backend, 2)?, s.arch).max(0) as usize;
        let len = DalvikState::reg_jint(s.arg(backend, 3)?, s.arch).max(0) as usize;
        let buf_addr = s.arg(backend, 4)?;
        if let Some(bytes) = s.get_object(h).and_then(|o| o.as_bytes()) {
            let end = (start + len).min(bytes.len());
            if start < end {
                backend.mem_write(buf_addr, &bytes[start..end])?;
            }
        }
        Ok(SvcResult::Void)
    }
}

struct SetByteArrayRegionSvc(Rc<RefCell<DalvikState>>);
impl Svc for SetByteArrayRegionSvc {
    fn name(&self) -> &str { "SetByteArrayRegion" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let mut s = self.0.borrow_mut();
        let h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
        let start = DalvikState::reg_jint(s.arg(backend, 2)?, s.arch).max(0) as usize;
        let len = DalvikState::reg_jint(s.arg(backend, 3)?, s.arch).max(0) as usize;
        let buf_addr = s.arg(backend, 4)?;
        let mut tmp = vec![0u8; len];
        backend.mem_read(buf_addr, &mut tmp)?;
        if let Some(obj) = s.objects.get_mut(&h) {
            if let DvmObjectData::ByteArray(ref mut bytes) = obj.data {
                if start + len <= bytes.len() {
                    bytes[start..start + len].copy_from_slice(&tmp);
                }
            }
        }
        Ok(SvcResult::Void)
    }
}

struct RegisterNativesSvc(Rc<RefCell<DalvikState>>);
impl Svc for RegisterNativesSvc {
    fn name(&self) -> &str { "RegisterNatives" }
    fn handle(&mut self, backend: &mut dyn Backend, _: &mut MemoryManager) -> Result<SvcResult> {
        let mut s = self.0.borrow_mut();
        let cls_h = DalvikState::reg_jint(s.arg(backend, 1)?, s.arch);
        let methods_addr = s.arg(backend, 2)?;
        let count = DalvikState::reg_jint(s.arg(backend, 3)?, s.arch).max(0) as u64;
        let cname = s
            .get_class(cls_h)
            .map(|c| c.name.clone())
            .unwrap_or_default();
        let ptr_sz = s.ptr_size() as u64;
        let struct_sz = ptr_sz * 3;
        for i in 0..count {
            let base = methods_addr + i * struct_sz;
            let name_ptr = UnidbgPointer::new(base, s.ptr_size()).read_pointer(backend)?.addr();
            let sig_ptr = UnidbgPointer::new(base + ptr_sz, s.ptr_size()).read_pointer(backend)?.addr();
            let fn_ptr = UnidbgPointer::new(base + ptr_sz * 2, s.ptr_size()).read_pointer(backend)?.addr();
            let mname = UnidbgPointer::new(name_ptr, s.ptr_size()).read_cstr(backend)?;
            let msig = UnidbgPointer::new(sig_ptr, s.ptr_size()).read_cstr(backend)?;
            if s.verbose {
                eprintln!("[JNI RegisterNatives] {cname}.{mname}{msig} -> {fn_ptr:#x}");
            }
            s.registered_natives.insert((cname.clone(), mname, msig), fn_ptr);
        }
        Ok(SvcResult::Return(JNI_OK as u64))
    }
}
