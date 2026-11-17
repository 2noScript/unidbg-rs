use crate::dvm::objects::{DvmClass, DvmField, DvmMethod, DvmObject, DvmObjectData};
use crate::dvm::var_arg::JniArg;
use crate::dvm::vm::DalvikVM;

/// User-overridable JNI callback trait (replaces `Jni` + `AbstractJni`).
/// Default implementations fail soft (return `None` / `0` / `false`), matching `AbstractJni`.
pub trait Jni {
    fn find_class(&mut self, _vm: &DalvikVM, _name: &str) -> Option<String> {
        None
    }

    fn call_object_method_v(
        &mut self,
        _vm: &DalvikVM,
        _obj: &DvmObject,
        _method: &DvmMethod,
        _args: &[JniArg],
    ) -> Option<DvmObjectData> {
        None
    }

    fn call_static_object_method_v(
        &mut self,
        _vm: &DalvikVM,
        _class: &DvmClass,
        _method: &DvmMethod,
        _args: &[JniArg],
    ) -> Option<DvmObjectData> {
        None
    }

    fn call_int_method_v(
        &mut self,
        _vm: &DalvikVM,
        _obj: &DvmObject,
        _method: &DvmMethod,
        _args: &[JniArg],
    ) -> i32 {
        0
    }

    fn call_static_int_method_v(
        &mut self,
        _vm: &DalvikVM,
        _class: &DvmClass,
        _method: &DvmMethod,
        _args: &[JniArg],
    ) -> i32 {
        0
    }

    fn call_long_method_v(
        &mut self,
        _vm: &DalvikVM,
        _obj: &DvmObject,
        _method: &DvmMethod,
        _args: &[JniArg],
    ) -> i64 {
        0
    }

    fn call_static_long_method_v(
        &mut self,
        _vm: &DalvikVM,
        _class: &DvmClass,
        _method: &DvmMethod,
        _args: &[JniArg],
    ) -> i64 {
        0
    }

    fn call_boolean_method_v(
        &mut self,
        _vm: &DalvikVM,
        _obj: &DvmObject,
        _method: &DvmMethod,
        _args: &[JniArg],
    ) -> bool {
        false
    }

    fn call_static_boolean_method_v(
        &mut self,
        _vm: &DalvikVM,
        _class: &DvmClass,
        _method: &DvmMethod,
        _args: &[JniArg],
    ) -> bool {
        false
    }

    fn call_void_method_v(
        &mut self,
        _vm: &DalvikVM,
        _obj: &DvmObject,
        _method: &DvmMethod,
        _args: &[JniArg],
    ) {
    }

    fn call_static_void_method_v(
        &mut self,
        _vm: &DalvikVM,
        _class: &DvmClass,
        _method: &DvmMethod,
        _args: &[JniArg],
    ) {
    }

    fn get_object_field(
        &mut self,
        _vm: &DalvikVM,
        _obj: &DvmObject,
        _field: &DvmField,
    ) -> Option<DvmObjectData> {
        None
    }

    fn get_static_object_field(
        &mut self,
        _vm: &DalvikVM,
        _class: &DvmClass,
        _field: &DvmField,
    ) -> Option<DvmObjectData> {
        None
    }

    fn new_object_v(
        &mut self,
        _vm: &DalvikVM,
        _class: &DvmClass,
        _method: &DvmMethod,
        _args: &[JniArg],
    ) -> Option<DvmObjectData> {
        Some(DvmObjectData::Empty)
    }
}

/// Default fail-soft `Jni` implementation.
pub struct AbstractJni;

impl Jni for AbstractJni {}
