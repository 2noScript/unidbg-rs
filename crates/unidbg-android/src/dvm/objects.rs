use std::collections::HashMap;

/// Data payload carried by a [`DvmObject`].
#[derive(Debug, Clone)]
pub enum DvmObjectData {
    Empty,
    Boolean(bool),
    Int(i32),
    Long(i64),
    String(String),
    ByteArray(Vec<u8>),
    IntArray(Vec<i32>),
    ObjectArray(Vec<i64>),
    Class(String),
}

/// Emulated Dalvik/ART object handle.
#[derive(Debug, Clone)]
pub struct DvmObject {
    pub handle: i64,
    pub class_name: String,
    pub data: DvmObjectData,
}

impl DvmObject {
    pub fn as_str(&self) -> Option<&str> {
        match &self.data {
            DvmObjectData::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match &self.data {
            DvmObjectData::ByteArray(b) => Some(b.as_slice()),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match &self.data {
            DvmObjectData::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i32> {
        match &self.data {
            DvmObjectData::Int(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_long(&self) -> Option<i64> {
        match &self.data {
            DvmObjectData::Long(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_object_array(&self) -> Option<&[i64]> {
        match &self.data {
            DvmObjectData::ObjectArray(v) => Some(v.as_slice()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DvmMethod {
    pub id: i64,
    pub class_name: String,
    pub name: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct DvmField {
    pub id: i64,
    pub class_name: String,
    pub name: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct DvmClass {
    pub handle: i64,
    pub name: String,
    pub super_class: Option<i64>,
    pub methods: HashMap<String, DvmMethod>,
    pub fields: HashMap<String, DvmField>,
}
