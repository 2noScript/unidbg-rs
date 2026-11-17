use crate::arm::backend::Backend;
use crate::error::{Result, UnidbgError};

/// Guest memory pointer wrapper supporting both 32-bit and 64-bit address spaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnidbgPointer {
    addr: u64,
    pointer_size: usize,
}

impl UnidbgPointer {
    pub fn new(addr: u64, pointer_size: usize) -> Self {
        debug_assert!(pointer_size == 4 || pointer_size == 8);
        let masked = if pointer_size == 4 {
            addr & 0xffff_ffff
        } else {
            addr
        };
        Self {
            addr: masked,
            pointer_size,
        }
    }

    pub fn addr(&self) -> u64 {
        self.addr
    }

    pub fn pointer_size(&self) -> usize {
        self.pointer_size
    }

    pub fn is_null(&self) -> bool {
        self.addr == 0
    }

    pub fn share(&self, offset: i64) -> Self {
        let next = if offset >= 0 {
            self.addr.wrapping_add(offset as u64)
        } else {
            self.addr.wrapping_sub(offset.unsigned_abs())
        };
        Self::new(next, self.pointer_size)
    }

    pub fn read_bytes(&self, backend: &dyn Backend, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        backend.mem_read(self.addr, &mut buf)?;
        Ok(buf)
    }

    pub fn write_bytes(&self, backend: &mut dyn Backend, data: &[u8]) -> Result<()> {
        backend.mem_write(self.addr, data)
    }

    pub fn read_u8(&self, backend: &dyn Backend) -> Result<u8> {
        let mut buf = [0u8; 1];
        backend.mem_read(self.addr, &mut buf)?;
        Ok(buf[0])
    }

    pub fn read_u16(&self, backend: &dyn Backend) -> Result<u16> {
        let mut buf = [0u8; 2];
        backend.mem_read(self.addr, &mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    pub fn read_u32(&self, backend: &dyn Backend) -> Result<u32> {
        let mut buf = [0u8; 4];
        backend.mem_read(self.addr, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    pub fn read_u64(&self, backend: &dyn Backend) -> Result<u64> {
        let mut buf = [0u8; 8];
        backend.mem_read(self.addr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    pub fn read_i32(&self, backend: &dyn Backend) -> Result<i32> {
        Ok(self.read_u32(backend)? as i32)
    }

    pub fn read_i64(&self, backend: &dyn Backend) -> Result<i64> {
        Ok(self.read_u64(backend)? as i64)
    }

    pub fn read_pointer(&self, backend: &dyn Backend) -> Result<Self> {
        let addr = match self.pointer_size {
            4 => self.read_u32(backend)? as u64,
            8 => self.read_u64(backend)?,
            _ => unreachable!(),
        };
        Ok(Self::new(addr, self.pointer_size))
    }

    pub fn write_u8(&self, backend: &mut dyn Backend, val: u8) -> Result<()> {
        backend.mem_write(self.addr, &[val])
    }

    pub fn write_u16(&self, backend: &mut dyn Backend, val: u16) -> Result<()> {
        backend.mem_write(self.addr, &val.to_le_bytes())
    }

    pub fn write_u32(&self, backend: &mut dyn Backend, val: u32) -> Result<()> {
        backend.mem_write(self.addr, &val.to_le_bytes())
    }

    pub fn write_u64(&self, backend: &mut dyn Backend, val: u64) -> Result<()> {
        backend.mem_write(self.addr, &val.to_le_bytes())
    }

    pub fn write_i32(&self, backend: &mut dyn Backend, val: i32) -> Result<()> {
        self.write_u32(backend, val as u32)
    }

    pub fn write_i64(&self, backend: &mut dyn Backend, val: i64) -> Result<()> {
        self.write_u64(backend, val as u64)
    }

    pub fn write_pointer(&self, backend: &mut dyn Backend, target: u64) -> Result<()> {
        match self.pointer_size {
            4 => self.write_u32(backend, target as u32),
            8 => self.write_u64(backend, target),
            _ => unreachable!(),
        }
    }

    pub fn read_cstr(&self, backend: &dyn Backend) -> Result<String> {
        let mut out = Vec::new();
        let mut cur = self.addr;
        let mut byte = [0u8; 1];
        loop {
            backend.mem_read(cur, &mut byte)?;
            if byte[0] == 0 {
                break;
            }
            out.push(byte[0]);
            cur += 1;
            if out.len() > 1024 * 1024 {
                return Err(UnidbgError::Backend("cstr exceeded 1 MiB limit".into()));
            }
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    pub fn write_cstr(&self, backend: &mut dyn Backend, s: &str) -> Result<()> {
        let mut data = Vec::with_capacity(s.len() + 1);
        data.extend_from_slice(s.as_bytes());
        data.push(0);
        backend.mem_write(self.addr, &data)
    }
}

/// Trait for C-compatible guest structures (replaces `UnidbgStructure`).
pub trait UnidbgStruct: Sized {
    fn size(pointer_size: usize) -> usize;
    fn pack(&self, ptr: &UnidbgPointer, backend: &mut dyn Backend) -> Result<()>;
    fn unpack(ptr: &UnidbgPointer, backend: &dyn Backend) -> Result<Self>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arm::backend::tests::MockBackend;
    use crate::arm::backend::MemoryPerm;

    #[derive(Debug, PartialEq, Eq)]
    struct DummyPair {
        tag: u32,
        next: u64,
    }

    impl UnidbgStruct for DummyPair {
        fn size(pointer_size: usize) -> usize {
            if pointer_size == 4 {
                8
            } else {
                16
            }
        }

        fn pack(&self, ptr: &UnidbgPointer, backend: &mut dyn Backend) -> Result<()> {
            ptr.write_u32(backend, self.tag)?;
            let next_off = if ptr.pointer_size() == 4 { 4 } else { 8 };
            ptr.share(next_off).write_pointer(backend, self.next)
        }

        fn unpack(ptr: &UnidbgPointer, backend: &dyn Backend) -> Result<Self> {
            let tag = ptr.read_u32(backend)?;
            let next_off = if ptr.pointer_size() == 4 { 4 } else { 8 };
            let next = ptr.share(next_off).read_pointer(backend)?.addr();
            Ok(Self { tag, next })
        }
    }

    #[test]
    fn pointer_read_write_32_and_64() {
        let mut backend = MockBackend::new();
        backend.mem_map(0x2000, 0x1000, MemoryPerm::ALL).unwrap();

        let p32 = UnidbgPointer::new(0x2000, 4);
        let pair32 = DummyPair {
            tag: 0x1234,
            next: 0x8000_0000,
        };
        pair32.pack(&p32, &mut backend).unwrap();
        assert_eq!(DummyPair::unpack(&p32, &backend).unwrap(), pair32);

        let p64 = UnidbgPointer::new(0x2100, 8);
        let pair64 = DummyPair {
            tag: 0xabcd,
            next: 0x1234_5678_9abc_def0,
        };
        pair64.pack(&p64, &mut backend).unwrap();
        assert_eq!(DummyPair::unpack(&p64, &backend).unwrap(), pair64);

        let str_ptr = UnidbgPointer::new(0x2200, 8);
        str_ptr.write_cstr(&mut backend, "hello unidbg-rs").unwrap();
        assert_eq!(str_ptr.read_cstr(&backend).unwrap(), "hello unidbg-rs");
    }
}
