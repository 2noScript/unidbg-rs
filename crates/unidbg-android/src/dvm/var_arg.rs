use unidbg_api::arm::backend::Backend;
use unidbg_api::arm::Arch;
use unidbg_api::error::Result;

/// Parsed JNI method parameter value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum JniArg {
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    Object(i64),
}

/// Parse parameter shorty characters from a JNI signature, e.g. `(ILjava/lang/String;[B)V` -> `['I', 'L', '[']`.
pub fn parse_param_shorty(signature: &str) -> Vec<char> {
    let mut out = Vec::new();
    let Some(start) = signature.find('(') else {
        return out;
    };
    let Some(end) = signature.find(')') else {
        return out;
    };
    let params = &signature[start + 1..end];
    let bytes = params.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] as char {
            '[' => {
                out.push('[');
                i += 1;
                while i < bytes.len() && bytes[i] == b'[' {
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == b'L' {
                    while i < bytes.len() && bytes[i] != b';' {
                        i += 1;
                    }
                }
                i += 1;
            }
            'L' => {
                out.push('L');
                while i < bytes.len() && bytes[i] != b';' {
                    i += 1;
                }
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Reads `va_list` arguments according to AAPCS32 or AAPCS64.
pub struct VaList;

impl VaList {
    pub fn read(
        arch: Arch,
        backend: &dyn Backend,
        va_list_addr: u64,
        signature: &str,
    ) -> Result<Vec<JniArg>> {
        let shorty = parse_param_shorty(signature);
        if shorty.is_empty() || va_list_addr == 0 {
            return Ok(Vec::new());
        }
        match arch {
            Arch::Arm32 => Self::read_32(backend, va_list_addr, &shorty),
            Arch::Arm64 => Self::read_64(backend, va_list_addr, &shorty),
        }
    }

    fn read_32(backend: &dyn Backend, mut ap: u64, shorty: &[char]) -> Result<Vec<JniArg>> {
        let mut args = Vec::with_capacity(shorty.len());
        for &c in shorty {
            match c {
                'J' | 'D' => {
                    ap = (ap + 7) & !7;
                    let mut buf = [0u8; 8];
                    backend.mem_read(ap, &mut buf)?;
                    ap += 8;
                    if c == 'J' {
                        args.push(JniArg::Long(i64::from_le_bytes(buf)));
                    } else {
                        args.push(JniArg::Double(f64::from_le_bytes(buf)));
                    }
                }
                'F' => {
                    let mut buf = [0u8; 4];
                    backend.mem_read(ap, &mut buf)?;
                    ap += 4;
                    args.push(JniArg::Float(f32::from_le_bytes(buf)));
                }
                'L' | '[' => {
                    let mut buf = [0u8; 4];
                    backend.mem_read(ap, &mut buf)?;
                    ap += 4;
                    args.push(JniArg::Object(u32::from_le_bytes(buf) as i64));
                }
                _ => {
                    let mut buf = [0u8; 4];
                    backend.mem_read(ap, &mut buf)?;
                    ap += 4;
                    args.push(JniArg::Int(i32::from_le_bytes(buf)));
                }
            }
        }
        Ok(args)
    }

    fn read_64(backend: &dyn Backend, va_addr: u64, shorty: &[char]) -> Result<Vec<JniArg>> {
        // AAPCS64 va_list:
        //   +0x00: __stack (u64)
        //   +0x08: __gr_top (u64)
        //   +0x10: __vr_top (u64)
        //   +0x18: __gr_offs (i32)
        //   +0x1c: __vr_offs (i32)
        let mut raw = [0u8; 32];
        backend.mem_read(va_addr, &mut raw)?;
        let mut stack = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let gr_top = u64::from_le_bytes(raw[8..16].try_into().unwrap());
        let vr_top = u64::from_le_bytes(raw[16..24].try_into().unwrap());
        let mut gr_offs = i32::from_le_bytes(raw[24..28].try_into().unwrap());
        let mut vr_offs = i32::from_le_bytes(raw[28..32].try_into().unwrap());

        let mut args = Vec::with_capacity(shorty.len());
        for &c in shorty {
            match c {
                'F' | 'D' => {
                    let val_u64 = if vr_offs < 0 {
                        let addr = (vr_top as i64 + vr_offs as i64) as u64;
                        vr_offs += 16;
                        let mut b = [0u8; 8];
                        backend.mem_read(addr, &mut b)?;
                        u64::from_le_bytes(b)
                    } else {
                        let mut b = [0u8; 8];
                        backend.mem_read(stack, &mut b)?;
                        stack += 8;
                        u64::from_le_bytes(b)
                    };
                    if c == 'F' {
                        args.push(JniArg::Float(f32::from_bits(val_u64 as u32)));
                    } else {
                        args.push(JniArg::Double(f64::from_bits(val_u64)));
                    }
                }
                _ => {
                    let val_u64 = if gr_offs < 0 {
                        let addr = (gr_top as i64 + gr_offs as i64) as u64;
                        gr_offs += 8;
                        let mut b = [0u8; 8];
                        backend.mem_read(addr, &mut b)?;
                        u64::from_le_bytes(b)
                    } else {
                        let mut b = [0u8; 8];
                        backend.mem_read(stack, &mut b)?;
                        stack += 8;
                        u64::from_le_bytes(b)
                    };
                    match c {
                        'J' => args.push(JniArg::Long(val_u64 as i64)),
                        'L' | '[' => args.push(JniArg::Object(val_u64 as i64)),
                        _ => args.push(JniArg::Int(val_u64 as i32)),
                    }
                }
            }
        }
        Ok(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unidbg_api::arm::backend::{BackendContext, CodeHookFn, HookId, IntrHookFn, MemHookFn, MemoryPerm};
    use unidbg_api::error::UnidbgError;
    use std::collections::HashMap;

    struct DummyBackend(HashMap<u64, Vec<u8>>);
    struct DummyCtx;
    impl BackendContext for DummyCtx {
        fn as_any(&self) -> &dyn std::any::Any { self }
        fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    }

    impl Backend for DummyBackend {
        fn reg_read(&self, _: u32) -> Result<u64> { Ok(0) }
        fn reg_write(&mut self, _: u32, _: u64) -> Result<()> { Ok(()) }
        fn reg_read_vec(&self, _: u32) -> Result<u128> { Ok(0) }
        fn reg_write_vec(&mut self, _: u32, _: u128) -> Result<()> { Ok(()) }
        fn mem_read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            for (b, page) in &self.0 {
                if addr >= *b && addr + buf.len() as u64 <= *b + page.len() as u64 {
                    let off = (addr - *b) as usize;
                    buf.copy_from_slice(&page[off..off + buf.len()]);
                    return Ok(());
                }
            }
            Err(UnidbgError::Backend("unmapped".into()))
        }
        fn mem_write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
            for (b, page) in &mut self.0 {
                if addr >= *b && addr + data.len() as u64 <= *b + page.len() as u64 {
                    let off = (addr - *b) as usize;
                    page[off..off + data.len()].copy_from_slice(data);
                    return Ok(());
                }
            }
            Err(UnidbgError::Backend("unmapped".into()))
        }
        fn mem_map(&mut self, addr: u64, size: usize, _: MemoryPerm) -> Result<()> {
            self.0.insert(addr, vec![0; size]);
            Ok(())
        }
        fn mem_unmap(&mut self, _: u64, _: usize) -> Result<()> { Ok(()) }
        fn mem_protect(&mut self, _: u64, _: usize, _: MemoryPerm) -> Result<()> { Ok(()) }
        fn emu_start(&mut self, _: u64, _: u64, _: u64, _: usize) -> Result<()> { Ok(()) }
        fn emu_stop(&mut self) -> Result<()> { Ok(()) }
        fn context_alloc(&self) -> Result<Box<dyn BackendContext>> { Ok(Box::new(DummyCtx)) }
        fn context_save(&self, _: &mut dyn BackendContext) -> Result<()> { Ok(()) }
        fn context_restore(&mut self, _: &dyn BackendContext) -> Result<()> { Ok(()) }
        fn hook_add_code(&mut self, _: u64, _: u64, _: CodeHookFn) -> Result<HookId> { Ok(HookId(1)) }
        fn hook_add_mem(&mut self, _: u64, _: u64, _: MemHookFn) -> Result<HookId> { Ok(HookId(2)) }
        fn hook_add_intr(&mut self, _: IntrHookFn) -> Result<HookId> { Ok(HookId(3)) }
        fn hook_del(&mut self, _: HookId) -> Result<()> { Ok(()) }
    }

    #[test]
    fn parse_shorty_and_read_valist_32_64() {
        assert_eq!(
            parse_param_shorty("(IJDLjava/lang/String;[B)V"),
            vec!['I', 'J', 'D', 'L', '[']
        );

        let mut backend = DummyBackend(HashMap::new());
        backend.mem_map(0x1000, 0x1000, MemoryPerm::ALL).unwrap();

        // 32-bit va_list: int(7), align-8, long(0x1122334455667788), double(3.5), obj(0x70030001)
        backend.mem_write(0x1000, &7i32.to_le_bytes()).unwrap();
        backend.mem_write(0x1008, &0x1122_3344_5566_7788i64.to_le_bytes()).unwrap();
        backend.mem_write(0x1010, &3.5f64.to_le_bytes()).unwrap();
        backend.mem_write(0x1018, &0x7003_0001u32.to_le_bytes()).unwrap();

        let args32 = VaList::read(Arch::Arm32, &backend, 0x1000, "(IJDLjava/lang/String;)V").unwrap();
        assert_eq!(
            args32,
            vec![
                JniArg::Int(7),
                JniArg::Long(0x1122_3344_5566_7788),
                JniArg::Double(3.5),
                JniArg::Object(0x7003_0001),
            ]
        );

        // 64-bit va_list: gr_top=0x1200, gr_offs=-16, vr_top=0x1300, vr_offs=-16
        backend.mem_write(0x1200 - 16, &99u64.to_le_bytes()).unwrap();
        backend.mem_write(0x1200 - 8, &0x7003_0002u64.to_le_bytes()).unwrap();
        backend.mem_write(0x1300 - 16, &2.25f64.to_le_bytes()).unwrap();

        let mut va64 = [0u8; 32];
        va64[0..8].copy_from_slice(&0x1400u64.to_le_bytes()); // stack
        va64[8..16].copy_from_slice(&0x1200u64.to_le_bytes()); // gr_top
        va64[16..24].copy_from_slice(&0x1300u64.to_le_bytes()); // vr_top
        va64[24..28].copy_from_slice(&(-16i32).to_le_bytes()); // gr_offs
        va64[28..32].copy_from_slice(&(-16i32).to_le_bytes()); // vr_offs
        backend.mem_write(0x1100, &va64).unwrap();

        let args64 = VaList::read(Arch::Arm64, &backend, 0x1100, "(IDLjava/lang/String;)V").unwrap();
        assert_eq!(
            args64,
            vec![
                JniArg::Int(99),
                JniArg::Double(2.25),
                JniArg::Object(0x7003_0002),
            ]
        );
    }
}
