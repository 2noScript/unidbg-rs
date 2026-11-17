use unidbg_api::arm::backend::Backend;
use unidbg_api::error::{Result, UnidbgError};

/// `LC_DYLD_CHAINED_FIXUPS` header and pointer-chain walker (`FixupChains`).
#[derive(Debug, Clone, Copy)]
pub struct ChainedFixupsHeader {
    pub fixups_version: u32,
    pub starts_offset: u32,
    pub imports_offset: u32,
    pub symbols_offset: u32,
    pub imports_count: u32,
    pub imports_format: u32,
    pub symbols_format: u32,
}

impl ChainedFixupsHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 28 {
            return Err(UnidbgError::ElfLoad("dyld_chained_fixups_header truncated".into()));
        }
        let u32_at = |off: usize| u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        Ok(Self {
            fixups_version: u32_at(0),
            starts_offset: u32_at(4),
            imports_offset: u32_at(8),
            symbols_offset: u32_at(12),
            imports_count: u32_at(16),
            imports_format: u32_at(20),
            symbols_format: u32_at(24),
        })
    }
}

pub struct FixupChains;

impl FixupChains {
    /// Apply `DYLD_CHAINED_PTR_64_OFFSET` rebase chain starting at `chain_start`.
    pub fn apply_64_rebase_chain(
        backend: &mut dyn Backend,
        base: u64,
        mut cur_addr: u64,
    ) -> Result<usize> {
        let mut count = 0usize;
        loop {
            let mut buf = [0u8; 8];
            backend.mem_read(cur_addr, &mut buf)?;
            let raw = u64::from_le_bytes(buf);
            let bind = (raw >> 63) & 1;
            let next = ((raw >> 51) & 0xfff) * 4;
            if bind == 0 {
                let target = raw & 0x0000_000f_ffff_ffff;
                backend.mem_write(cur_addr, &(base + target).to_le_bytes())?;
                count += 1;
            }
            if next == 0 {
                break;
            }
            cur_addr += next;
        }
        Ok(count)
    }
}
