use crate::arm::backend::{Arm64Reg, ArmReg, Backend, MemoryPerm};
use crate::arm::Arch;
use crate::error::{Result, UnidbgError};
use crate::pointer::UnidbgPointer;
use rangemap::RangeMap;

pub const PAGE_SIZE: usize = 0x1000;

#[inline]
pub fn align_up(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

#[inline]
pub fn align_down(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    value & !(align - 1)
}

/// Mapped memory region metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryMap {
    pub base: u64,
    pub size: usize,
    pub perm: MemoryPerm,
}

/// Heap-allocated block returned by [`Memory::malloc`].
#[derive(Debug, PartialEq, Eq)]
pub struct MemoryBlock {
    pub addr: u64,
    pub size: usize,
}

impl MemoryBlock {
    pub fn pointer(&self, pointer_size: usize) -> UnidbgPointer {
        UnidbgPointer::new(self.addr, pointer_size)
    }
}

/// Guest virtual memory manager trait.
pub trait Memory {
    fn allocate_stack(&mut self, backend: &mut dyn Backend, size: usize) -> Result<u64>;
    fn set_stack_point(&mut self, backend: &mut dyn Backend, sp: u64) -> Result<()>;
    fn stack_point(&self) -> u64;

    fn mmap(&mut self, backend: &mut dyn Backend, start: u64, length: usize, perm: MemoryPerm) -> Result<u64>;
    fn munmap(&mut self, backend: &mut dyn Backend, start: u64, length: usize) -> Result<()>;
    fn mprotect(&mut self, backend: &mut dyn Backend, start: u64, length: usize, perm: MemoryPerm) -> Result<()>;

    fn malloc(&mut self, backend: &mut dyn Backend, length: usize, runtime: bool) -> Result<MemoryBlock>;
    fn free(&mut self, block: MemoryBlock) -> Result<()>;

    fn brk(&mut self, backend: &mut dyn Backend, addr: u64) -> Result<u64>;
    fn pointer(&self, addr: u64) -> UnidbgPointer;
    fn memory_maps(&self) -> Vec<MemoryMap>;
}

/// Default virtual memory manager backed by [`rangemap::RangeMap`].
pub struct MemoryManager {
    arch: Arch,
    pointer_size: usize,
    regions: RangeMap<u64, MemoryPerm>,
    mmap_base: u64,
    mmap_end: u64,
    stack_base: u64,
    sp: u64,
    heap_base: u64,
    heap_cursor: u64,
    heap_mapped_end: u64,
    free_list: Vec<(u64, usize)>,
    alloc_sizes: std::collections::HashMap<u64, usize>,
    brk_base: u64,
    brk_cur: u64,
}

impl MemoryManager {
    pub fn new(arch: Arch) -> Self {
        let (pointer_size, mmap_base, mmap_end, stack_base, heap_base, brk_base) = match arch {
            Arch::Arm32 => (
                4,
                0x4000_0000,
                0xb000_0000,
                0xbfff_0000,
                0x2000_0000,
                0x3000_0000,
            ),
            Arch::Arm64 => (
                8,
                0x4000_0000,
                0x7fff_0000_0000,
                0x7fff_ff00_0000,
                0x2000_0000,
                0x3000_0000,
            ),
        };
        Self {
            arch,
            pointer_size,
            regions: RangeMap::new(),
            mmap_base,
            mmap_end,
            stack_base,
            sp: 0,
            heap_base,
            heap_cursor: heap_base,
            heap_mapped_end: heap_base,
            free_list: Vec::new(),
            alloc_sizes: std::collections::HashMap::new(),
            brk_base,
            brk_cur: brk_base,
        }
    }

    pub fn alloc_size(&self, addr: u64) -> Option<usize> {
        self.alloc_sizes.get(&addr).copied()
    }

    pub fn pointer_size(&self) -> usize {
        self.pointer_size
    }

    fn map_region(&mut self, backend: &mut dyn Backend, addr: u64, size: usize, perm: MemoryPerm) -> Result<()> {
        backend.mem_map(addr, size, perm)?;
        self.regions.insert(addr..addr + size as u64, perm);
        Ok(())
    }

    fn coalesce_free_list(&mut self) {
        self.free_list.sort_by_key(|(addr, _)| *addr);
        let mut merged: Vec<(u64, usize)> = Vec::with_capacity(self.free_list.len());
        for (addr, size) in self.free_list.drain(..) {
            if let Some((last_addr, last_size)) = merged.last_mut() {
                if *last_addr + (*last_size as u64) == addr {
                    *last_size += size;
                    continue;
                }
            }
            merged.push((addr, size));
        }
        self.free_list = merged;
    }
}

impl Memory for MemoryManager {
    fn allocate_stack(&mut self, backend: &mut dyn Backend, size: usize) -> Result<u64> {
        let aligned = align_up(size as u64, PAGE_SIZE as u64) as usize;
        let base = self.stack_base - aligned as u64;
        self.map_region(backend, base, aligned, MemoryPerm::READ | MemoryPerm::WRITE)?;
        let top = self.stack_base;
        self.set_stack_point(backend, top)?;
        Ok(top)
    }

    fn set_stack_point(&mut self, backend: &mut dyn Backend, sp: u64) -> Result<()> {
        self.sp = sp;
        let reg = match self.arch {
            Arch::Arm32 => ArmReg::SP as u32,
            Arch::Arm64 => Arm64Reg::SP as u32,
        };
        backend.reg_write(reg, sp)
    }

    fn stack_point(&self) -> u64 {
        self.sp
    }

    fn mmap(&mut self, backend: &mut dyn Backend, start: u64, length: usize, perm: MemoryPerm) -> Result<u64> {
        if length == 0 {
            return Err(UnidbgError::Backend("mmap length cannot be zero".into()));
        }
        let aligned_len = align_up(length as u64, PAGE_SIZE as u64) as usize;

        let addr = if start == 0 {
            self.regions
                .gaps(&(self.mmap_base..self.mmap_end))
                .find(|gap| (gap.end - gap.start) >= aligned_len as u64)
                .map(|gap| gap.start)
                .ok_or_else(|| UnidbgError::Backend("out of mmap address space".into()))?
        } else {
            let aligned_start = align_down(start, PAGE_SIZE as u64);
            let end = aligned_start + aligned_len as u64;
            if self.regions.overlaps(&(aligned_start..end)) {
                self.munmap(backend, aligned_start, aligned_len)?;
            }
            aligned_start
        };

        self.map_region(backend, addr, aligned_len, perm)?;
        Ok(addr)
    }

    fn munmap(&mut self, backend: &mut dyn Backend, start: u64, length: usize) -> Result<()> {
        if length == 0 {
            return Ok(());
        }
        let aligned_start = align_down(start, PAGE_SIZE as u64);
        let aligned_len = align_up((start - aligned_start) + length as u64, PAGE_SIZE as u64) as usize;
        let end = aligned_start + aligned_len as u64;

        let overlapping: Vec<(u64, u64)> = self
            .regions
            .overlapping(aligned_start..end)
            .map(|(r, _)| (r.start.max(aligned_start), r.end.min(end)))
            .collect();

        for (seg_start, seg_end) in overlapping {
            backend.mem_unmap(seg_start, (seg_end - seg_start) as usize)?;
        }
        self.regions.remove(aligned_start..end);
        Ok(())
    }

    fn mprotect(&mut self, backend: &mut dyn Backend, start: u64, length: usize, perm: MemoryPerm) -> Result<()> {
        if length == 0 {
            return Ok(());
        }
        let aligned_start = align_down(start, PAGE_SIZE as u64);
        let aligned_len = align_up((start - aligned_start) + length as u64, PAGE_SIZE as u64) as usize;
        let end = aligned_start + aligned_len as u64;

        backend.mem_protect(aligned_start, aligned_len, perm)?;
        self.regions.insert(aligned_start..end, perm);
        Ok(())
    }

    fn malloc(&mut self, backend: &mut dyn Backend, length: usize, _runtime: bool) -> Result<MemoryBlock> {
        let aligned = align_up(length.max(1) as u64, 16) as usize;

        if let Some(pos) = self.free_list.iter().position(|(_, sz)| *sz >= aligned) {
            let (addr, sz) = self.free_list.remove(pos);
            if sz > aligned {
                self.free_list.push((addr + aligned as u64, sz - aligned));
            }
            self.alloc_sizes.insert(addr, aligned);
            return Ok(MemoryBlock {
                addr,
                size: aligned,
            });
        }

        let addr = self.heap_cursor;
        let next = addr + aligned as u64;
        if next > self.heap_mapped_end {
            let need = align_up(next - self.heap_mapped_end, PAGE_SIZE as u64) as usize;
            self.map_region(
                backend,
                self.heap_mapped_end,
                need,
                MemoryPerm::READ | MemoryPerm::WRITE,
            )?;
            self.heap_mapped_end += need as u64;
        }
        self.heap_cursor = next;
        self.alloc_sizes.insert(addr, aligned);
        Ok(MemoryBlock {
            addr,
            size: aligned,
        })
    }

    fn free(&mut self, block: MemoryBlock) -> Result<()> {
        if block.addr < self.heap_base || block.addr >= self.heap_cursor {
            return Err(UnidbgError::Backend(format!(
                "invalid free address {:#x}",
                block.addr
            )));
        }
        self.free_list.push((block.addr, block.size));
        self.coalesce_free_list();
        Ok(())
    }

    fn brk(&mut self, backend: &mut dyn Backend, addr: u64) -> Result<u64> {
        if addr == 0 {
            return Ok(self.brk_cur);
        }
        if addr > self.brk_cur {
            let cur_page = align_up(self.brk_cur, PAGE_SIZE as u64);
            let target_page = align_up(addr, PAGE_SIZE as u64);
            if target_page > cur_page {
                if self.regions.overlaps(&(cur_page..target_page)) {
                    return Ok(self.brk_cur);
                }
                self.map_region(
                    backend,
                    cur_page,
                    (target_page - cur_page) as usize,
                    MemoryPerm::READ | MemoryPerm::WRITE,
                )?;
            }
            self.brk_cur = addr;
        } else if addr >= self.brk_base {
            self.brk_cur = addr;
        }
        Ok(self.brk_cur)
    }

    fn pointer(&self, addr: u64) -> UnidbgPointer {
        UnidbgPointer::new(addr, self.pointer_size)
    }

    fn memory_maps(&self) -> Vec<MemoryMap> {
        self.regions
            .iter()
            .map(|(range, perm)| MemoryMap {
                base: range.start,
                size: (range.end - range.start) as usize,
                perm: *perm,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arm::backend::tests::MockBackend;

    #[test]
    fn mmap_munmap_split_and_mprotect() {
        let mut backend = MockBackend::new();
        let mut mem = MemoryManager::new(Arch::Arm64);

        let a = mem.mmap(&mut backend, 0, 0x3000, MemoryPerm::READ | MemoryPerm::WRITE).unwrap();
        let b = mem.mmap(&mut backend, 0, 0x1000, MemoryPerm::READ).unwrap();
        assert_eq!(a + 0x3000, b);

        // Unmap the middle page of region `a` -> splits into two maps
        mem.munmap(&mut backend, a + 0x1000, 0x1000).unwrap();
        mem.mprotect(&mut backend, b, 0x1000, MemoryPerm::READ | MemoryPerm::EXEC).unwrap();

        let maps = mem.memory_maps();
        assert_eq!(maps.len(), 3);
        assert_eq!(maps[0], MemoryMap { base: a, size: 0x1000, perm: MemoryPerm::READ | MemoryPerm::WRITE });
        assert_eq!(maps[1], MemoryMap { base: a + 0x2000, size: 0x1000, perm: MemoryPerm::READ | MemoryPerm::WRITE });
        assert_eq!(maps[2], MemoryMap { base: b, size: 0x1000, perm: MemoryPerm::READ | MemoryPerm::EXEC });
    }

    #[test]
    fn malloc_free_coalesce_and_stack() {
        let mut backend = MockBackend::new();
        let mut mem = MemoryManager::new(Arch::Arm64);

        let sp = mem.allocate_stack(&mut backend, 0x4000).unwrap();
        assert_eq!(backend.reg_read(Arm64Reg::SP as u32).unwrap(), sp);

        let b1 = mem.malloc(&mut backend, 32, false).unwrap();
        let b2 = mem.malloc(&mut backend, 64, false).unwrap();
        assert!(b1.addr + b1.size as u64 <= b2.addr);

        let b1_addr = b1.addr;
        mem.free(b1).unwrap();
        mem.free(b2).unwrap();

        // Coalesced block (32 + 64 = 96) should satisfy a 96-byte allocation at b1_addr
        let b3 = mem.malloc(&mut backend, 96, false).unwrap();
        assert_eq!(b3.addr, b1_addr);
    }
}
