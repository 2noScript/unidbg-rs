use crate::syscall::AndroidSyscallHandler;
use unidbg_api::arm::backend::{ArmReg, Backend};
use unidbg_api::error::{Result, UnidbgError};
use unidbg_api::memory::MemoryManager;

pub fn dispatch(
    h: &mut AndroidSyscallHandler,
    backend: &mut dyn Backend,
    memory: &mut MemoryManager,
) -> Result<()> {
    let nr = backend.reg_read(ArmReg::R7 as u32)?;
    let r0 = backend.reg_read(ArmReg::R0 as u32)?;
    let r1 = backend.reg_read(ArmReg::R1 as u32)?;
    let r2 = backend.reg_read(ArmReg::R2 as u32)?;

    let ret: i64 = match nr {
        1 | 248 => return Err(UnidbgError::StopEmulator(r0 as i64)), // exit / exit_group
        3 => h.sys_read(backend, r0 as i32, r1, r2 as usize)?,       // read
        4 => h.sys_write(backend, r0 as i32, r1, r2 as usize)?,      // write
        5 => h.sys_openat(backend, memory, -100, r0, r1 as u32)?,    // open
        6 => h.sys_close(r0 as i32)?,                                // close
        19 => h.sys_lseek(r0 as i32, r1 as i64, r2 as i32)?,         // lseek
        20 => h.pid as i64,                                          // getpid
        23 | 46 | 70 | 71 | 208 | 210 | 213 | 214 => 0,              // setuid / setgid / setre* / set*32
        24 | 47 | 49 | 50 | 199 | 200 | 201 | 202 => 1000,           // getuid/getgid/geteuid/getegid (16 & 32)
        45 => h.sys_brk(backend, memory, r0)?,                       // brk
        76 | 191 => 0,                                               // getrlimit / ugetrlimit
        91 => h.sys_munmap(backend, memory, r0, r1 as usize)?,       // munmap
        122 => h.sys_uname(backend, r0)?,                            // uname
        125 => h.sys_mprotect(backend, memory, r0, r1 as usize, r2)?,// mprotect
        172 | 174 | 175 | 186 | 220 => 0,                            // prctl / rt_sigaction / rt_sigprocmask / sigaltstack / madvise
        192 => h.sys_mmap(backend, memory, r0, r1 as usize, r2)?,    // mmap2
        197 => 0,                                                    // fstat64
        224 => h.tid as i64,                                         // gettid
        240 => 0,                                                    // futex
        256 => h.tid as i64,                                         // set_tid_address
        263 => h.sys_clock_gettime(backend, r1)?,                    // clock_gettime
        322 => h.sys_openat(backend, memory, r0 as i32, r1, r2 as u32)?, // openat
        334 => 0,                                                    // faccessat
        359 => h.sys_pipe2(backend, r0)?,                            // pipe2
        384 => h.sys_getrandom(backend, r0, r1 as usize)?,           // getrandom
        0xf0005 => h.sys_set_tls(backend, r0)?,                      // ARM_NR_set_tls
        _ => {
            tracing::warn!(nr, r0, r1, r2, "unhandled ARM32 syscall -> -ENOSYS");
            -38 // -ENOSYS
        }
    };

    backend.reg_write(ArmReg::R0 as u32, ret as u64)?;
    Ok(())
}
