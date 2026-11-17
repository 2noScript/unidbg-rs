use crate::syscall::AndroidSyscallHandler;
use unidbg_api::arm::backend::{Arm64Reg, Backend};
use unidbg_api::error::{Result, UnidbgError};
use unidbg_api::memory::MemoryManager;

pub fn dispatch(
    h: &mut AndroidSyscallHandler,
    backend: &mut dyn Backend,
    memory: &mut MemoryManager,
) -> Result<()> {
    let nr = backend.reg_read(Arm64Reg::X8 as u32)?;
    let x0 = backend.reg_read(Arm64Reg::X0 as u32)?;
    let x1 = backend.reg_read(Arm64Reg::X1 as u32)?;
    let x2 = backend.reg_read(Arm64Reg::X2 as u32)?;
    let x3 = backend.reg_read(Arm64Reg::X3 as u32)?;

    let ret: i64 = match nr {
        34 => 0,                                        // mkdirat
        48 | 439 => 0,                                  // faccessat / faccessat2
        56 => h.sys_openat(backend, memory, x0 as i32, x1, x2 as u32)?, // openat
        57 => h.sys_close(x0 as i32)?,                  // close
        59 => h.sys_pipe2(backend, x0)?,                // pipe2
        62 => h.sys_lseek(x0 as i32, x1 as i64, x2 as i32)?, // lseek
        63 => h.sys_read(backend, x0 as i32, x1, x2 as usize)?, // read
        64 => h.sys_write(backend, x0 as i32, x1, x2 as usize)?, // write
        79 => h.sys_newfstatat(backend, x0 as i32, x1, x2)?, // newfstatat
        80 => h.sys_fstat(backend, x0 as i32, x1)?,           // fstat
        93 | 94 => return Err(UnidbgError::StopEmulator(x0 as i64)), // exit / exit_group
        96 => h.tid as i64,                             // set_tid_address
        98 => {                                         // futex
            let op = x1 as u32 & 0x7f;
            if op == 0 /* FUTEX_WAIT */ && *h.in_spawned_thread.borrow() {
                return Err(UnidbgError::StopEmulator(0));
            }
            0
        }
        99 => 0,                                        // set_robust_list
        101 => {                                        // nanosleep
            if *h.in_spawned_thread.borrow() {
                return Err(UnidbgError::StopEmulator(0));
            }
            0
        }
        113 => h.sys_clock_gettime(backend, x1)?,       // clock_gettime
        131 => 0,                                       // tgkill
        132 => 0,                                       // sigaltstack
        134 | 135 => 0,                                 // rt_sigaction / rt_sigprocmask
        143..=149 => 0,                                 // setregid / setgid / setreuid / setuid / setresuid / setresgid
        160 => h.sys_uname(backend, x0)?,               // uname
        167 => 0,                                       // prctl
        169 => h.sys_gettimeofday(backend, x0)?,        // gettimeofday
        172 => h.pid as i64,                            // getpid
        174 | 175 | 176 | 177 => 1000,                  // getuid/geteuid/getgid/getegid
        178 => h.tid as i64,                            // gettid
        214 => h.sys_brk(backend, memory, x0)?,         // brk
        215 => h.sys_munmap(backend, memory, x0, x1 as usize)?, // munmap
        220 => {                                        // clone
            const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
            const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
            let x4 = backend.reg_read(Arm64Reg::X4 as u32)?;
            let x5 = backend.reg_read(Arm64Reg::X5 as u32)?;
            let x6 = backend.reg_read(Arm64Reg::X6 as u32)?;
            let new_tid = h.next_tid();
            if (x0 & CLONE_PARENT_SETTID) != 0 && x2 != 0 {
                backend.mem_write(x2, &new_tid.to_le_bytes())?;
            }
            if ((x0 & CLONE_CHILD_SETTID) != 0 || x4 != 0) && x4 != 0 {
                backend.mem_write(x4, &new_tid.to_le_bytes())?;
            }
            if x5 != 0 {
                h.pending_threads.borrow_mut().push(crate::syscall::ClonedThread {
                    tid: new_tid,
                    fn_addr: x5,
                    arg: x6,
                    ctid: x4,
                    tls: x3,
                });
            }
            new_tid as i64
        }
        222 => h.sys_mmap(backend, memory, x0, x1 as usize, x2)?, // mmap
        226 => h.sys_mprotect(backend, memory, x0, x1 as usize, x2)?, // mprotect
        278 => h.sys_getrandom(backend, x0, x1 as usize)?, // getrandom
        _ => {
            tracing::warn!(nr, x0, x1, x2, x3, "unhandled ARM64 syscall -> -ENOSYS");
            -38 // -ENOSYS
        }
    };

    backend.reg_write(Arm64Reg::X0 as u32, ret as u64)?;
    Ok(())
}
