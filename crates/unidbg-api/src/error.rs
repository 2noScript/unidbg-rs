use crate::arm::backend::MemoryPerm;
use thiserror::Error;

/// Unified error type for `unidbg-rs`.
#[derive(Debug, Error)]
pub enum UnidbgError {
    #[error("invalid memory access at {addr:#x} (size={size}, perm={perm:?})")]
    InvalidMemoryAccess {
        addr: u64,
        size: usize,
        perm: MemoryPerm,
    },

    #[error("emulator stopped with status {0}")]
    StopEmulator(i64),

    #[error("long jump triggered")]
    LongJump,

    #[error("unhandled syscall number {0}")]
    UnhandledSyscall(u64),

    #[error("backend error: {0}")]
    Backend(String),

    #[error("ELF load error: {0}")]
    ElfLoad(String),

    #[error("JNI error: {0}")]
    Jni(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, UnidbgError>;
