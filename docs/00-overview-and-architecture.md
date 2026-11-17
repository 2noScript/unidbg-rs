# `unidbg-rs` Architecture Overview (Idiomatic Rust Port of `unidbg`)

Design principles of **`unidbg-rs`**:
1. **100% behavioral and architectural parity with `unidbg` (Java)** across modules, execution flow, features, and naming.
2. **Idiomatic Rust** (not a mechanical 1:1 translation of Java OOP): collapse boilerplate hierarchies (`Abstract*`, `Base*`, `I*`, `*Impl`) into clean `trait` + `struct` pairs, use `Result`/`Option`, drop `get_` prefixes, and rely on RAII `Drop` and clear ownership.
3. **Zero dependency on `rnidbg`**: built independently on top of `unidbg` and standard Rust ecosystem crates (`unicorn-engine`, `capstone`, `keystone-engine`, `goblin`, `rangemap`, `gdbstub`, `tracing`, `thiserror`).

---

## 1. Cargo Workspace Layout (`unidbg` -> `unidbg-rs`)

Directly mapped from [`unidbg/pom.xml`](../unidbg/pom.xml):

| `unidbg` Module | `unidbg-rs` Crate | Role |
| :--- | :--- | :--- |
| `unidbg-api` | `crates/unidbg-api` | Core API: `Emulator`, `Memory`, `ArmSvcMemory`, `Backend` trait, `Debugger`, `FileSystem`, `Hook`, `ThreadDispatcher`, `SignalOps`, `Unwinder`, `WorkerPool` |
| `unidbg-android` | `crates/unidbg-android` | `AndroidEmulator`, `AndroidElfLoader`, `Arm32SyscallHandler`, `Arm64SyscallHandler`, `LinuxFileSystem`, `DalvikVM` (32/64), `XHook`, `AndroidUnwinder` |
| `unidbg-ios` | `crates/unidbg-ios` | `DarwinEmulator`, `MachOLoader`, `Dyld32/64`, `FixupChains`, `DarwinSyscallHandler`, `ObjC`, `FishHook`, `Substrate` |
| `backend/unicorn2` | `backend/unicorn2` | `UnicornBackend` powered by `unicorn-engine` (ARM32 + Thumb + ARM64) |
| `backend/dynarmic` | `backend/dynarmic` | C-ABI wrapper + `build.rs` around `unidbg/backend/dynarmic/src/main/native` |
| `backend/hypervisor` | `backend/hypervisor` | Apple `Hypervisor.framework` backend (macOS Apple Silicon) |
| `backend/kvm` | `backend/kvm` | Linux KVM backend (ARM64) |
| *(CLI)* | `crates/unidbg-cli` | CLI runner (`exec`, `jni`, `gdb`) |

---

## 2. Idiomatic Rust Conventions

1. **Collapse Java boilerplate (`I*`, `Abstract*`, `Base*`, `*Impl`) into concise `trait` + `struct` pairs**:
   - Java's `Emulator.java`, `AbstractEmulator.java`, `ARMEmulator.java`, `AbstractARMEmulator.java` → `emulator.rs` (`pub trait Emulator` + `pub struct EmulatorCore`).
   - `IxHook.java` + `XHookImpl.java` → `xhook.rs` (`pub struct XHook`).
   - `FileIO.java` + `AbstractFileIO.java` + `BaseFileIO.java` → `file/mod.rs` (`pub trait FileIO`).
2. **Rust-standard naming & return types**:
   - Drop `get_` prefixes: `memory()`, `backend()`, `pid()`, `name()`, `base()`, `size()` (keep `set_*` for setters).
   - Use `Result<T, UnidbgError>` and `Option<T>` instead of `null`, exceptions (`StopEmulatorException`, `LongJumpException`), or `-1` sentinels.
   - Use `enum` and `bitflags!`: `Arch::Arm32 | Arch::Arm64`, `MemoryPerm`, `Family::Android32 | Android64 | Ios32 | Ios64`.
   - Use `&[u8]`, `&mut [u8]`, `&str`, `impl AsRef<Path>` instead of `byte[]`, `String`, `File`.
3. **RAII (`Drop`) & clean ownership**:
   - Rely on `Drop` for automatic resource cleanup instead of mandatory `close()`/`destroy()`.
   - Separate `Backend` (CPU/RAM) from `RuntimeContext` (VFS, threads, DVM), passing context explicitly into callbacks/syscalls to avoid circular references and unnecessary `UnsafeCell`.
