# Changelog

All notable changes to `unidbg-rs` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-11-18

### Added
- **VFS Security & LogCat Containment (`unidbg-android`)**:
  - Synced with upstream `unidbg` `#795` (`d94dba1`): `LinuxFileSystem::resolve_contained_path` now enforces `rootDir` containment (blocking `..` traversal and symlink escapes with `-EACCES`) and supports `/dev/log/*` LogCat files under `rootDir`.
- **CI/CD & Crates.io Packaging**:
  - Added `.github/workflows/ci.yml` (Linux + macOS workspace tests) and `.github/workflows/publish.yml` (automated `crates.io` release on `v*` tags).
  - Updated `Cargo.toml` package metadata and internal crate versions to `0.1.1`.

## [0.1.0] - 2026-11-17

### Added
- **Core Framework (`unidbg-api`)**:
  - `Backend` trait, `EmulatorCore`, `MemoryManager` (`rangemap`-backed `mmap`/`munmap`/`mprotect`/`brk`/`malloc`/`free`), `UnidbgPointer`, and `RegisterContext` (`Arm32Context`, `Arm64Context`).
  - `ArmSvcMemory` with ARM64 (`SVC #imm; RET`) and ARM32/Thumb (`SVC #0; BX LR`) trampolines.
  - `AssemblyCodeDumper` (`capstone`), `TraceMemoryHook`, `RegAccessPrinter`, `InlineHook`, `SimpleArmUnwinder`/`SimpleArm64Unwinder` (`cpp_demangle`).
  - `GdbServer` (RSP over TCP), `WorkerPool`, `UniThreadDispatcher`, `SignalOps`, and `FileSystem`/`FileIO`/`IOResolver`.
- **Android Emulation (`unidbg-android`)**:
  - `AndroidElfLoader` (`goblin`) supporting ELF32/ELF64, `PT_LOAD`, ARM32/ARM64 relocations (`RELATIVE`, `GLOB_DAT`, `JUMP_SLOT`, `ABS*`, `IRELATIVE`, `DT_RELR`), `.init_array` dependency ordering, and `call_entry`.
  - `Arm32SyscallHandler` & `Arm64SyscallHandler` (`openat`, `read`, `write`, `fstat`, `newfstatat`, `mmap`, `brk`, `pipe2`, `uname`, `clock_gettime`, `gettimeofday`, `getrandom`, `clone` + `run_threads()`, `futex`, `exit`/`exit_group`, etc.) + `LinuxFileSystem` VFS.
  - `DalvikVM` (32/64-bit) with `JavaVM` + 233-entry `JNIEnv` table, `VaList`, `Jni` trait (`AbstractJni` defaults), `RegisterNatives`, `ApkLibraryFile`, `XHook`, and virtual modules (`AndroidModule`, `JniGraphics`, `MediaNdkModule`, `SystemProperties`).
- **iOS Emulation (`unidbg-ios`)**:
  - `MachOLoader` (32/64-bit & Fat/Universal Mach-O), `FixupChains`, Darwin BSD/Mach syscalls (`svc #0x80`), `IpaLoader` (`zip` + `plist`), `ObjcRuntime`, `FishHook`, and `Substrate`.
- **CLI & Backends**:
  - `unidbg-cli` (`exec`, `jni`, `gdb`).
  - `backend/unicorn2` (`UnicornBackend` for ARM32, Thumb, ARM64).
  - `backend/hypervisor` (`HypervisorBackend` for macOS Apple Silicon ARM64).
  - `backend/dynarmic` (C-ABI wrapper + `build.rs` for `DYNARMIC_HOME`) and `backend/kvm` (Linux AArch64 `/dev/kvm` ioctl backend).
- **Documentation & Licensing**:
  - `README.md`, `LICENSE` (`Apache-2.0`), and English architecture/mapping/roadmap docs in `docs/`.

### Notes
- `cargo test --workspace` passes all **41/41** tests with 0 warnings on macOS Apple Silicon (`UnicornBackend` + `HypervisorBackend`).
- Runtime execution tests for `DynarmicBackend` (requires `DYNARMIC_HOME`) and `KvmBackend` (requires Linux AArch64 `/dev/kvm`) remain pending on those target environments.
