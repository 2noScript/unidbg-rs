# unidbg-rs

[![CI](https://github.com/2noScript/unidbg-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/2noScript/unidbg-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/unidbg-android.svg)](https://crates.io/crates/unidbg-android)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

An **idiomatic Rust** port of [**unidbg**](https://github.com/zhkl0228/unidbg) — an ARM32 / Thumb / ARM64 emulator for Android ELF binaries/libraries and iOS Mach-O binaries/frameworks, without requiring a JVM.

---

## Features (Parity with `unidbg`)

### Core Framework (`unidbg-api`)
- **CPU & Memory Abstraction**: `Backend` trait, `EmulatorCore`, `MemoryManager` (`rangemap`-backed `mmap`, `munmap`, `mprotect`, `brk`, `malloc`/`free` with `alloc_size` tracking), and `UnidbgPointer` (32/64-bit).
- **SVC Bridge (`ArmSvcMemory`)**: Generates ARM64 (`SVC #imm; RET`) and ARM32/Thumb (`SVC #0; BX LR`) trampolines for hooking native symbols and JNI callbacks.
- **Tracing & Disassembly**: `AssemblyCodeDumper` (`capstone`-powered ARM32/Thumb/ARM64 disassembly), `TraceMemoryHook` (filtered `READ`/`WRITE` tracing), and `RegAccessPrinter`.
- **Hooking & Unwinding**: `InlineHook` (pure-Rust ARM64 & ARM32 trampolines), `SimpleArmUnwinder` / `SimpleArm64Unwinder` with `cpp_demangle` C++ symbol demangling.
- **Debugging & Concurrency**:
  - `GdbServer`: GDB Remote Serial Protocol (RSP) over TCP (`?`, `qSupported`, `g`, `m`, `M`, `Z0`, `z0`, `s`, `c`, `k`).
  - `WorkerPool`: Multi-threaded worker pool running independent emulator instances per thread.
  - Cooperative `UniThreadDispatcher`, `SignalOps`, and `FileSystem` / `FileIO` / `IOResolver` traits.

### Android Emulation (`unidbg-android`)
- **ELF32 / ELF64 Dynamic Linker (`AndroidElfLoader`)**:
  - `PT_LOAD` mapping with page alignment and `MemoryPerm` enforcement.
  - ARM64 & ARM32 relocations (`RELATIVE`, `GLOB_DAT`, `JUMP_SLOT`, `ABS64`/`ABS32`, `IRELATIVE`/IFUNC, `DT_RELR`).
  - `.preinit_array`, `.init`, `.init_array` (including topological dependency initialization on ARM64) and `ET_EXEC` / PIE `call_entry`.
  - Virtual linker & allocator hooks: `dlopen`, `dlsym`, `malloc`, `calloc`, `realloc`, `free`, `__system_property_get`.
- **Linux Syscalls & VFS (`LinuxFileSystem`)**:
  - ARM32 EABI and ARM64 `asm-generic` syscall dispatchers (`openat`, `read`, `write`, `lseek`, `fstat`, `newfstatat`, `mmap`, `munmap`, `mprotect`, `brk`, `pipe2`, `uname`, `clock_gettime`, `gettimeofday`, `getrandom`, `clone` + `run_threads()`, `futex`, `exit`/`exit_group`, etc.).
  - Virtual files (`/dev/urandom`, `/dev/null`, `/dev/zero`, `/proc/self/maps`, `/proc/self/cmdline`, `/proc/cpuinfo`, `/proc/meminfo`, custom `IOResolver`s).
- **DalvikVM & JNI Bridge (`dvm`)**:
  - `DalvikVM` (32-bit & 64-bit) with `JavaVM` + 233-entry `JNIEnv` table, `LocalRef`/`GlobalRef`, `RegisterNatives`, `DvmClass` inheritance (`GetSuperclass`), `DvmObject` (`String`, `ByteArray`, `IntArray`, `ObjectArray`, `Boolean`, `Int`, `Long`).
  - AAPCS32 & AAPCS64 `VaList` argument decoding.
  - `Jni` trait with fail-soft `AbstractJni` defaults and `ApkLibraryFile` (loading `.so` directly from `.apk` archives).
  - Virtual modules: `AndroidModule`, `JniGraphics`, `MediaNdkModule`, `SystemProperties`.
- **PLT/GOT Hooking**: `XHook` (`register` + `refresh`).

### iOS Emulation (`unidbg-ios`)
- **Mach-O & Dyld (`MachOLoader`)**: Mach-O 32/64 and Fat/Universal binary loading via `goblin::mach`, plus `FixupChains` (`apply_64_rebase_chain`).
- **Darwin Syscalls & IPA (`IpaLoader`)**: BSD syscalls + Mach traps (`svc #0x80`) and `.ipa` / `Info.plist` parsing (`zip` + `plist`).
- **ObjC & Hooking**: `ObjcRuntime` (`objc_getClass`, `sel_registerName`, `objc_msgSend`), `FishHook`, and `Substrate`.

### CPU Backends
| Backend | Crate | Status |
| :--- | :--- | :--- |
| **Unicorn2** (`unicorn-engine`) | `backend/unicorn2` | Ready (ARM32, Thumb, ARM64) |
| **Apple Hypervisor** (`Hypervisor.framework`) | `backend/hypervisor` | Experimental (macOS Apple Silicon ARM64) |
| **Dynarmic** | `backend/dynarmic` | Planned (Phase 7) |
| **Linux KVM** | `backend/kvm` | Planned (Phase 7) |

---

## Workspace Structure

```text
unidbg-rs/
├── crates/
│   ├── unidbg-api/        # Core traits, memory, SVC, hooks, trace, GDB RSP, worker pool
│   ├── unidbg-android/    # Android ELF loader, Linux syscalls, VFS, DalvikVM/JNI, XHook
│   ├── unidbg-ios/        # Mach-O loader, Darwin syscalls, IPA loader, ObjC, FishHook/Substrate
│   └── unidbg-cli/        # CLI tool (`exec`, `jni`, `gdb`)
├── backend/
│   ├── unicorn2/          # Unicorn Engine 2 backend
│   ├── hypervisor/        # macOS Hypervisor.framework backend
│   ├── dynarmic/          # Dynarmic backend (WIP)
│   └── kvm/               # Linux KVM backend (WIP)
├── docs/                  # Architecture, crate mapping, and roadmap checklists
└── unidbg/                # Upstream Java unidbg submodule (zhkl0228/unidbg)
```

---

## Getting Started

### Prerequisites
- Rust toolchain (stable, Edition 2021+)
- C/C++ toolchain & CMake (required by `unicorn-engine` / `capstone` sys crates)

### Clone & Test

```bash
git clone --recursive https://github.com/2noScript/unidbg-rs.git
cd unidbg-rs
cargo test --workspace
```

*(If you already cloned without `--recursive`, run `git submodule update --init --recursive` to fetch `unidbg/` resources used by integration tests.)*

### Use as a Cargo Dependency

Add the crates you need from [crates.io](https://crates.io/crates/unidbg-android) in your `Cargo.toml`:

```toml
[dependencies]
unidbg-api = "0.1"
unidbg-android = "0.1"
unidbg-unicorn2 = "0.1"
# For iOS emulation:
# unidbg-ios = "0.1"
```

Or install the CLI directly:

```bash
cargo install unidbg-cli
```

*(Alternatively, to track the latest development commits on GitHub, use `{ git = "https://github.com/2noScript/unidbg-rs", branch = "main" }` consistently across all `unidbg-*` crates rather than mixing `crates.io` and `git` sources.)*

### Quick Example (Rust)

```rust
use unidbg_android::dvm::vm::DalvikVM;
use unidbg_android::emulator::AndroidEmulatorBuilder;
use unidbg_android::resolver::AndroidResolver;
use unidbg_api::arm::{Arch, ArmMode};
use unidbg_unicorn2::unicorn_backend::UnicornBackend;

let backend = Box::new(UnicornBackend::new(Arch::Arm64, ArmMode::Arm64)?);
let mut emu = AndroidEmulatorBuilder::for_64_bit()
    .process_name("com.example.app")
    .resolver(AndroidResolver::new(23, Arch::Arm64, "unidbg/unidbg-android/src/main/resources/android"))
    .build(backend)?;

let vm = DalvikVM::init(&mut emu)?;
let module = emu.load_library("path/to/libnative.so", true)?;
emu.call_init_functions(&module)?;
let jni_ver = vm.call_jni_onload(&mut emu, &module)?;
```

### CLI Usage (`unidbg-cli`)

```bash
# Run an ELF executable
cargo run -p unidbg-cli -- exec path/to/binary --arch arm64

# Call a JNI method
cargo run -p unidbg-cli -- jni path/to/libnative-lib.so --arch arm32 \
  --call Java_com_kanxue_test2_MainActivity_stringFromJNI

# Start a GDB RSP server
cargo run -p unidbg-cli -- gdb path/to/binary --arch arm64 --port 2345
```

---

## Documentation
- [Architecture Overview](docs/00-overview-and-architecture.md)
- [Rust Ecosystem & Crate Mapping](docs/01-ecosystem-and-crate-mapping.md)
- [Roadmap & Progress Checklists](docs/02-roadmap-and-checklists.md)
- [Structure Mapping (`unidbg` -> `unidbg-rs`)](docs/03-unidbg-structure-mapping.md)

## License & Attribution
- Licensed under the **Apache-2.0** License.
- Built with reference to [**zhkl0228/unidbg**](https://github.com/zhkl0228/unidbg).
