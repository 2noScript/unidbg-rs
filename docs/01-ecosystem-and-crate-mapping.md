# Rust Ecosystem Crate Mapping (`unidbg` -> `unidbg-rs`)

Mapping of all `unidbg` dependencies and components to standard `crates.io` crates (zero dependency on `rnidbg`).

---

## 1. Dependency & Crate Mapping

| Component in `unidbg` (Java) | Original Java Library | Equivalent Rust Crate | Notes |
| :--- | :--- | :--- | :--- |
| **Unicorn CPU Backend** | `unicorn` 1.0.15 / `unidbg-unicorn2` | `unicorn-engine` | Built-in support for ARM32, Thumb, and ARM64 |
| **Dynarmic CPU Backend** | `unidbg-dynarmic` (JNI + C++) | Custom C-ABI + `cmake`/`cc` | Uses `unidbg/backend/dynarmic/src/main/native` with a C wrapper instead of JNI |
| **Hypervisor / KVM** | `unidbg-hypervisor`, `unidbg-kvm` | `applevisor` / `Hypervisor.framework` (macOS), `kvm-ioctls` (Linux) | Hardware-assisted backends (Phase 7) |
| **Disassembler** | `capstone` 3.1.8 | `capstone` | ARM32, Thumb, and ARM64 parity with `unidbg` |
| **Assembler** | `keystone` 0.9.7 | `keystone-engine` | Optional/supplementary for dynamic assembly |
| **ELF Parser** | `net.fornwall.jelf` | `goblin` (`elf` feature) | Parses ELF32/ELF64, program headers, sections, dynamic symbols, relocations |
| **Mach-O Parser (iOS)** | `MachOLoader` + `kaitai-struct` | `goblin` (`mach` feature) | Parses Mach-O 32/64 & Fat binaries; custom `DyldChainedFixups` |
| **APK / IPA Archive** | `apk-parser` 2.6.10 | `zip` (+ optional `abxml`) | Reads `lib/<abi>/*.so` directly from `.apk` |
| **Plist Parser (iOS)** | `dd-plist` 1.29 | `plist` | Reads XML & binary `Info.plist` inside `.ipa` |
| **C++ Demangler** | `demumble` 1.0.4 | `cpp_demangle` | Pure Rust, no C++ FFI needed |
| **DWARF Unwind (optional)** | *(FP walk)* | `gimli` | Parses `.eh_frame` when frame pointers are omitted |
| **Memory Interval Map** | `SparseList` | `rangemap` | Standard `rangemap::RangeMap`, zero-unsafe, supports interval split/merge |
| **GDB Remote Stub** | `debugger/gdb` (custom) | `gdbstub` / custom RSP | ARM & AArch64 RSP support for GDB/LLDB/IDA |
| **JSON / Serialization** | `fastjson` 2.0.65 | `serde` + `serde_json` | Config, trace dumps, crash reports |
| **Logging & Diagnostics** | `slf4j` + `log4j` | `tracing` + `tracing-subscriber` | Structured logging, dynamic filtering via `RUST_LOG` |
| **Error Handling** | Java Exceptions | `thiserror` (lib) + `anyhow` (CLI) | Strongly-typed `UnidbgError` |
| **CLI** | Java `main` | `clap` (derive) | Subcommands `exec`, `jni`, `gdb` |
| **Bitflags & Struct Mapping** | `ByteBuffer`, bitmasks | `bitflags`, `bytes`, `zerocopy` | Safe C struct read/write (ELF, `stat`, `sigaction`, `prop_info`) |
| **Worker Pool** | `worker/WorkerPool` | `std::thread` / `crossbeam-channel` | Runs multiple `Emulator` instances concurrently across threads |

---

## 2. Core Subsystems Ported Directly from `unidbg`

1. **`ArmSvcMemory`**: Allocates pages containing SVC stubs (`SVC #imm; RET` on ARM64, `SVC #0; BX LR` on ARM32/Thumb) for JNI, `dlopen`/`dlsym`, and virtual modules.
2. **ELF Relocations & Dynamic Linker (`AndroidElfLoader`)**: Uses `goblin` for parsing, with custom logic for `PT_LOAD` mapping, `DT_RELR`, `R_AARCH64_IRELATIVE` (IFUNC), `R_AARCH64_TLS_TPREL`, `PT_TLS`, `.init_array`, and `ArmLd` (`dlopen`/`dlsym`/`malloc`/`calloc`/`realloc`/`free`).
3. **Linux/Darwin Syscalls & VFS**: ARM32 EABI, ARM64 `asm-generic`, Darwin BSD/Mach syscalls, and virtual `FileIO` (`/proc/self/maps`, `/dev/urandom`, `ashmem`, `pipe2`, etc.).
4. **Dalvik VM & JNI Bridge**: `DalvikVM` (32/64-bit), `VaList` (AAPCS32/64), `JNIEnv` dispatch table, `Jni` trait (fail-soft `AbstractJni` defaults), `DvmClass`/`DvmObject`.
5. **Inline Hooking (`XHook`, `InlineHook`, `FishHook`, `Substrate`)**: `capstone`-guided instruction checks and native trampolines.
