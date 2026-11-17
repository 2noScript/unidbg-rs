# `unidbg-rs` Roadmap & Progress Checklist

> **Rule**: Only mark `[x]` after the implementation **AND** its corresponding `Test & Check` pass. Zero dependency on `rnidbg`; `unidbg` is the reference specification, written in Idiomatic Rust.

## Master Checklist

- [x] **Phase 0**: Cargo Workspace, `UnidbgError`, `Backend` trait & `UnicornBackend`
- [x] **Phase 1**: `unidbg-api` (Pointer, Memory, `ArmSvcMemory`, Trace, Thread, Signal, Emulator)
- [x] **Phase 2**: `unidbg-android` Core (`AndroidElfLoader`, `LinuxFileSystem`, ARM32/ARM64 Syscalls, `ArmLd`, `SystemPropertyHook`)
- [x] **Phase 3**: `unidbg-android` DVM (`DalvikVM` 32/64, `VaList`, `Jni` trait, `ApkLibraryFile`)
- [x] **Phase 4**: Hooking (`XHook`, `InlineHook`) & Stack `Unwinder` + `cpp_demangle`
- [x] **Phase 5**: `GDBServer`, `WorkerPool`, `unidbg-cli`
- [x] **Phase 6**: `unidbg-ios` (Mach-O, `DarwinSyscall`, `IpaLoader`, `FishHook`, `Substrate`)
- [ ] **Phase 7**: Additional Backends (`backend/dynarmic`, `[x] backend/hypervisor`, `backend/kvm`)

---

## Phase 0: Workspace Skeleton & `UnicornBackend` [P0]

- [x] **0.1. Initialize Cargo Workspace**
  - [x] Create root `Cargo.toml` with workspace members: `crates/unidbg-api`, `crates/unidbg-android`, `crates/unidbg-cli`, `backend/unicorn2`.
  - [x] Create `Cargo.toml` + `src/lib.rs` skeletons for each crate.
  - [x] **Test & Check 0.1**: Run `cargo check --workspace` → exit code 0.

- [x] **0.2. `UnidbgError`, `MemoryPerm` & `Backend` Trait (`crates/unidbg-api`)**
  - [x] `crates/unidbg-api/src/error.rs`: define `UnidbgError` (`InvalidMemoryAccess`, `StopEmulator`, `LongJump`, `UnhandledSyscall`, `Backend`, `ElfLoad`, `Jni`, `Io`) and `Result<T>`.
  - [x] `crates/unidbg-api/src/arm/backend.rs`: define `MemoryPerm` (`bitflags!`), `ArmReg`, `Arm64Reg`, `HookId`, `MemAccessType`, and `pub trait Backend` (`reg_read/write`, `reg_read_vec/write_vec`, `mem_read/write`, `mem_map/unmap/protect`, `emu_start/stop`, `context_alloc/save/restore`, `hook_add_code/mem`, `hook_del`).
  - [x] **Test & Check 0.2**: `MockBackend` in `#[cfg(test)]`; run `cargo test -p unidbg-api` covering `mem_map`/`mem_write`/`mem_read`/`reg_read`/`reg_write`.

- [x] **0.3. Implement `UnicornBackend` (`backend/unicorn2`)**
  - [x] Add `unicorn-engine` to `backend/unicorn2/Cargo.toml`.
  - [x] Implement `unidbg_api::arm::backend::Backend` in `backend/unicorn2/src/unicorn_backend.rs` for both `Arch::Arm32` (ARM/Thumb) and `Arch::Arm64`.
  - [x] **Test & Check 0.3**:
    - [x] `cargo test -p unidbg-unicorn2 create_destroy_loop`: create & drop `UnicornBackend` 100 times consecutively with no crashes/leaks.
    - [x] `cargo test -p unidbg-unicorn2 run_arm64_add`: map `0x1000`, run `MOV X0, #10; ADD X0, X0, #32`, assert `X0 == 42`.
    - [x] `cargo test -p unidbg-unicorn2 run_arm32_add`: run both ARM and Thumb modes, assert `R0 == 42`.

---

## Phase 1: `unidbg-api` (Core Framework) [P0]

- [x] **1.1. `pointer.rs` (`UnidbgPointer` & `UnidbgStruct`)**
  - [x] Implement `UnidbgPointer` (4-byte & 8-byte pointers): `share`, `read_u8/u16/u32/u64/i32/i64/bytes/cstr`, `write_u32/u64/bytes/cstr`.
  - [x] Implement `UnidbgStruct` trait (`pack`, `unpack`).
  - [x] **Test & Check 1.1**: `cargo test -p unidbg-api pointer` passes on both 32-bit and 64-bit.

- [x] **1.2. `memory/mod.rs` (`Memory`, `MemoryMap`, `MemoryBlock`)**
  - [x] Use `rangemap::RangeMap` to track mapped regions and `MemoryPerm`.
  - [x] Implement `MemoryManager`: `allocate_stack`, `set_stack_point`, `mmap` (auto + fixed), `munmap`, `mprotect`, `malloc` / `free` (`MemoryBlock`), `brk`, `pointer`.
  - [x] **Test & Check 1.2**: `cargo test -p unidbg-api memory` tests auto `mmap`, `munmap` region splitting, `mprotect`, and non-overlapping `malloc`/`free`.

- [x] **1.3. `svc.rs` & `arm/svc.rs` (`Svc` & `ArmSvcMemory`)**
  - [x] `pub trait Svc` (`handle(&mut self, backend, memory) -> Result<SvcResult>`).
  - [x] `ArmSvcMemory` allocates SVC pages and emits stubs: ARM64 (`SVC #imm; RET`), ARM32 (`SVC #0; BX LR`), Thumb (`SVC #0; BX LR`).
  - [x] **Test & Check 1.3**: `cargo test -p unidbg-unicorn2 --test emulator_integration` registers `AddSvc` (`X0 + X1`), invokes it from ARM64 guest code via `BLR`, and asserts `X0 == 42`.

- [x] **1.4. `trace.rs` (`AssemblyCodeDumper`, `TraceMemoryHook`, `RegAccessPrinter`)**
  - [x] `AssemblyCodeDumper` disassembles ARM32/Thumb/ARM64 instructions step-by-step via `capstone`.
  - [x] `TraceMemoryHook` filters `[begin, end]` ranges and logs `READ`/`WRITE`.
  - [x] **Test & Check 1.4**: `cargo test -p unidbg-api trace` + `emulator_integration` runs ARM64 code with `AssemblyCodeDumper` + `TraceMemoryHook`, asserting disassembly and memory trace records match.

- [x] **1.5. `spi.rs`, `file/mod.rs`, `module.rs`, `thread/`, `signal.rs`, `emulator.rs`**
  - [x] Define traits: `Loader`, `LibraryFile`, `SyscallHandler`, `InitFunction`, `FileSystem`, `FileIO`, `IOResolver`, `Module`, `Symbol`.
  - [x] Implement `UniThreadDispatcher`, `Task`, `Waiter`.
  - [x] Implement `SignalOps`, `SignalTask`, `SigSet`.
  - [x] Implement `Emulator` trait, `EmulatorCore`, and `emulate(begin, until)` loop.
  - [x] **Test & Check 1.5**: `cargo test -p unidbg-api thread` tests cooperative task yield & wakeup via `Waiter`.

---

## Phase 2: `unidbg-android` Core (ELF, Syscalls, VFS, Linker) [P0]

- [x] **2.1. `elf_loader.rs` & `module.rs` (`AndroidElfLoader`, `LinuxModule`)**
  - [x] Parse ELF32 & ELF64 with `goblin::elf::Elf::parse`.
  - [x] Map `PT_LOAD` segments with `0x1000` alignment + `MemoryPerm`.
  - [x] ARM64 relocations (`RELATIVE`, `GLOB_DAT`, `JUMP_SLOT`, `ABS64`, `IRELATIVE`, `DT_RELR`) & ARM32 relocations (`RELATIVE`, `GLOB_DAT`, `JUMP_SLOT`, `ABS32`, `IRELATIVE`).
  - [x] Parse `.preinit_array`, `.init`, `.init_array`, and symbol tables.
  - [x] **Test & Check 2.1**: `cargo test -p unidbg-android elf_loader` loads `libtmessages.29.so` (ARM64) and `libnative-lib.so` (ARM32) + SDK 23 `libc.so`.

- [x] **2.2. `fs/` (`LinuxFileSystem` & `FileIO` implementations)**
  - [x] `LinuxFileSystem` manages fd table (`0,1,2` stdio, `open`, `close`).
  - [x] Implement: `SimpleFileIO`, `SliceFileIO`, `StdOutIO`, `RandomFileIO` (`/dev/urandom`), `NullZeroFileIO`, `/proc/self/maps`, `cmdline`, `cpuinfo`, `meminfo`, `PipeFileIO` (`pipe2`).
  - [x] **Test & Check 2.2**: `cargo test -p unidbg-android fs` tests opening/reading `/proc/self/maps`, `/dev/urandom`, and `pipe2` write-read.

- [x] **2.3. `syscall/` (`Arm64SyscallHandler` & `Arm32SyscallHandler`)**
  - [x] Shared `AndroidSyscallHandler` for VFS, `mmap`, `brk`, `uname`, `clock_gettime`, `gettimeofday`, `getrandom`, `fstat`/`newfstatat`, `pipe2`, `set_tls`.
  - [x] `Arm64SyscallHandler` & `Arm32SyscallHandler` dispatch Linux ARM64 & ARM32 EABI syscalls (including `clone` + `run_threads()`).
  - [x] **Test & Check 2.3**: `cargo test -p unidbg-android --test android_integration` runs `strlen`/`atoi` on real `libc.so` (ARM64 & ARM32) and `write(1)` + `exit_group(7)`.

- [x] **2.4. `resolver.rs`, `ld.rs`, `system_property.rs`**
  - [x] `AndroidResolver` (loads system libs from standard SDK directory).
  - [x] `DlOpenSvc` / `DlSymSvc`: `dlopen`, `dlsym`.
  - [x] `SystemPropertyGetSvc`: `__system_property_get`.
  - [x] **Test & Check 2.4**: `real_dlsym_and_system_property_get` passes on real `libc.so`.

---

## Phase 3: `unidbg-android/src/dvm/` (DalvikVM, JNI & APK) [P0/P1]

- [x] **3.1. `dvm/vm.rs` & `dvm/objects.rs`**
  - [x] `DvmObject` (`DvmObjectData::String`, `ByteArray`, `IntArray`, `ObjectArray`, `Boolean`, `Int`, `Long`, `DvmClass`, `DvmMethod`, `DvmField`).
  - [x] `DalvikVM` (32-bit & 64-bit): `LocalRef`/`GlobalRef`, `resolve_class`, `resolve_class_with_super`, `call_jni_onload`.
  - [x] **Test & Check 3.1**: `DalvikVM` initializes `JavaVM` + `JNIEnv` tables for both 32-bit and 64-bit.

- [x] **3.2. `dvm/var_arg.rs` (`VaList`)**
  - [x] `VaList::read_32` (AAPCS32) and `VaList::read_64` (AAPCS64).
  - [x] **Test & Check 3.2**: `cargo test -p unidbg-android var_arg` decodes mixed `(int, long, double, jobject)` varargs on 32-bit & 64-bit.

- [x] **3.3. `dvm/jni.rs` (`Jni` trait & `JNIEnv` / `JavaVM` table)**
  - [x] `pub trait Jni` (with `AbstractJni` fail-soft defaults), registers `JavaVM` + `JNIEnv` (233 entries) and `RegisterNatives`.
  - [x] **Test & Check 3.3**: `real_arm32_jni_string_from_jni` (`libnative-lib.so` returns `"Hello from C++"`) and `real_arm64_jni_ffmpeg_get_version` (`libtmessages.29.so` returns version string) pass.

- [x] **3.4. `dvm/apk.rs` (`ApkLibraryFile`) & `virtual_module/`** [P1]
  - [x] Read `.so` directly from `.apk` using `zip`.
  - [x] **Test & Check 3.4**: `cargo test -p unidbg-android apk_library_file_reads_so_from_zip` passes.
  - [x] Port `virtual_module`: `AndroidModule`, `JniGraphics`, `MediaNdkModule`, `SystemProperties` + `real_virtual_modules_resolve_and_execute` passes.

---

## Phase 4: Inline Hooking & Stack Unwinding [P1]

- [x] **4.1. `xhook.rs` (`XHook` PLT/GOT Hook)**
  - [x] Record `plt_got` in `AndroidElfLoader` and patch GOT slots to `Svc` callbacks via `XHook::register` + `refresh`.
  - [x] **Test & Check 4.1**: `real_xhook_patches_got_and_intercepts_call` patches `malloc` GOT in real `libnative-lib.so` and verifies the hook fires during `stringFromJNI`.

- [x] **4.2. `hook/mod.rs` (`InlineHook`)**
  - [x] Inspect target instructions with `capstone` (`InlineHook::inspect`).
  - [x] Generate pure-Rust ARM64 (`LDR X16, #8; BR X16; .quad`) and ARM32 (`LDR PC, [PC, #-4]; .word`) trampolines in `InlineHook::replace`.
  - [x] **Test & Check 4.2**: `real_inline_hook_replaces_libc_strlen` hooks `strlen` in real `sdk23/lib64/libc.so` and returns `999`.

- [x] **4.3. `unwind.rs` & `cpp_demangle`**
  - [x] Walk FP chain (`X29`/`X30` ARM64, `R11`/`LR` ARM32) + resolve `LinuxModule` + `Symbol` + `cpp_demangle`.
  - [x] **Test & Check 4.3**: `real_unwinder_resolves_3_frames_and_demangles_cpp` resolves 3 frames on `libtmessages.29.so` and demangles `_ZN7android7String8C1EPKc`.

---

## Phase 5: Debugger (`GDBServer`), `WorkerPool` & `unidbg-cli` [P1]

- [x] **5.1. `debugger/` & `GdbServer` (RSP TCP server)**
  - [x] `Debugger` trait (`add_breakpoint`, `del_breakpoint`, `has_breakpoint`, `set_single_step`) + `GdbServer` over TCP (`?`, `qSupported`, `g`, `m`, `M`, `Z0`, `z0`, `s`, `c`, `k`).
  - [x] **Test & Check 5.1**: `gdb_rsp_tcp_reads_regs_mem_and_sets_breakpoint` connects over TCP to `GdbServer`, sends `g`, `m`, `Z0`, and validates responses.

- [x] **5.2. `worker.rs` (`WorkerPool`)**
  - [x] Thread pool running N independent `Emulator` instances per worker thread (`Worker` need not be `Send`).
  - [x] **Test & Check 5.2**: `worker_pool_executes_100_jobs_in_parallel` + `real_worker_pool_runs_arm64_libc_strlen_in_parallel` (4 real ARM64 `AndroidEmulator`s executing 20 `libc.so` `strlen` jobs in parallel).

- [x] **5.3. `unidbg-cli` (`clap`)**
  - [x] Subcommands `exec`, `jni`, `gdb`.
  - [x] **Test & Check 5.3**: Running `unidbg-cli jni ...libnative-lib.so --arch arm32 --call Java_com_kanxue_test2_MainActivity_stringFromJNI` outputs `"Hello from C++"`.

---

## Phase 6: `unidbg-ios` (Mach-O, Dyld, Darwin, ObjC) [P2]

- [x] **6.1. `macho_loader.rs` (`MachOLoader`, `MachOModule`, Fat/Universal binary)** (`goblin::mach`)
  - [x] **Test & Check 6.1**: `real_load_macho_arm64_dylib_and_substrate_hook` & `real_load_macho_approov_framework_and_fishhook` load real `libsubstrate_arm64.dylib` and `Approov.framework/Approov`.
- [x] **6.2. `syscall.rs` (Darwin BSD/Mach) & `ipa.rs` (`IpaLoader`)** (`zip` + `plist`)
  - [x] **Test & Check 6.2**: `real_ipa_loader_reads_real_info_plist` reads real `Info.plist` from `.ipa`, and `real_darwin_arm64_syscalls_getpid_and_exit` executes Darwin ARM64 syscalls (`svc #0x80`).
- [x] **6.3. `hook.rs` (`FishHook`, `Substrate`), `fixup_chains.rs`, `objc.rs`**
  - [x] **Test & Check 6.3**: `Substrate::hook_function` hooks a function in `libsubstrate_arm64.dylib` returning `777`, `FishHook::rebind_by_key` rebinds slots in `Approov`, `real_objc_runtime_and_fixup_chains` passes `objc_getClass`/`sel_registerName`/`objc_msgSend` and `FixupChains::apply_64_rebase_chain`.

---

## Phase 7: Additional Backends (`dynarmic`, `hypervisor`, `kvm`) [P2]

- [ ] **7.1. `backend/dynarmic`**: Write C-ABI wrapper + `build.rs` around `unidbg/backend/dynarmic/src/main/native` implementing the `Backend` trait.
  - [ ] **Test & Check 7.1**: Pass Phase 0–3 test suites on `DynarmicBackend`.
- [x] **7.2. `backend/hypervisor`**: Implement `Backend` trait on macOS Apple Silicon (`Hypervisor.framework` FFI + `entitlements.plist`).
  - [x] **Test & Check 7.2**: `hv_test` (codesigned) executes `mov x0, #10; add x0, x0, #32; brk #0` directly on Apple Silicon hardware, asserting `X0 == 42`.
- [ ] **7.3. `backend/kvm`**: Implement `Backend` trait on Linux ARM64 (`kvm-ioctls`).
  - [ ] **Test & Check 7.3**: Pass `run_arm64_add` on `KvmBackend`.
