# Kế hoạch & Checklist Tiến độ (`unidbg-rs`)

> **Quy tắc**: Chỉ đánh dấu `[x]` sau khi đã viết xong code **VÀ** chạy `Test & Check` tương ứng thành công. Không phụ thuộc `rnidbg`; lấy `unidbg` làm chuẩn và viết theo Idiomatic Rust.

## Tổng quan Tiến độ (Master Checklist)

- [x] **Phase 0**: Cargo Workspace, `UnidbgError`, `Backend` trait & `UnicornBackend`
- [x] **Phase 1**: `unidbg-api` (Pointer, Memory, `ArmSvcMemory`, Trace, Thread, Signal, Emulator)
- [x] **Phase 2**: `unidbg-android` Core (`AndroidElfLoader`, `LinuxFileSystem`, Syscalls ARM32/ARM64, `ArmLd`, `SystemPropertyHook`)
- [x] **Phase 3**: `unidbg-android` DVM (`DalvikVM` 32/64, `VaList`, `Jni` trait, `ApkLibraryFile`)
- [x] **Phase 4**: Hooking (`XHook`, `InlineHook`) & Stack `Unwinder` + `cpp_demangle`
- [x] **Phase 5**: `GDBServer`, `WorkerPool`, `unidbg-cli`
- [x] **Phase 6**: `unidbg-ios` (Mach-O, `DarwinSyscall`, `IpaLoader`, `FishHook`, `Substrate`)
- [ ] **Phase 7**: Backends bổ sung (`backend/dynarmic`, `[x] backend/hypervisor`, `backend/kvm`)

---

## Phase 0: Khung Workspace & `UnicornBackend` [P0]

- [x] **0.1. Khởi tạo Cargo Workspace**
  - [x] Tạo `Cargo.toml` root với workspace members: `crates/unidbg-api`, `crates/unidbg-android`, `crates/unidbg-cli`, `backend/unicorn2`.
  - [x] Tạo skeleton `Cargo.toml` + `src/lib.rs` cho từng crate.
  - [x] **Test & Check 0.1**: Chạy `cargo check --workspace` → exit code 0.

- [x] **0.2. `UnidbgError`, `MemoryPerm` & `Backend` Trait (`crates/unidbg-api`)**
  - [x] `crates/unidbg-api/src/error.rs`: định nghĩa `UnidbgError` (`InvalidMemoryAccess`, `StopEmulator`, `LongJump`, `UnhandledSyscall`, `Backend`, `ElfLoad`, `Jni`, `Io`) và `Result<T>`.
  - [x] `crates/unidbg-api/src/arm/backend.rs`: định nghĩa `MemoryPerm` (`bitflags!`), `ArmReg`, `Arm64Reg`, `HookId`, `MemAccessType`, và `pub trait Backend` (`reg_read/write`, `reg_read_vec/write_vec`, `mem_read/write`, `mem_map/unmap/protect`, `emu_start/stop`, `context_alloc/save/restore`, `hook_add_code/mem`, `hook_del`).
  - [x] **Test & Check 0.2**: Tạo `MockBackend` trong `#[cfg(test)]`, chạy `cargo test -p unidbg-api` test `mem_map`/`mem_write`/`mem_read`/`reg_read`/`reg_write`.

- [x] **0.3. Implement `UnicornBackend` (`backend/unicorn2`)**
  - [x] Thêm crate `unicorn-engine` vào `backend/unicorn2/Cargo.toml`.
  - [x] Tạo `backend/unicorn2/src/unicorn_backend.rs` implement `unidbg_api::arm::backend::Backend` cho cả `Arch::ARM` (ARM32/Thumb) và `Arch::ARM64`.
  - [x] **Test & Check 0.3**:
    - [x] `cargo test -p unidbg-unicorn2 create_destroy_loop`: tạo & drop `UnicornBackend` 100 lần liên tiếp không crash/leak.
    - [x] `cargo test -p unidbg-unicorn2 run_arm64_add`: map `0x1000`, chạy `MOV X0, #10; ADD X0, X0, #32`, assert `X0 == 42`.
    - [x] `cargo test -p unidbg-unicorn2 run_arm32_add`: chạy cả mode ARM và Thumb, assert `R0 == 42`.

---

## Phase 1: `unidbg-api` (Core Framework) [P0]

- [x] **1.1. `pointer.rs` (`UnidbgPointer` & `UnidbgStruct`)**
  - [x] Implement `UnidbgPointer` (hỗ trợ pointer 4-byte & 8-byte): `share`, `read_u8/u16/u32/u64/i32/i64/bytes/cstr`, `write_u32/u64/bytes/cstr`.
  - [x] Implement trait `UnidbgStruct` (`pack`, `unpack`).
  - [x] **Test & Check 1.1**: `cargo test -p unidbg-api pointer` pass trên cả 32-bit và 64-bit.

- [x] **1.2. `memory/mod.rs` (`Memory`, `MemoryMap`, `MemoryBlock`)**
  - [x] Dùng `rangemap::RangeMap` quản lý vùng nhớ đã map + quyền `MemoryPerm`.
  - [x] Implement `MemoryManager`: `allocate_stack`, `set_stack_point`, `mmap` (auto + fixed), `munmap`, `mprotect`, `malloc` / `free` (`MemoryBlock`), `brk`, `pointer`.
  - [x] **Test & Check 1.2**: `cargo test -p unidbg-api memory` test `mmap` tự động, `munmap` cắt đôi vùng nhớ, `mprotect`, `malloc`/`free` không overlap.

- [x] **1.3. `svc.rs` & `arm/svc.rs` (`Svc` & `ArmSvcMemory`)**
  - [x] `pub trait Svc` (`handle(&mut self, backend, memory) -> Result<SvcResult>`).
  - [x] `ArmSvcMemory` cấp phát vùng SVC và sinh stub: ARM64 (`SVC #imm; RET`), ARM32 (`SVC #0; BX LR`), Thumb (`SVC #0; BX LR`).
  - [x] **Test & Check 1.3**: `cargo test -p unidbg-unicorn2 --test emulator_integration` đăng ký `AddSvc` cộng `X0 + X1`, gọi từ guest code ARM64 qua `BLR` và kiểm tra `X0 == 42`.

- [x] **1.4. `trace.rs` (`AssemblyCodeDumper`, `TraceMemoryHook`, `RegAccessPrinter`)**
  - [x] `AssemblyCodeDumper` dùng `capstone` disassemble lệnh ARM32/Thumb/ARM64 theo từng bước.
  - [x] `TraceMemoryHook` lọc dải địa chỉ `[begin, end]`, log `READ`/`WRITE`.
  - [x] **Test & Check 1.4**: `cargo test -p unidbg-api trace` + `emulator_integration` chạy lệnh ARM64 với `AssemblyCodeDumper` + `TraceMemoryHook`, assert output disassemble và memory record khớp.

- [x] **1.5. `spi.rs`, `file/mod.rs`, `module.rs`, `thread/`, `signal.rs`, `emulator.rs`**
  - [x] Định nghĩa traits: `Loader`, `LibraryFile`, `SyscallHandler`, `InitFunction`, `FileSystem`, `FileIO`, `IOResolver`, `Module`, `Symbol`.
  - [x] Implement `UniThreadDispatcher`, `Task`, `Waiter`.
  - [x] Implement `SignalOps`, `SignalTask`, `SigSet`.
  - [x] Implement `Emulator` trait, `EmulatorCore`, vòng lặp `emulate(begin, until)`.
  - [x] **Test & Check 1.5**: `cargo test -p unidbg-api thread` test task yield & wakeup qua `Waiter`.

---

## Phase 2: `unidbg-android` Core (ELF, Syscalls, VFS, Linker) [P0]

- [x] **2.1. `elf_loader.rs` & `module.rs` (`AndroidElfLoader`, `LinuxModule`)**
  - [x] Parse ELF32 & ELF64 bằng `goblin::elf::Elf::parse`.
  - [x] Map `PT_LOAD` theo `0x1000` align + `MemoryPerm`.
  - [x] Relocations ARM64 (`RELATIVE`, `GLOB_DAT`, `JUMP_SLOT`, `ABS64`, `IRELATIVE`, `DT_RELR`) & ARM32 (`RELATIVE`, `GLOB_DAT`, `JUMP_SLOT`, `ABS32`, `IRELATIVE`).
  - [x] Parse `.preinit_array`, `.init`, `.init_array`, symbol tables.
  - [x] **Test & Check 2.1**: `cargo test -p unidbg-android elf_loader` load thành công `libtmessages.29.so` (ARM64) và `libnative-lib.so` (ARM32) + `libc.so` SDK 23.

- [x] **2.2. `fs/` (`LinuxFileSystem` & `FileIO` implementations)**
  - [x] `LinuxFileSystem` quản lý fd table (`0,1,2` stdio, `open`, `close`).
  - [x] Implement: `SimpleFileIO`, `SliceFileIO`, `StdOutIO`, `RandomFileIO` (`/dev/urandom`), `NullZeroFileIO`, `/proc/self/maps`, `cmdline`, `cpuinfo`, `meminfo`, `PipeFileIO` (`pipe2`).
  - [x] **Test & Check 2.2**: `cargo test -p unidbg-android fs` test mở/đọc `/proc/self/maps`, `/dev/urandom`, và `pipe2` write-read.

- [x] **2.3. `syscall/` (`ARM64SyscallHandler` & `ARM32SyscallHandler`)**
  - [x] `AndroidSyscallHandler` dùng chung cho VFS, `mmap`, `brk`, `uname`, `clock_gettime`, `getrandom`, `pipe2`, `set_tls`.
  - [x] `Arm64SyscallHandler` & `Arm32SyscallHandler` dispatch đầy đủ syscall chuẩn Linux ARM64 & ARM32 EABI.
  - [x] **Test & Check 2.3**: `cargo test -p unidbg-android --test android_integration` chạy `strlen`/`atoi` trên `libc.so` thật (ARM64 & ARM32) và `write(1)` + `exit_group(7)`.

- [x] **2.4. `resolver.rs`, `ld.rs`, `system_property.rs`**
  - [x] `AndroidResolver` (đọc system libs từ thư mục SDK chuẩn).
  - [x] `DlOpenSvc` / `DlSymSvc`: `dlopen`, `dlsym`.
  - [x] `SystemPropertyGetSvc`: `__system_property_get`.
  - [x] **Test & Check 2.4**: `real_dlsym_and_system_property_get` pass trên `libc.so` thật.

---

## Phase 3: `unidbg-android/src/dvm/` (DalvikVM, JNI & APK) [P0/P1]

- [x] **3.1. `dvm/vm.rs` & `dvm/objects.rs`**
  - [x] `DvmObject` (`DvmObjectData::String`, `ByteArray`, `IntArray`, `ObjectArray`, `DvmClass`, `DvmMethod`, `DvmField`).
  - [x] `DalvikVM` (hỗ trợ 32-bit & 64-bit): `LocalRef`/`GlobalRef`, `resolve_class`, `call_jni_onload`.
  - [x] **Test & Check 3.1**: `DalvikVM` khởi tạo bảng `JavaVM` + `JNIEnv` cho cả 32-bit và 64-bit.

- [x] **3.2. `dvm/var_arg.rs` (`VaList`)**
  - [x] `VaList::read_32` (AAPCS32) và `VaList::read_64` (AAPCS64).
  - [x] **Test & Check 3.2**: `cargo test -p unidbg-android var_arg` đọc đúng tham số hỗn hợp `(int, long, double, jobject)` trên 32-bit & 64-bit.

- [x] **3.3. `dvm/jni.rs` (`Jni` trait & `JNIEnv` / `JavaVM` table)**
  - [x] `pub trait Jni` (có default fail-soft giống `AbstractJni`), đăng ký bảng `JavaVM` + `JNIEnv` (233 entries) và `RegisterNatives`.
  - [x] **Test & Check 3.3**: `real_arm32_jni_string_from_jni` (`libnative-lib.so` trả về `"Hello from C++"`) và `real_arm64_jni_ffmpeg_get_version` (`libtmessages.29.so` trả về version string) đều pass.

- [x] **3.4. `dvm/apk.rs` (`ApkLibraryFile`) & `virtual_module/`** [P1]
  - [x] Đọc `.so` trực tiếp từ `.apk` bằng `zip`.
  - [x] **Test & Check 3.4**: `cargo test -p unidbg-android apk_library_file_reads_so_from_zip` pass.
  - [x] Port `virtual_module`: `AndroidModule`, `JniGraphics`, `MediaNdkModule`, `SystemProperties` + test `real_virtual_modules_resolve_and_execute` pass.

---

## Phase 4: Inline Hooking & Stack Unwinding [P1]

- [x] **4.1. `xhook.rs` (`XHook` PLT/GOT Hook)**
  - [x] Ghi nhận `plt_got` trong `AndroidElfLoader` và patch GOT sang `Svc` callback qua `XHook::register` + `refresh`.
  - [x] **Test & Check 4.1**: `real_xhook_patches_got_and_intercepts_call` patch `malloc` GOT trong `libnative-lib.so` thật và xác nhận hook chạy khi gọi `stringFromJNI`.

- [x] **4.2. `hook/mod.rs` (`InlineHook`)**
  - [x] Dùng `capstone` kiểm tra lệnh tại điểm hook (`InlineHook::inspect`).
  - [x] Sinh trampoline ARM64 (`LDR X16, #8; BR X16; .quad`) và ARM32 (`LDR PC, [PC, #-4]; .word`) thuần Rust trong `InlineHook::replace`.
  - [x] **Test & Check 4.2**: `real_inline_hook_replaces_libc_strlen` hook `strlen` trong `sdk23/lib64/libc.so` thật và trả về `999`.

- [x] **4.3. `unwind.rs` & `cpp_demangle`**
  - [x] Walk FP chain (`X29`/`X30` ARM64, `R11`/`LR` ARM32) + map sang `LinuxModule` + `Symbol` + `cpp_demangle`.
  - [x] **Test & Check 4.3**: `real_unwinder_resolves_3_frames_and_demangles_cpp` giải mã đúng 3 frame trên `libtmessages.29.so` và demangle `_ZN7android7String8C1EPKc`.

---

## Phase 5: Debugger (`GDBServer`), `WorkerPool` & `unidbg-cli` [P1]

- [x] **5.1. `debugger/` & `GdbServer` (RSP TCP server)**
  - [x] `Debugger` trait (`add_breakpoint`, `del_breakpoint`, `has_breakpoint`, `set_single_step`) + `GdbServer` qua TCP (`?`, `qSupported`, `g`, `m`, `M`, `Z0`, `z0`, `s`, `c`, `k`).
  - [x] **Test & Check 5.1**: `gdb_rsp_tcp_reads_regs_mem_and_sets_breakpoint` kết nối TCP thật tới `GdbServer`, gửi gói `g`, `m`, `Z0`, nhận phản hồi hợp lệ.

- [x] **5.2. `worker.rs` (`WorkerPool`)**
  - [x] Thread pool chạy N `Emulator` độc lập trên từng thread (`Worker` không cần `Send`).
  - [x] **Test & Check 5.2**: `worker_pool_executes_100_jobs_in_parallel` + `real_worker_pool_runs_arm64_libc_strlen_in_parallel` (4 `AndroidEmulator` ARM64 thật chạy 20 job `libc.so` `strlen` song song).

- [x] **5.3. `unidbg-cli` (`clap`)**
  - [x] Subcommands `exec`, `jni`, `gdb`.
  - [x] **Test & Check 5.3**: Chạy `unidbg-cli jni ...libnative-lib.so --arch arm32 --call Java_com_kanxue_test2_MainActivity_stringFromJNI` in ra `"Hello from C++"`.

---

## Phase 6: `unidbg-ios` (Mach-O, Dyld, Darwin, ObjC) [P2]

- [x] **6.1. `macho_loader.rs` (`MachOLoader`, `MachOModule`, Fat/Universal binary)** (`goblin::mach`)
  - [x] **Test & Check 6.1**: `real_load_macho_arm64_dylib_and_substrate_hook` & `real_load_macho_approov_framework_and_fishhook` load thành công `libsubstrate_arm64.dylib` và `Approov.framework/Approov` thật.
- [x] **6.2. `syscall.rs` (Darwin BSD/Mach) & `ipa.rs` (`IpaLoader`)** (`zip` + `plist`)
  - [x] **Test & Check 6.2**: `real_ipa_loader_reads_real_info_plist` đọc `Info.plist` thật từ `.ipa` và `real_darwin_arm64_syscalls_getpid_and_exit` chạy syscall Darwin ARM64 (`svc #0x80`).
- [x] **6.3. `hook.rs` (`FishHook`, `Substrate`), `fixup_chains.rs`, `objc.rs`**
  - [x] **Test & Check 6.3**: `Substrate::hook_function` hook hàm trong `libsubstrate_arm64.dylib` trả về `777`, `FishHook::rebind_by_key` rebind slot trong `Approov`, `real_objc_runtime_and_fixup_chains` pass `objc_getClass`/`sel_registerName`/`objc_msgSend` và `FixupChains::apply_64_rebase_chain`.

---

## Phase 7: Backends bổ sung (`dynarmic`, `hypervisor`, `kvm`) [P2]

- [ ] **7.1. `backend/dynarmic`**: Viết C-ABI wrapper + `build.rs` từ `unidbg/backend/dynarmic/src/main/native` implement `Backend` trait.
  - [ ] **Test & Check 7.1**: Pass toàn bộ test suite Phase 0–3 trên `DynarmicBackend`.
- [x] **7.2. `backend/hypervisor`**: Implement `Backend` trait trên macOS Apple Silicon (`Hypervisor.framework` FFI + `entitlements.plist`).
  - [x] **Test & Check 7.2**: `hv_test` (codesigned) chạy `mov x0, #10; add x0, x0, #32; brk #0` trực tiếp trên phần cứng Apple Silicon, assert `X0 == 42` pass.
- [ ] **7.3. `backend/kvm`**: Implement `Backend` trait trên Linux ARM64 (`kvm-ioctls`).
  - [ ] **Test & Check 7.3**: Pass `run_arm64_add` trên `KvmBackend`.
