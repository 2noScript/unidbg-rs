# Ánh xạ Cấu trúc `unidbg` -> `unidbg-rs` (Idiomatic Rust)

Lấy **`unidbg` gốc** làm chuẩn kiến trúc và chức năng; tổ chức file, struct/trait và chữ ký hàm theo phong cách **Idiomatic Rust**. Cột đầu tiên (`[ ]` / `[x]`) dùng để đánh dấu module/file đã hoàn thành và pass test.

---

## 1. `unidbg-api` (`crates/unidbg-api/src/`)

| Done | Nhóm trong `unidbg-api` (Java) | File / Module Rust | Thiết kế Rust (`trait` / `struct` / `fn`) |
| :---: | :--- | :--- | :--- |
| [x] | `Emulator`, `AbstractEmulator`, `EmulatorBuilder`, `Family` | `emulator.rs` | `pub trait Emulator` (`load_library`, `memory`, `backend`, `syscall_handler`, `attach`, `trace_code`, `trace_read`, `trace_write`, `pid`, `name`), `EmulatorCore`, `EmulatorBuilder`, `Family` |
| [x] | `Module`, `Symbol`, `Svc` | `module.rs`, `symbol.rs`, `svc.rs` | `pub trait Module` (`find_symbol`, `call_function`, `call_entry`, `base`, `size`, `name`), `Symbol`, `pub trait Svc` (`handle`) |
| [x] | `AssemblyCodeDumper`, `TraceHook`, `TraceMemoryHook`, `RegAccessPrinter` | `trace.rs` | `AssemblyCodeDumper`, `TraceMemoryHook`, `RegAccessPrinter` |
| [x] | `arm/ARM`, `AbstractARMEmulator`, `AbstractARM64Emulator`, `Cpsr` | `arm/mod.rs` | `Arch`, `ArmMode`, `Cpsr`, `show_regs`, `is_thumb` |
| [x] | `arm/ARMSvcMemory`, `ArmSvc`, `ThumbSvc`, `Arm64Svc`, `ArmHook`, `Arm64Hook` | `arm/svc.rs`, `arm/hook.rs` | `ArmSvcMemory` (`register_svc`, `allocate`), `SvcStub`, `HookStatus` |
| [x] | `arm/backend/*` (`Backend`, `BackendFactory`) | `arm/backend.rs` | `pub trait Backend` (`reg_read`, `reg_write`, `mem_read`, `mem_write`, `mem_map`, `mem_unmap`, `mem_protect`, `emu_start`, `emu_stop`, `context_alloc/save/restore`, `hook_add_code`, `hook_add_mem`, `hook_del`) |
| [ ] | `arm/context/*` | `arm/context.rs` | `pub trait RegisterContext`, `Arm32Context`, `Arm64Context` |
| [x] | `memory/*` (`Memory`, `MemoryMap`, `MemoryBlock`, `SvcMemory`) | `memory/mod.rs`, `memory/svc.rs` | `pub trait Memory` (`malloc`, `mmap`, `munmap`, `mprotect`, `allocate_stack`, `pointer`, `find_module`), `MemoryMap`, `MemoryBlock` |
| [x] | `pointer/*` (`UnidbgPointer`, `UnidbgStructure`) | `pointer.rs` | `UnidbgPointer`, `pub trait UnidbgStruct` |
| [x] | `file/*` (`FileSystem`, `FileIO`, `IOResolver`) | `file/mod.rs` | `pub trait FileSystem`, `pub trait FileIO`, `pub trait IOResolver` |
| [x] | `spi/*` (`Loader`, `LibraryFile`, `SyscallHandler`, `InitFunction`) | `spi.rs` | `pub trait Loader`, `pub trait LibraryFile`, `pub trait SyscallHandler`, `pub trait InitFunction` |
| [x] | `thread/*` (`UniThreadDispatcher`, `Task`, `Waiter`, `Function32/64`) | `thread/mod.rs`, `dispatcher.rs`, `task.rs` | `pub trait ThreadDispatcher`, `UniThreadDispatcher`, `Task`, `pub trait Waiter`, `Function32`, `Function64` |
| [x] | `signal/*` (`SignalOps`, `SignalTask`, `SigSet`, `UnixSigSet`) | `signal.rs` | `pub trait SignalOps`, `SignalTask`, `SigSet` |
| [x] | `hook/*` (`IHook`, `ReplaceCallback`, `HookZz`, `Whale`) | `hook/mod.rs`, `hook/hookzz.rs`, `hook/whale.rs` | `pub trait Hook`, `ReplaceCallback`, `HookContext`, `HookZz`, `Whale` |
| [x] | `debugger/*` (`Debugger`, `BreakPoint`, `gdb/*`) | `debugger/mod.rs`, `debugger/gdb.rs` | `pub trait Debugger`, `GdbServer` |
| [x] | `unwind/*` (`Unwinder`, `Frame`, `SimpleARMUnwinder`, `SimpleARM64Unwinder`) | `unwind.rs` | `pub trait Unwinder`, `Frame`, `SimpleArmUnwinder`, `SimpleArm64Unwinder` |
| [x] | `worker/*` (`WorkerPool`, `Worker`, `WorkerFactory`) | `worker.rs` | `pub trait Worker`, `WorkerPool` |

---

## 2. `unidbg-android` (`crates/unidbg-android/src/`)

| Done | Nhóm trong `unidbg-android` (Java) | File / Module Rust | Thiết kế Rust |
| :---: | :--- | :--- | :--- |
| [x] | `AndroidEmulator`, `AndroidEmulatorBuilder`, `AndroidARMEmulator`, `AndroidARM64Emulator` | `emulator.rs` | `AndroidEmulator` + `AndroidEmulatorBuilder` (`arm32()`, `arm64()`) |
| [x] | `AndroidResolver` | `resolver.rs` | `AndroidResolver` |
| [x] | `AndroidElfLoader`, `LinuxModule`, `LinuxSymbol`, `LinuxInitFunction` | `elf_loader.rs`, `module.rs` | `AndroidElfLoader` (dùng `goblin`), `LinuxModule`, `LinuxSymbol`, `LinuxInitFunction` |
| [x] | `AndroidSyscallHandler`, `ARM32SyscallHandler`, `ARM64SyscallHandler` | `syscall/mod.rs`, `arm32.rs`, `arm64.rs` | `AndroidSyscallHandler`, `Arm32SyscallHandler`, `Arm64SyscallHandler` |
| [x] | `ArmLD`, `ArmLD64`, `SystemPropertyHook`, `XHookImpl` | `ld.rs`, `system_property.rs`, `xhook.rs` | `ArmLd`, `SystemPropertyHook`, `XHook` |
| [x] | `AndroidARMUnwinder`, `AndroidARM64Unwinder` | `unwind.rs` | `AndroidUnwinder` |
| [x] | `LinuxFileSystem`, `AndroidFileIO`, `linux/file/*` | `fs/mod.rs`, `fs/*.rs` | `LinuxFileSystem`, `SimpleFileIO`, `ByteArrayFileIO`, `MapsFileIO`, `RandomFileIO`, `Ashmem`, `LocalSocketIO`, ... |
| [x] | `dvm/*` (`VM`, `DalvikVM`, `DalvikVM64`, `Jni`, `AbstractJni`, `VaList*`, `DvmClass`, `DvmObject`, `ApkLibraryFile`) | `dvm/mod.rs`, `vm.rs`, `jni.rs`, `var_arg.rs`, `objects.rs`, `apk.rs` | `pub trait Jni`, `DalvikVM` (32/64-bit), `VaList`, `DvmClass`, `DvmObject`, `ApkLibraryFile` |
| [x] | `virtualmodule/android/*` | `virtual_module/mod.rs` | `AndroidModule`, `JniGraphics`, `MediaNdkModule`, `SystemProperties` |

---

## 3. `unidbg-ios` (`crates/unidbg-ios/src/`) — Phase 6

| Done | Nhóm trong `unidbg-ios` (Java) | File / Module Rust | Thiết kế Rust |
| :---: | :--- | :--- | :--- |
| [x] | `DarwinARMEmulator`, `DarwinARM64Emulator`, `DarwinEmulatorBuilder` | `emulator.rs` | `DarwinEmulator` |
| [x] | `MachOLoader`, `MachOModule`, `Dyld32`, `Dyld64`, `FixupChains` | `macho_loader.rs`, `fixup_chains.rs` | `goblin::mach` + Fat/Universal Mach-O loader + `FixupChains` |
| [x] | `DarwinSyscallHandler`, `ARM32SyscallHandler`, `ARM64SyscallHandler` | `syscall.rs` | BSD syscalls + Mach traps |
| [x] | `IpaLoader`, `objc/*`, `FishHook`, `Substrate` | `ipa.rs`, `objc.rs`, `hook.rs` | `IpaLoader` (`zip` + `plist`), `ObjcRuntime`, `FishHook`, `Substrate` |
