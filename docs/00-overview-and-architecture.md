# Kiến trúc tổng quan `unidbg-rs` (Port `unidbg` sang Idiomatic Rust)

Nguyên tắc thiết kế của dự án **`unidbg-rs`**:
1. **Lấy `unidbg` (Java) làm chuẩn 100%** về kiến trúc module, luồng xử lý, tính năng và tên gọi.
2. **Viết theo phong cách Idiomatic Rust** (không dịch máy Java OOP): gộp các lớp boilerplate (`Abstract*`, `Base*`, `I*`, `*Impl`) thành `trait` + `struct` gọn gàng, dùng `Result`/`Option`, bỏ `get_`, dùng RAII `Drop` và ownership sạch.
3. **Không phụ thuộc `rnidbg`**: xây dựng hoàn toàn độc lập dựa trên `unidbg` và hệ sinh thái crate chuẩn của Rust (`unicorn-engine`, `capstone`, `keystone-engine`, `goblin`, `rangemap`, `gdbstub`, `tracing`, `thiserror`).

---

## 1. Cấu trúc Cargo Workspace (`unidbg` -> `unidbg-rs`)

Đối chiếu trực tiếp từ [unidbg/pom.xml](file:///Users/2noscript/workspace/project/unidbg-rs/unidbg/pom.xml):

| Module trong `unidbg` | Crate trong `unidbg-rs` | Vai trò |
| :--- | :--- | :--- |
| `unidbg-api` | `crates/unidbg-api` | Core API: `Emulator`, `Memory`, `ArmSvcMemory`, `Backend` trait, `Debugger`, `FileSystem`, `Hook`, `ThreadDispatcher`, `SignalOps`, `Unwinder`, `WorkerPool` |
| `unidbg-android` | `crates/unidbg-android` | `AndroidEmulator`, `AndroidElfLoader`, `ARM32SyscallHandler`, `ARM64SyscallHandler`, `LinuxFileSystem`, `DalvikVM` (32/64), `XHook`, `AndroidUnwinder` |
| `unidbg-ios` | `crates/unidbg-ios` | (Phase 6) `DarwinEmulator`, `MachOLoader`, `Dyld32/64`, `FixupChains`, `DarwinSyscallHandler`, `ObjC`, `FishHook`, `Substrate` |
| `backend/unicorn2` | `backend/unicorn2` | `UnicornBackend` dùng crate `unicorn-engine` (hỗ trợ ARM32 + Thumb + ARM64) |
| `backend/dynarmic` | `backend/dynarmic` | (Phase 4/5 hoặc sau Unicorn) C-ABI wrapper + `build.rs` từ `unidbg/backend/dynarmic/src/main/native` |
| `backend/hypervisor` | `backend/hypervisor` | (Phase 7) Apple Hypervisor.framework backend |
| `backend/kvm` | `backend/kvm` | (Phase 7) Linux KVM backend |
| *(CLI)* | `crates/unidbg-cli` | CLI runner (`exec`, `jni`, `gdb`) |

---

## 2. Quy ước viết code theo phong cách Idiomatic Rust

1. **Gộp các lớp Java boilerplate (`I*`, `Abstract*`, `Base*`, `*Impl`) thành `trait` + `struct` gọn**:
   - Java tách `Emulator.java`, `AbstractEmulator.java`, `ARMEmulator.java`, `AbstractARMEmulator.java` → Rust gom thành `emulator.rs` (`pub trait Emulator` + `pub struct EmulatorCore`).
   - `IxHook.java` + `XHookImpl.java` → `xhook.rs` (`pub trait XHook` / `pub struct XHook`).
   - `FileIO.java` + `AbstractFileIO.java` + `BaseFileIO.java` → `file/io.rs` (`pub trait FileIO`).
2. **Đặt tên hàm & kiểu trả về chuẩn Rust**:
   - Bỏ tiền tố `get_`: `memory()`, `backend()`, `pid()`, `name()`, `base()`, `size()` (giữ `set_*` cho setter).
   - Dùng `Result<T, UnidbgError>` và `Option<T>` thay cho `null`, exception (`StopEmulatorException`, `LongJumpException`), hoặc mã lỗi `-1`.
   - Dùng `enum` và `bitflags!`: `Arch::Arm32 | Arch::Arm64`, `MemoryPerm`, `Family::Android32 | Android64 | Ios32 | Ios64`.
   - Dùng `&[u8]`, `&mut [u8]`, `&str`, `impl AsRef<Path>` thay cho `byte[]`, `String`, `File`.
3. **RAII (`Drop`) & Ownership sạch**:
   - Dùng `Drop` để giải phóng tài nguyên tự động thay vì bắt buộc gọi `close()`/`destroy()`.
   - Tách `Backend` (CPU/RAM) khỏi `RuntimeContext` (VFS, threads, DVM), truyền context rõ ràng vào callback/syscall để tránh circular reference và `UnsafeCell` bừa bãi.
