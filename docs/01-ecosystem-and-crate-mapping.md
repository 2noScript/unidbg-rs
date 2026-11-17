# Phân tích Thư viện Tương đương trong Hệ sinh thái Rust (`unidbg` -> `unidbg-rs`)

Bảng đối chiếu toàn bộ dependency và thành phần của `unidbg` sang các crate chuẩn trên `crates.io` (không phụ thuộc `rnidbg`).

---

## 1. Bảng ánh xạ Dependency & Crate tương đương

| Thành phần trong `unidbg` (Java) | Thư viện Java gốc | Crate Rust tương đương | Ghi chú |
| :--- | :--- | :--- | :--- |
| **Unicorn CPU Backend** | `unicorn` 1.0.15 / `unidbg-unicorn2` | `unicorn-engine` | Hỗ trợ sẵn ARM32, Thumb, ARM64 qua `crates.io` |
| **Dynarmic CPU Backend** | `unidbg-dynarmic` (JNI + C++) | Tự bọc C-ABI + `cmake`/`cc` | Dùng source `unidbg/backend/dynarmic/src/main/native` viết C wrapper thay JNI |
| **Hypervisor / KVM** | `unidbg-hypervisor`, `unidbg-kvm` | `applevisor` (macOS), `kvm-ioctls` (Linux) | Hardware-assisted backends (Phase 7) |
| **Disassembler** | `capstone` 3.1.8 | `capstone` | Hỗ trợ ARM32, Thumb, ARM64 đồng nhất với `unidbg` |
| **Assembler** | `keystone` 0.9.7 | `keystone-engine` | Dùng cho SVC stubs, `HookZz`, `Whale`, `Substrate` |
| **ELF Parser** | `net.fornwall.jelf` | `goblin` (`elf` feature) | Parse ELF32/ELF64, program headers, sections, dynamic symbols, relocations |
| **Mach-O Parser (iOS)** | `MachOLoader` + `kaitai-struct` | `goblin` (`mach` feature) | Parse Mach-O 32/64, load commands; tự bổ sung `DyldChainedFixups` |
| **APK / IPA Archive** | `apk-parser` 2.6.10 | `zip` + `abxml` | Đọc `lib/<abi>/*.so` và `AndroidManifest.xml` trực tiếp từ `.apk` |
| **Plist Parser (iOS)** | `dd-plist` 1.29 | `plist` | Đọc XML & binary `Info.plist` trong `.ipa` |
| **C++ Demangler** | `demumble` 1.0.4 | `cpp_demangle` | Pure Rust, không cần C++ FFI |
| **DWARF Unwind (tùy chọn)** | *(FP walk)* | `gimli` | Parse `.eh_frame` khi binary thiếu frame pointer |
| **Memory Interval Map** | `SparseList` | `rangemap` (hoặc tự viết `SparseList` nhỏ) | `rangemap::RangeMap` chuẩn, zero-unsafe, hỗ trợ split/merge interval |
| **GDB Remote Stub** | `debugger/gdb` (tự viết) | `gdbstub` + `gdbstub_arch` | Có sẵn target ARM & AArch64 cho GDB/LLDB/IDA |
| **JSON / Serialization** | `fastjson` 2.0.65 | `serde` + `serde_json` | Config, trace dump, crash report |
| **Logging & Diagnostics** | `slf4j` + `log4j` | `tracing` + `tracing-subscriber` | Structured logging, lọc động qua `RUST_LOG` |
| **Error Handling** | Java Exceptions | `thiserror` (lib) + `anyhow` (CLI) | `UnidbgError` có kiểu rõ ràng |
| **CLI** | Java `main` | `clap` (derive) | Subcommands `exec`, `jni`, `gdb`, `trace` |
| **Bitflags & Struct Mapping** | `ByteBuffer`, bitmask | `bitflags`, `bytes`, `zerocopy` | Đọc/ghi struct C (ELF, `stat`, `sigaction`, `prop_info`) an toàn |
| **Worker Pool** | `worker/WorkerPool` | `crossbeam-channel` / `rayon` | Chạy nhiều `Emulator` song song trên các thread |

---

## 2. Các phần lõi vẫn phải tự thiết kế/port từ `unidbg`

1. **`ArmSvcMemory`**: Cấp phát trang nhớ chứa stub `SVC #imm; RET` (ARM64) hoặc `SVC #0; BX LR` (ARM32/Thumb) để hook vào JNI, `dlopen`/`dlsym`, virtual modules.
2. **ELF Relocations & Dynamic Linker (`AndroidElfLoader`)**: Dùng `goblin` để parse, nhưng phải tự implement logic map `PT_LOAD`, `DT_RELR`, `R_AARCH64_IRELATIVE` (IFUNC), `R_AARCH64_TLS_TPREL`, `PT_TLS`, `.init_array`, và `ArmLd` (`dlopen`/`dlsym`/`dl_iterate_phdr`).
3. **Linux/Darwin Syscalls & VFS**: Bảng syscall ARM32 EABI, ARM64 `asm-generic`, và hệ thống `FileIO` ảo (`/proc/self/maps`, `/dev/urandom`, `ashmem`, `pipe`, `socket`).
4. **Dalvik VM & JNI Bridge**: `DalvikVM` (32/64-bit), `VaList32`/`VaList64` (AAPCS32/64), bảng ~230 hàm `JNIEnv`, `Jni` trait (`AbstractJni` fail-soft), `DvmClass`/`DvmObject`.
5. **Inline Hooking (`XHook`, `HookZz`, `Whale`, `FishHook`)**: Dùng `capstone` kiểm tra lệnh PC-relative và `keystone-engine` sinh trampoline.
