use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use unidbg_android::dvm::vm::DalvikVM;
use unidbg_android::emulator::AndroidEmulatorBuilder;
use unidbg_android::resolver::AndroidResolver;
use unidbg_android::unwind::AndroidUnwinder;
use unidbg_android::xhook::XHook;
use unidbg_api::arm::backend::{Arm64Reg, ArmReg, Backend, MemoryPerm};
use unidbg_api::arm::{Arch, ArmMode};
use unidbg_api::emulator::Emulator;
use unidbg_api::error::UnidbgError;
use unidbg_api::hook::InlineHook;
use unidbg_api::memory::{Memory, MemoryManager};
use unidbg_api::pointer::UnidbgPointer;
use unidbg_api::svc::{Svc, SvcResult};
use unidbg_unicorn2::unicorn_backend::UnicornBackend;

fn android_resources_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("unidbg/unidbg-android/src/main/resources/android")
}

#[test]
fn real_arm64_libc_strlen_and_atoi() {
    let res_dir = android_resources_dir();
    let libc_path = res_dir.join("sdk23/lib64/libc.so");
    let backend = Box::new(UnicornBackend::new(Arch::Arm64, ArmMode::Arm64).unwrap());

    let mut emu = AndroidEmulatorBuilder::for_64_bit()
        .resolver(AndroidResolver::new(23, Arch::Arm64, res_dir))
        .build(backend)
        .unwrap();

    let libc = emu.load_library(libc_path, true).unwrap();
    let strlen_addr = libc.find_symbol_addr("strlen").unwrap();
    let atoi_addr = libc.find_symbol_addr("atoi").unwrap();

    // Allocate guest memory for test strings
    let buf = emu.core_mut().mmap(0, 0x1000, MemoryPerm::READ | MemoryPerm::WRITE).unwrap();
    let ptr = UnidbgPointer::new(buf, 8);
    ptr.write_cstr(emu.core_mut().backend_mut(), "hello unidbg-rs!").unwrap();

    let len = emu.call_function(strlen_addr, &[buf]).unwrap();
    assert_eq!(len, 16);

    let num_addr = buf + 64;
    UnidbgPointer::new(num_addr, 8)
        .write_cstr(emu.core_mut().backend_mut(), "-12345")
        .unwrap();
    let val = emu.call_function(atoi_addr, &[num_addr]).unwrap();
    assert_eq!(val as i32, -12345);
}

#[test]
fn real_arm32_libc_strlen() {
    let res_dir = android_resources_dir();
    let libc_path = res_dir.join("sdk23/lib/libc.so");
    let backend = Box::new(UnicornBackend::new(Arch::Arm32, ArmMode::Arm32).unwrap());

    let mut emu = AndroidEmulatorBuilder::for_32_bit()
        .resolver(AndroidResolver::new(23, Arch::Arm32, res_dir))
        .build(backend)
        .unwrap();

    let libc = emu.load_library(libc_path, true).unwrap();
    let strlen_addr = libc.find_symbol_addr("strlen").unwrap();

    let buf = emu.core_mut().mmap(0, 0x1000, MemoryPerm::READ | MemoryPerm::WRITE).unwrap();
    UnidbgPointer::new(buf, 4)
        .write_cstr(emu.core_mut().backend_mut(), "unidbg32")
        .unwrap();

    let len = emu.call_function(strlen_addr, &[buf]).unwrap();
    assert_eq!(len, 8);
}

#[test]
fn real_arm64_syscalls_write_and_exit_group() {
    let backend = Box::new(UnicornBackend::new(Arch::Arm64, ArmMode::Arm64).unwrap());
    let mut emu = AndroidEmulatorBuilder::for_64_bit().build(backend).unwrap();

    let code_base = emu.core_mut().mmap(0, 0x1000, MemoryPerm::ALL).unwrap();
    let msg_addr = emu.core_mut().mmap(0, 0x1000, MemoryPerm::READ | MemoryPerm::WRITE).unwrap();
    let msg = b"hi from arm64\n";
    emu.core_mut().backend_mut().mem_write(msg_addr, msg).unwrap();

    // X0 = 1 (stdout), X1 = msg_addr, X2 = msg.len(), X8 = 64 (write), SVC #0
    // X0 = 7, X8 = 94 (exit_group), SVC #0
    emu.core_mut().backend_mut().reg_write(Arm64Reg::X1 as u32, msg_addr).unwrap();
    let mut code = Vec::new();
    code.extend_from_slice(&0xd280_0020u32.to_le_bytes()); // mov x0, #1
    code.extend_from_slice(&0xd280_01c2u32.to_le_bytes()); // mov x2, #14
    code.extend_from_slice(&0xd280_0808u32.to_le_bytes()); // mov x8, #64 (write)
    code.extend_from_slice(&0xd400_0001u32.to_le_bytes()); // svc #0
    code.extend_from_slice(&0xd280_00e0u32.to_le_bytes()); // mov x0, #7
    code.extend_from_slice(&0xd280_0bc8u32.to_le_bytes()); // mov x8, #94 (exit_group)
    code.extend_from_slice(&0xd400_0001u32.to_le_bytes()); // svc #0
    emu.core_mut().backend_mut().mem_write(code_base, &code).unwrap();

    let err = emu
        .core_mut()
        .emulate(code_base, code_base + code.len() as u64)
        .unwrap_err();
    assert!(matches!(err, UnidbgError::StopEmulator(7)));
    assert_eq!(emu.fs().borrow().stdout.as_string(), "hi from arm64\n");
}

#[test]
fn real_dlsym_and_system_property_get() {
    let res_dir = android_resources_dir();
    let libc_path = res_dir.join("sdk23/lib64/libc.so");
    let backend = Box::new(UnicornBackend::new(Arch::Arm64, ArmMode::Arm64).unwrap());

    let mut emu = AndroidEmulatorBuilder::for_64_bit()
        .resolver(AndroidResolver::new(23, Arch::Arm64, res_dir))
        .build(backend)
        .unwrap();

    let libc = emu.load_library(libc_path, true).unwrap();
    let expected_strlen = libc.find_symbol_addr("strlen").unwrap();

    let buf = emu.core_mut().mmap(0, 0x1000, MemoryPerm::READ | MemoryPerm::WRITE).unwrap();
    let sym_name = buf;
    let prop_key = buf + 64;
    let prop_val = buf + 128;

    let ptr_sym = UnidbgPointer::new(sym_name, 8);
    let ptr_key = UnidbgPointer::new(prop_key, 8);
    let ptr_val = UnidbgPointer::new(prop_val, 8);
    ptr_sym.write_cstr(emu.core_mut().backend_mut(), "strlen").unwrap();
    ptr_key.write_cstr(emu.core_mut().backend_mut(), "ro.build.version.sdk").unwrap();

    let dlsym_addr = emu.find_symbol("dlsym").unwrap();
    let resolved = emu.call_function(dlsym_addr, &[0, sym_name]).unwrap();
    assert_eq!(resolved, expected_strlen);

    let prop_get_addr = emu.find_symbol("__system_property_get").unwrap();
    let len = emu.call_function(prop_get_addr, &[prop_key, prop_val]).unwrap();
    assert_eq!(len, 2);
    assert_eq!(ptr_val.read_cstr(emu.core().backend()).unwrap(), "23");
}

#[test]
fn real_arm32_jni_string_from_jni() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let res_dir = android_resources_dir();
    let so_path = root.join("unidbg/unidbg-android/src/test/resources/example_binaries/armeabi-v7a/libnative-lib.so");
    let backend = Box::new(UnicornBackend::new(Arch::Arm32, ArmMode::Arm32).unwrap());

    let mut emu = AndroidEmulatorBuilder::for_32_bit()
        .resolver(AndroidResolver::new(19, Arch::Arm32, res_dir))
        .build(backend)
        .unwrap();

    let vm = DalvikVM::init(&mut emu).unwrap();
    let module = emu.load_library(so_path, true).unwrap();
    emu.call_init_functions(&module).unwrap();
    let fn_addr = module
        .find_symbol_addr("Java_com_kanxue_test2_MainActivity_stringFromJNI")
        .unwrap();

    let env_ptr = vm.jni_env_ptr();
    let thiz = vm.add_local_string("MainActivity") as u64;
    let jstr_handle = match emu.call_function(fn_addr, &[env_ptr, thiz]) {
        Ok(v) => v as i32 as i64,
        Err(e) => {
            use unidbg_api::arm::backend::ArmReg;
            let b = emu.core().backend();
            let pc = b.reg_read(ArmReg::PC as u32).unwrap();
            let sp = b.reg_read(ArmReg::SP as u32).unwrap();
            let lr = b.reg_read(ArmReg::LR as u32).unwrap();
            let r0 = b.reg_read(ArmReg::R0 as u32).unwrap();
            let r1 = b.reg_read(ArmReg::R1 as u32).unwrap();
            let r2 = b.reg_read(ArmReg::R2 as u32).unwrap();
            let r3 = b.reg_read(ArmReg::R3 as u32).unwrap();
            panic!("call_function failed: {e:?} | pc={pc:#x} sp={sp:#x} lr={lr:#x} r0={r0:#x} r1={r1:#x} r2={r2:#x} r3={r3:#x}");
        }
    };
    let obj = vm.get_object(jstr_handle).expect("expected jstring object");
    assert_eq!(obj.as_str().unwrap(), "Hello from C++");
}

#[test]
fn real_arm64_jni_ffmpeg_get_version() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let res_dir = android_resources_dir();
    let so_path = root.join("unidbg/unidbg-android/src/test/resources/example_binaries/arm64-v8a/libtmessages.29.so");
    let backend = Box::new(UnicornBackend::new(Arch::Arm64, ArmMode::Arm64).unwrap());

    let mut emu = AndroidEmulatorBuilder::for_64_bit()
        .resolver(AndroidResolver::new(23, Arch::Arm64, res_dir))
        .build(backend)
        .unwrap();

    let vm = DalvikVM::init(&mut emu).unwrap();
    let module = emu.load_library(so_path, true).unwrap();
    let fn_addr = module
        .find_symbol_addr("Java_com_google_android_exoplayer2_ext_ffmpeg_FfmpegLibrary_ffmpegGetVersion")
        .unwrap();

    let env_ptr = vm.jni_env_ptr();
    let cls_h = vm.resolve_class("com/google/android/exoplayer2/ext/ffmpeg/FfmpegLibrary") as u64;
    let jstr_handle = emu.call_function(fn_addr, &[env_ptr, cls_h]).unwrap() as i64;
    let obj = vm.get_object(jstr_handle).expect("expected ffmpeg version jstring");
    let ver = obj.as_str().unwrap();
    assert!(!ver.is_empty(), "ffmpeg version string should not be empty");
}

struct CountingMallocSvc(Rc<Cell<usize>>);
impl Svc for CountingMallocSvc {
    fn name(&self) -> &str { "counting_malloc" }
    fn handle(&mut self, backend: &mut dyn Backend, memory: &mut MemoryManager) -> unidbg_api::error::Result<SvcResult> {
        self.0.set(self.0.get() + 1);
        let size = backend.reg_read(ArmReg::R0 as u32)? as usize;
        let blk = memory.malloc(backend, size.max(1), true)?;
        Ok(SvcResult::Return(blk.addr))
    }
}

#[test]
fn real_xhook_patches_got_and_intercepts_call() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let res_dir = android_resources_dir();
    let so_path = root.join("unidbg/unidbg-android/src/test/resources/example_binaries/armeabi-v7a/libnative-lib.so");
    let backend = Box::new(UnicornBackend::new(Arch::Arm32, ArmMode::Arm32).unwrap());

    let mut emu = AndroidEmulatorBuilder::for_32_bit()
        .resolver(AndroidResolver::new(19, Arch::Arm32, res_dir))
        .build(backend)
        .unwrap();

    let vm = DalvikVM::init(&mut emu).unwrap();
    let module = emu.load_library(so_path, true).unwrap();
    emu.call_init_functions(&module).unwrap();

    let hits = Rc::new(Cell::new(0usize));
    let hook_addr = emu.core_mut().register_svc(Box::new(CountingMallocSvc(hits.clone()))).unwrap();

    let mut xhook = XHook::new(Arch::Arm32);
    xhook.register("libnative-lib.so", "malloc", hook_addr);
    let loader = emu.loader().clone();
    let patched = xhook.refresh(&loader.borrow(), emu.core_mut().backend_mut()).unwrap();
    assert_eq!(patched, 1);

    let fn_addr = module.find_symbol_addr("Java_com_kanxue_test2_MainActivity_stringFromJNI").unwrap();
    let thiz = vm.add_local_string("MainActivity") as u64;
    let _ = emu.call_function(fn_addr, &[vm.jni_env_ptr(), thiz]).unwrap();
    assert!(hits.get() >= 1, "expected XHook malloc callback to fire at least once");
}

struct Return999Svc;
impl Svc for Return999Svc {
    fn name(&self) -> &str { "ret_999" }
    fn handle(&mut self, _: &mut dyn Backend, _: &mut MemoryManager) -> unidbg_api::error::Result<SvcResult> {
        Ok(SvcResult::Return(999))
    }
}

#[test]
fn real_inline_hook_replaces_libc_strlen() {
    let res_dir = android_resources_dir();
    let libc_path = res_dir.join("sdk23/lib64/libc.so");
    let backend = Box::new(UnicornBackend::new(Arch::Arm64, ArmMode::Arm64).unwrap());

    let mut emu = AndroidEmulatorBuilder::for_64_bit()
        .resolver(AndroidResolver::new(23, Arch::Arm64, res_dir))
        .build(backend)
        .unwrap();

    let libc = emu.load_library(libc_path, true).unwrap();
    let strlen_addr = libc.find_symbol_addr("strlen").unwrap();

    let insns = InlineHook::inspect(Arch::Arm64, emu.core().backend(), strlen_addr, 4).unwrap();
    assert_eq!(insns.len(), 4);

    let hook_svc = emu.core_mut().register_svc(Box::new(Return999Svc)).unwrap();
    let orig = InlineHook::replace(Arch::Arm64, emu.core_mut().backend_mut(), strlen_addr, hook_svc).unwrap();
    assert_eq!(orig.len(), 16);

    let s = emu.core_mut().mmap(0, 0x1000, MemoryPerm::READ | MemoryPerm::WRITE).unwrap();
    UnidbgPointer::new(s, 8).write_cstr(emu.core_mut().backend_mut(), "hello").unwrap();

    let res = emu.call_function(strlen_addr, &[s]).unwrap();
    assert_eq!(res, 999);
}

#[test]
fn real_unwinder_resolves_3_frames_and_demangles_cpp() {
    assert_eq!(
        AndroidUnwinder::demangle("_ZN7android7String8C1EPKc").as_deref(),
        Some("android::String8::String8(char const*)")
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let res_dir = android_resources_dir();
    let so_path = root.join("unidbg/unidbg-android/src/test/resources/example_binaries/arm64-v8a/libtmessages.29.so");
    let backend = Box::new(UnicornBackend::new(Arch::Arm64, ArmMode::Arm64).unwrap());

    let mut emu = AndroidEmulatorBuilder::for_64_bit()
        .resolver(AndroidResolver::new(23, Arch::Arm64, res_dir))
        .build(backend)
        .unwrap();

    let module = emu.load_library(so_path, true).unwrap();
    let f1 = module.find_symbol_addr("JNI_OnLoad").unwrap() + 8;
    let f2 = module.find_symbol_addr("Java_com_google_android_exoplayer2_ext_ffmpeg_FfmpegLibrary_ffmpegGetVersion").unwrap() + 4;
    let f3 = module.find_symbol_addr("Java_com_google_android_exoplayer2_ext_ffmpeg_FfmpegLibrary_ffmpegHasDecoder").unwrap() + 4;

    // Build a 3-frame FP chain in guest stack memory: fp0 -> fp1 -> fp2 -> 0
    let stack = emu.core_mut().mmap(0, 0x1000, MemoryPerm::READ | MemoryPerm::WRITE).unwrap();
    let fp0 = stack + 0x100;
    let fp1 = stack + 0x200;
    let fp2 = stack + 0x300;
    let b = emu.core_mut().backend_mut();
    b.reg_write(Arm64Reg::PC as u32, f1).unwrap();
    b.reg_write(Arm64Reg::X29 as u32, fp0).unwrap();
    UnidbgPointer::new(fp0, 8).write_u64(b, fp1).unwrap();
    UnidbgPointer::new(fp0 + 8, 8).write_u64(b, f2).unwrap();
    UnidbgPointer::new(fp1, 8).write_u64(b, fp2).unwrap();
    UnidbgPointer::new(fp1 + 8, 8).write_u64(b, f3).unwrap();
    UnidbgPointer::new(fp2, 8).write_u64(b, 0).unwrap();

    let loader = emu.loader().borrow();
    let unwinder = AndroidUnwinder::new(Arch::Arm64, &loader);
    let frames = unwinder.unwind(emu.core().backend(), 8).unwrap();
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0].symbol.as_deref(), Some("JNI_OnLoad"));
    assert_eq!(frames[0].offset, 8);
    assert_eq!(frames[1].module.as_deref(), Some("libtmessages.29.so"));
    assert_eq!(frames[2].offset, 4);
}

#[test]
fn real_worker_pool_runs_arm64_libc_strlen_in_parallel() {
    use std::sync::Arc;
    use unidbg_api::worker::{Worker, WorkerFactory, WorkerPool};

    struct LibcWorker {
        emu: unidbg_android::emulator::AndroidEmulator,
        strlen_addr: u64,
        buf_addr: u64,
    }

    impl Worker for LibcWorker {
        type Input = String;
        type Output = u64;

        fn handle(&mut self, input: Self::Input) -> Self::Output {
            UnidbgPointer::new(self.buf_addr, 8)
                .write_cstr(self.emu.core_mut().backend_mut(), &input)
                .unwrap();
            self.emu.call_function(self.strlen_addr, &[self.buf_addr]).unwrap()
        }
    }

    struct LibcFactory(PathBuf);
    impl WorkerFactory<LibcWorker> for LibcFactory {
        fn create(&self) -> LibcWorker {
            let libc_path = self.0.join("sdk23/lib64/libc.so");
            let backend = Box::new(UnicornBackend::new(Arch::Arm64, ArmMode::Arm64).unwrap());
            let mut emu = AndroidEmulatorBuilder::for_64_bit()
                .resolver(AndroidResolver::new(23, Arch::Arm64, &self.0))
                .build(backend)
                .unwrap();
            let libc = emu.load_library(libc_path, true).unwrap();
            let strlen_addr = libc.find_symbol_addr("strlen").unwrap();
            let buf_addr = emu
                .core_mut()
                .mmap(0, 0x1000, MemoryPerm::READ | MemoryPerm::WRITE)
                .unwrap();
            LibcWorker {
                emu,
                strlen_addr,
                buf_addr,
            }
        }
    }

    let pool = WorkerPool::new(4, Arc::new(LibcFactory(android_resources_dir())));
    let jobs: Vec<_> = (1..=20usize)
        .map(|i| {
            let s = "a".repeat(i);
            (i as u64, pool.submit(s))
        })
        .collect();

    for (expected, rx) in jobs {
        assert_eq!(rx.recv().unwrap(), expected);
    }
}

#[test]
fn real_virtual_modules_resolve_and_execute() {
    use unidbg_android::virtual_module::{AndroidModule, JniGraphics, MediaNdkModule, SystemProperties};

    let backend = Box::new(UnicornBackend::new(Arch::Arm64, ArmMode::Arm64).unwrap());
    let mut emu = AndroidEmulatorBuilder::for_64_bit().build(backend).unwrap();

    AndroidModule::register(&mut emu).unwrap();
    JniGraphics::register(&mut emu).unwrap();
    MediaNdkModule::register(&mut emu).unwrap();
    SystemProperties::register(&mut emu).unwrap();

    let asset_from_java = emu.find_symbol("AAssetManager_fromJava").unwrap();
    let bitmap_info = emu.find_symbol("AndroidBitmap_getInfo").unwrap();
    let drm_create = emu.find_symbol("AMediaDrm_createByUUID").unwrap();

    assert_eq!(emu.call_function(asset_from_java, &[0, 0]).unwrap(), 0x1000);
    assert_eq!(emu.call_function(bitmap_info, &[0, 0, 0]).unwrap(), 0);
    assert_eq!(emu.call_function(drm_create, &[0]).unwrap(), 0x2000);
}

#[test]
fn real_arm32_tt_encrypt() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let res_dir = android_resources_dir();
    let so_path = root.join("unidbg/unidbg-android/src/test/resources/example_binaries/libttEncrypt.so");
    let backend = Box::new(UnicornBackend::new(Arch::Arm32, ArmMode::Arm32).unwrap());

    let mut emu = AndroidEmulatorBuilder::for_32_bit()
        .resolver(AndroidResolver::new(19, Arch::Arm32, res_dir))
        .build(backend)
        .unwrap();

    let vm = DalvikVM::init(&mut emu).unwrap();
    let module = emu.load_library(so_path, true).unwrap();
    emu.call_init_functions(&module).unwrap();

    let fn_addr = module
        .find_symbol_addr("Java_com_bytedance_frameworks_core_encrypt_TTEncryptUtils_ttEncrypt")
        .unwrap();

    let cls = vm.resolve_class("com/bytedance/frameworks/core/encrypt/TTEncryptUtils") as u64;
    let input = vm.add_local_bytes(vec![0u8; 16]) as u64;

    let out_handle = emu
        .call_function(fn_addr, &[vm.jni_env_ptr(), cls, input, 16])
        .unwrap() as i32 as i64;
    let out_obj = vm.get_object(out_handle).expect("expected encrypted jbyteArray");
    let encrypted = out_obj.as_bytes().expect("expected ByteArray payload");
    assert!(encrypted.len() > 16, "encrypted output should be > 16 bytes, got {}", encrypted.len());
}

#[test]
fn real_arm32_busybox_echo() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let res_dir = android_resources_dir();
    let busybox = root.join("unidbg/unidbg-android/src/test/resources/example_binaries/busybox");
    let backend = Box::new(UnicornBackend::new(Arch::Arm32, ArmMode::Arm32).unwrap());

    let mut emu = AndroidEmulatorBuilder::for_32_bit()
        .resolver(AndroidResolver::new(19, Arch::Arm32, res_dir))
        .build(backend)
        .unwrap();
    let module = emu.load_library(busybox, true).unwrap();
    let code = emu.call_entry(&module, &["echo", "hello-from-busybox"]).unwrap();
    let out = emu.fs().borrow().stdout.as_string();
    let err_out = emu.fs().borrow().stderr.as_string();
    assert_eq!(code, 0, "busybox exit={code}, stdout={out:?}, stderr={err_out:?}");
    assert_eq!(out, "hello-from-busybox\n");
}

#[test]
fn java_parity_crackme1() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let res_dir = android_resources_dir();
    let crackme = root.join("unidbg/unidbg-android/src/test/resources/example_binaries/crackme1");
    let backend = Box::new(UnicornBackend::new(Arch::Arm32, ArmMode::Arm32).unwrap());

    let mut emu = AndroidEmulatorBuilder::for_32_bit()
        .process_name("crackme1")
        .resolver(AndroidResolver::new(19, Arch::Arm32, res_dir))
        .build(backend)
        .unwrap();

    let module = emu.load_library(crackme, true).unwrap();
    let code = emu.call_entry(&module, &["crackme1", "password"]).unwrap();
    let out = emu.fs().borrow().stdout.as_string();
    // crackme1 prints "no\n" or "yes\n" and exits cleanly
    assert!(code == 0 || code == 1, "unexpected exit code {code}");
    assert!(!out.is_empty(), "expected crackme1 output on stdout, got empty");
}

#[test]
fn java_parity_main_activity_jnitest() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let res_dir = android_resources_dir();
    let so_path = root.join("unidbg/unidbg-android/src/test/resources/example_binaries/armeabi-v7a/libnative-lib.so");
    let backend = Box::new(UnicornBackend::new(Arch::Arm32, ArmMode::Arm32).unwrap());

    let mut emu = AndroidEmulatorBuilder::for_32_bit()
        .resolver(AndroidResolver::new(19, Arch::Arm32, res_dir))
        .build(backend)
        .unwrap();

    let vm = DalvikVM::init(&mut emu).unwrap();
    let module = emu.load_library(so_path, true).unwrap();
    emu.call_init_functions(&module).unwrap();

    let fn_addr = module
        .find_symbol_addr("Java_com_kanxue_test2_MainActivity_jnitest")
        .unwrap();
    let thiz = vm.add_local_string("MainActivity") as u64;
    let wrong = vm.add_local_string("AAA") as u64;
    let res = emu.call_function(fn_addr, &[vm.jni_env_ptr(), thiz, wrong]).unwrap() & 0xff;
    assert_eq!(res, 0);
}

#[test]
fn real_arm64_libtmessages_jni_onload_and_register_natives() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let res_dir = android_resources_dir();
    let so_path = root.join("unidbg/unidbg-android/src/test/resources/example_binaries/arm64-v8a/libtmessages.29.so");
    let backend = Box::new(UnicornBackend::new(Arch::Arm64, ArmMode::Arm64).unwrap());

    let mut emu = AndroidEmulatorBuilder::for_64_bit()
        .resolver(AndroidResolver::new(23, Arch::Arm64, res_dir))
        .build(backend)
        .unwrap();

    let vm = DalvikVM::init(&mut emu).unwrap();
    let module = emu.load_library(so_path, true).unwrap();
    let jni_ver = vm.call_jni_onload(&mut emu, &module).unwrap();
    assert_eq!(jni_ver, 0x0001_0006);
    assert!(
        !vm.state.borrow().registered_natives.is_empty(),
        "expected libtmessages.29.so JNI_OnLoad to call RegisterNatives"
    );
}
