use std::io::Write;
use std::path::{Path, PathBuf};
use unidbg_api::arm::backend::{Backend, MemoryPerm};
use unidbg_api::arm::{Arch, ArmMode};
use unidbg_api::emulator::Emulator;
use unidbg_api::error::UnidbgError;
use unidbg_api::memory::MemoryManager;
use unidbg_api::svc::{Svc, SvcResult};
use unidbg_ios::emulator::DarwinEmulator;
use unidbg_ios::fixup_chains::FixupChains;
use unidbg_ios::hook::{FishHook, Substrate};
use unidbg_ios::ipa::IpaLoader;
use unidbg_ios::objc::ObjcRuntime;
use unidbg_api::pointer::UnidbgPointer;
use unidbg_unicorn2::unicorn_backend::UnicornBackend;
use zip::write::SimpleFileOptions;

fn ios_examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("unidbg/unidbg-ios/src/test/resources/example_binaries")
}

struct Hook777Svc;
impl Svc for Hook777Svc {
    fn name(&self) -> &str {
        "hook_777"
    }
    fn handle(&mut self, _: &mut dyn Backend, _: &mut MemoryManager) -> unidbg_api::error::Result<SvcResult> {
        Ok(SvcResult::Return(777))
    }
}

#[test]
fn real_load_macho_arm64_dylib_and_substrate_hook() {
    let dylib = ios_examples_dir().join("libsubstrate_arm64.dylib");
    let backend = Box::new(UnicornBackend::new(Arch::Arm64, ArmMode::Arm64).unwrap());
    let mut emu = DarwinEmulator::new(Arch::Arm64, "ios_test", backend).unwrap();

    let module = emu.load_macho(dylib).unwrap();
    assert!(module.size > 0);
    assert!(!module.symbols.is_empty());

    let sym_addr = module
        .find_symbol_addr("MSHookFunction")
        .or_else(|| module.symbols.values().next().copied())
        .unwrap();

    let svc_addr = emu.core_mut().register_svc(Box::new(Hook777Svc)).unwrap();
    let orig = Substrate::hook_function(Arch::Arm64, emu.core_mut().backend_mut(), sym_addr, svc_addr).unwrap();
    assert_eq!(orig.len(), 16);

    let ret = emu.call_function(sym_addr, &[]).unwrap();
    assert_eq!(ret, 777);
}

#[test]
fn real_load_macho_approov_framework_and_fishhook() {
    let bin = ios_examples_dir().join("Approov.framework/Approov");
    let backend = Box::new(UnicornBackend::new(Arch::Arm64, ArmMode::Arm64).unwrap());
    let mut emu = DarwinEmulator::new(Arch::Arm64, "approov", backend).unwrap();

    let module = emu.load_macho(bin).unwrap();
    assert!(module.size > 0);
    assert!(!module.needed_dylibs.is_empty());

    if let Some((key, _)) = module.symbol_ptrs.iter().next().map(|(k, v)| (k.clone(), v.clone())) {
        let fh = FishHook::new(Arch::Arm64);
        let (loader, core) = emu.loader_and_core_mut();
        let count = fh
            .rebind_by_key(loader, core.backend_mut(), &key, 0x1234_5678)
            .unwrap();
        assert!(count >= 1);
    }
}

#[test]
fn real_ipa_loader_reads_real_info_plist() {
    let real_plist = std::fs::read(ios_examples_dir().join("Approov.framework/Info.plist")).unwrap();
    let ipa_path = std::env::temp_dir().join("unidbg_rs_test.ipa");
    {
        let file = std::fs::File::create(&ipa_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("Payload/TestApp.app/Info.plist", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(&real_plist).unwrap();
        zip.finish().unwrap();
    }

    let loader = IpaLoader::new(&ipa_path);
    let dict = loader.read_info_plist().unwrap();
    assert!(dict.contains_key("CFBundleIdentifier") || dict.contains_key("CFBundleName"));
    let _ = std::fs::remove_file(&ipa_path);
}

#[test]
fn real_darwin_arm64_syscalls_getpid_and_exit() {
    let backend = Box::new(UnicornBackend::new(Arch::Arm64, ArmMode::Arm64).unwrap());
    let mut emu = DarwinEmulator::new(Arch::Arm64, "darwin_sys", backend).unwrap();

    let code_base = emu.core_mut().mmap(0, 0x1000, MemoryPerm::ALL).unwrap();
    // mov x16, #20 (getpid) ; svc #0x80 ; mov x0, #5 ; mov x16, #1 (exit) ; svc #0x80
    let mut code = Vec::new();
    code.extend_from_slice(&0xd280_0290u32.to_le_bytes()); // mov x16, #20
    code.extend_from_slice(&0xd400_1001u32.to_le_bytes()); // svc #0x80
    code.extend_from_slice(&0xd280_00a0u32.to_le_bytes()); // mov x0, #5
    code.extend_from_slice(&0xd280_0030u32.to_le_bytes()); // mov x16, #1
    code.extend_from_slice(&0xd400_1001u32.to_le_bytes()); // svc #0x80
    emu.core_mut().backend_mut().mem_write(code_base, &code).unwrap();

    let err = emu
        .core_mut()
        .emulate(code_base, code_base + code.len() as u64)
        .unwrap_err();
    assert!(matches!(err, UnidbgError::StopEmulator(5)));
}

#[test]
fn real_objc_runtime_and_fixup_chains() {
    let backend = Box::new(UnicornBackend::new(Arch::Arm64, ArmMode::Arm64).unwrap());
    let mut emu = DarwinEmulator::new(Arch::Arm64, "objc_test", backend).unwrap();
    let objc = ObjcRuntime::init(&mut emu).unwrap();

    let buf = emu.core_mut().mmap(0, 0x1000, MemoryPerm::READ | MemoryPerm::WRITE).unwrap();
    UnidbgPointer::new(buf, 8)
        .write_cstr(emu.core_mut().backend_mut(), "NSString")
        .unwrap();
    UnidbgPointer::new(buf + 64, 8)
        .write_cstr(emu.core_mut().backend_mut(), "stringWithUTF8String:")
        .unwrap();

    let cls = emu.call_function(objc.objc_get_class_addr, &[buf]).unwrap();
    let sel = emu.call_function(objc.sel_register_name_addr, &[buf + 64]).unwrap();
    assert!(cls >= 0x8000_0001);
    assert!(sel > cls);
    assert_eq!(emu.call_function(objc.objc_msg_send_addr, &[cls, sel]).unwrap(), cls);

    // Verify FixupChains 64-bit rebase chain across 2 linked pointers (next = 8 bytes => field=2)
    let chain_page = emu.core_mut().mmap(0, 0x1000, MemoryPerm::READ | MemoryPerm::WRITE).unwrap();
    let p0: u64 = (2u64 << 51) | 0x1234;
    let p1: u64 = 0x5678; // next = 0 (end of chain)
    emu.core_mut().backend_mut().mem_write(chain_page, &p0.to_le_bytes()).unwrap();
    emu.core_mut().backend_mut().mem_write(chain_page + 8, &p1.to_le_bytes()).unwrap();

    let fixed = FixupChains::apply_64_rebase_chain(emu.core_mut().backend_mut(), 0x1_0000_0000, chain_page).unwrap();
    assert_eq!(fixed, 2);
    assert_eq!(UnidbgPointer::new(chain_page, 8).read_u64(emu.core().backend()).unwrap(), 0x1_0000_1234);
    assert_eq!(UnidbgPointer::new(chain_page + 8, 8).read_u64(emu.core().backend()).unwrap(), 0x1_0000_5678);
}
