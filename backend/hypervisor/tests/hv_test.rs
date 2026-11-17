#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn hypervisor_runs_arm64_add() {
    use unidbg_api::arm::backend::{Arm64Reg, Backend, MemoryPerm};
    use unidbg_hypervisor::hypervisor_backend::HypervisorBackend;

    let mut hv = match HypervisorBackend::new() {
        Ok(b) => b,
        Err(e) => {
            // If unsigned test binary lacks com.apple.security.hypervisor entitlement,
            // codesign with backend/hypervisor/entitlements.plist to run on hardware.
            let msg = format!("{e}");
            if msg.contains("com.apple.security.hypervisor") {
                eprintln!("SKIPPED (unsigned binary): {msg}");
                return;
            }
            panic!("unexpected HypervisorBackend::new error: {msg}");
        }
    };

    let base = 0x1000_0000u64;
    hv.mem_map(base, 0x4000, MemoryPerm::ALL).unwrap();

    // mov x0, #10 ; add x0, x0, #32 ; brk #0
    let mut code = Vec::new();
    code.extend_from_slice(&0xd280_0140u32.to_le_bytes());
    code.extend_from_slice(&0x9100_8000u32.to_le_bytes());
    code.extend_from_slice(&0xd420_0000u32.to_le_bytes());
    hv.mem_write(base, &code).unwrap();

    hv.emu_start(base, 0, 0, 0).unwrap();
    assert_eq!(hv.reg_read(Arm64Reg::X0 as u32).unwrap(), 42);
}
