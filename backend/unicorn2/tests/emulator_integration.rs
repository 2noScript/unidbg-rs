use unidbg_api::arm::backend::{Arm64Reg, Backend, MemoryPerm};
use unidbg_api::arm::{Arch, ArmMode};
use unidbg_api::emulator::{Emulator, EmulatorCore, Family};
use unidbg_api::error::Result;
use unidbg_api::memory::MemoryManager;
use unidbg_api::svc::{Svc, SvcResult};
use unidbg_api::trace::AssemblyCodeDumper;
use unidbg_unicorn2::unicorn_backend::UnicornBackend;

struct AddSvc;

impl Svc for AddSvc {
    fn name(&self) -> &str {
        "test_add"
    }

    fn handle(&mut self, backend: &mut dyn Backend, _memory: &mut MemoryManager) -> Result<SvcResult> {
        let x0 = backend.reg_read(Arm64Reg::X0 as u32)?;
        let x1 = backend.reg_read(Arm64Reg::X1 as u32)?;
        Ok(SvcResult::Return(x0 + x1))
    }
}

#[test]
fn emulator_calls_registered_svc_and_traces_memory() {
    let backend = Box::new(UnicornBackend::new(Arch::Arm64, ArmMode::Arm64).unwrap());
    let mut emu = EmulatorCore::new(Family::Android64, ArmMode::Arm64, "svc_test", backend).unwrap();

    let svc_addr = emu.register_svc(Box::new(AddSvc)).unwrap();

    // Map code & data pages
    let code_base = 0x10000u64;
    let data_base = 0x20000u64;
    emu.mmap(code_base, 0x1000, MemoryPerm::ALL).unwrap();
    emu.mmap(data_base, 0x1000, MemoryPerm::READ | MemoryPerm::WRITE)
        .unwrap();

    let (_mem_hook, mem_tracer) = emu.trace_memory(data_base, data_base + 0x100).unwrap();

    // Guest ARM64 code:
    //   mov x0, #19
    //   mov x1, #23
    //   mov x2, svc_addr (via X2)
    //   blr x2
    //   str x0, [x3]   (write result 42 to data_base)
    //   nop (until)
    emu.backend_mut().reg_write(Arm64Reg::X2 as u32, svc_addr).unwrap();
    emu.backend_mut().reg_write(Arm64Reg::X3 as u32, data_base).unwrap();

    let mut code = Vec::new();
    code.extend_from_slice(&0xd280_0260u32.to_le_bytes()); // mov x0, #19
    code.extend_from_slice(&0xd280_02e1u32.to_le_bytes()); // mov x1, #23
    code.extend_from_slice(&0xd63f_0040u32.to_le_bytes()); // blr x2
    code.extend_from_slice(&0xf900_0060u32.to_le_bytes()); // str x0, [x3]
    let until = code_base + code.len() as u64;
    code.extend_from_slice(&0xd503_201fu32.to_le_bytes()); // nop

    emu.backend_mut().mem_write(code_base, &code).unwrap();

    // Also verify Capstone disassembler on the exact code buffer
    let dumper = AssemblyCodeDumper::new(ArmMode::Arm64).unwrap();
    let disasm = dumper.disassemble(&code, code_base).unwrap();
    assert_eq!(disasm.len(), 5);

    let ret = emu.emulate(code_base, until).unwrap();
    assert_eq!(ret, 42);

    let mem_records = mem_tracer.records();
    assert_eq!(mem_records.len(), 1);
    assert_eq!(mem_records[0].addr, data_base);
    assert_eq!(mem_records[0].value, 42);
}
