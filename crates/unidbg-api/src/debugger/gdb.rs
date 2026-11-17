use crate::arm::backend::{Arm64Reg, ArmReg, Backend};
use crate::arm::Arch;
use crate::debugger::{Debugger, SimpleArmDebugger};
use crate::error::Result;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

/// GDB Remote Serial Protocol (RSP) server (`GDBServer`).
/// Supports `qSupported`, `?`, `g`, `m`, `M`, `Z0`, `z0`, `s`, `c`, `k`.
pub struct GdbServer {
    arch: Arch,
    debugger: SimpleArmDebugger,
}

impl GdbServer {
    pub fn new(arch: Arch) -> Self {
        Self {
            arch,
            debugger: SimpleArmDebugger::new(),
        }
    }

    pub fn debugger_mut(&mut self) -> &mut SimpleArmDebugger {
        &mut self.debugger
    }

    /// Listen on `addr` (e.g. `"127.0.0.1:23946"`), accept one client, and serve RSP until `c`/`k`/EOF.
    pub fn serve_one(&mut self, addr: &str, backend: &mut dyn Backend) -> Result<()> {
        let listener = TcpListener::bind(addr)?;
        let (stream, _) = listener.accept()?;
        self.handle_stream(stream, backend)
    }

    pub fn handle_stream(&mut self, mut stream: TcpStream, backend: &mut dyn Backend) -> Result<()> {
        let mut buf = [0u8; 4096];
        let mut acc = Vec::new();
        loop {
            let n = stream.read(&mut buf)?;
            if n == 0 {
                break;
            }
            acc.extend_from_slice(&buf[..n]);
            while let Some((pkt, consumed)) = Self::extract_packet(&acc) {
                acc.drain(..consumed);
                let (reply, should_quit) = self.process_packet(&pkt, backend)?;
                let csum: u8 = reply.bytes().fold(0u8, |a, b| a.wrapping_add(b));
                let frame = format!("+${reply}#{csum:02x}");
                stream.write_all(frame.as_bytes())?;
                if should_quit {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn extract_packet(data: &[u8]) -> Option<(String, usize)> {
        let start = data.iter().position(|&b| b == b'$')?;
        let end = data[start + 1..].iter().position(|&b| b == b'#')? + start + 1;
        if end + 2 >= data.len() {
            return None;
        }
        let body = String::from_utf8_lossy(&data[start + 1..end]).into_owned();
        Some((body, end + 3))
    }

    fn process_packet(&mut self, pkt: &str, backend: &mut dyn Backend) -> Result<(String, bool)> {
        if pkt == "?" {
            return Ok(("S05".to_string(), false));
        }
        if pkt.starts_with("qSupported") {
            return Ok(("PacketSize=4096".to_string(), false));
        }
        if pkt == "g" {
            return Ok((self.read_all_regs_hex(backend)?, false));
        }
        if let Some(rest) = pkt.strip_prefix('m') {
            if let Some((addr_s, len_s)) = rest.split_once(',') {
                let addr = u64::from_str_radix(addr_s, 16).unwrap_or(0);
                let len = usize::from_str_radix(len_s, 16).unwrap_or(0).min(2048);
                let mut mem = vec![0u8; len];
                if backend.mem_read(addr, &mut mem).is_ok() {
                    let hex: String = mem.iter().map(|b| format!("{b:02x}")).collect();
                    return Ok((hex, false));
                }
                return Ok(("E01".to_string(), false));
            }
        }
        if let Some(rest) = pkt.strip_prefix('M') {
            if let Some((left, hex_data)) = rest.split_once(':') {
                if let Some((addr_s, _len_s)) = left.split_once(',') {
                    let addr = u64::from_str_radix(addr_s, 16).unwrap_or(0);
                    let bytes: Vec<u8> = (0..hex_data.len())
                        .step_by(2)
                        .filter_map(|i| hex_data.get(i..i + 2).and_then(|s| u8::from_str_radix(s, 16).ok()))
                        .collect();
                    if backend.mem_write(addr, &bytes).is_ok() {
                        return Ok(("OK".to_string(), false));
                    }
                    return Ok(("E01".to_string(), false));
                }
            }
        }
        if let Some(rest) = pkt.strip_prefix("Z0,") {
            if let Some((addr_s, _)) = rest.split_once(',') {
                if let Ok(addr) = u64::from_str_radix(addr_s, 16) {
                    self.debugger.add_breakpoint(addr, false);
                    return Ok(("OK".to_string(), false));
                }
            }
        }
        if let Some(rest) = pkt.strip_prefix("z0,") {
            if let Some((addr_s, _)) = rest.split_once(',') {
                if let Ok(addr) = u64::from_str_radix(addr_s, 16) {
                    self.debugger.del_breakpoint(addr);
                    return Ok(("OK".to_string(), false));
                }
            }
        }
        if pkt == "s" {
            let pc_reg = match self.arch {
                Arch::Arm64 => Arm64Reg::PC as u32,
                Arch::Arm32 => ArmReg::PC as u32,
            };
            let pc = backend.reg_read(pc_reg)?;
            backend.emu_start(pc, 0, 0, 1)?;
            return Ok(("S05".to_string(), false));
        }
        if pkt == "c" {
            return Ok(("S05".to_string(), true));
        }
        if pkt == "k" {
            return Ok(("".to_string(), true));
        }
        Ok(("".to_string(), false))
    }

    fn read_all_regs_hex(&self, backend: &dyn Backend) -> Result<String> {
        let mut out = String::new();
        match self.arch {
            Arch::Arm64 => {
                // X0..X30, SP, PC (33 * 8 bytes) + CPSR (4 bytes)
                let regs = [
                    Arm64Reg::X0, Arm64Reg::X1, Arm64Reg::X2, Arm64Reg::X3,
                    Arm64Reg::X4, Arm64Reg::X5, Arm64Reg::X6, Arm64Reg::X7,
                    Arm64Reg::X8, Arm64Reg::X9, Arm64Reg::X10, Arm64Reg::X11,
                    Arm64Reg::X12, Arm64Reg::X13, Arm64Reg::X14, Arm64Reg::X15,
                    Arm64Reg::X16, Arm64Reg::X17, Arm64Reg::X18, Arm64Reg::X19,
                    Arm64Reg::X20, Arm64Reg::X21, Arm64Reg::X22, Arm64Reg::X23,
                    Arm64Reg::X24, Arm64Reg::X25, Arm64Reg::X26, Arm64Reg::X27,
                    Arm64Reg::X28, Arm64Reg::X29, Arm64Reg::X30, Arm64Reg::SP,
                    Arm64Reg::PC,
                ];
                for r in regs {
                    let v = backend.reg_read(r as u32)?;
                    for b in v.to_le_bytes() {
                        out.push_str(&format!("{b:02x}"));
                    }
                }
                let nzcv = backend.reg_read(Arm64Reg::NZCV as u32)? as u32;
                for b in nzcv.to_le_bytes() {
                    out.push_str(&format!("{b:02x}"));
                }
            }
            Arch::Arm32 => {
                let regs = [
                    ArmReg::R0, ArmReg::R1, ArmReg::R2, ArmReg::R3,
                    ArmReg::R4, ArmReg::R5, ArmReg::R6, ArmReg::R7,
                    ArmReg::R8, ArmReg::R9, ArmReg::R10, ArmReg::R11,
                    ArmReg::R12, ArmReg::SP, ArmReg::LR, ArmReg::PC,
                    ArmReg::CPSR,
                ];
                for r in regs {
                    let v = backend.reg_read(r as u32)? as u32;
                    for b in v.to_le_bytes() {
                        out.push_str(&format!("{b:02x}"));
                    }
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arm::backend::tests::MockBackend;
    use crate::arm::backend::MemoryPerm;

    #[test]
    fn gdb_rsp_tcp_reads_regs_mem_and_sets_breakpoint() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_thread = std::thread::spawn(move || {
            let mut backend = MockBackend::new();
            backend.reg_write(Arm64Reg::X0 as u32, 0x1122_3344_5566_7788).unwrap();
            backend.mem_map(0x10000, 0x1000, MemoryPerm::ALL).unwrap();
            backend.mem_write(0x10000, &[0xaa, 0xbb, 0xcc, 0xdd]).unwrap();

            let (stream, _) = listener.accept().unwrap();
            let mut gdb = GdbServer::new(Arch::Arm64);
            gdb.handle_stream(stream, &mut backend).unwrap();
            assert!(gdb.debugger_mut().has_breakpoint(0x10004));
        });

        let mut client = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        let send_recv = |s: &mut TcpStream, cmd: &str| -> String {
            let csum: u8 = cmd.bytes().fold(0u8, |a, b| a.wrapping_add(b));
            s.write_all(format!("${cmd}#{csum:02x}").as_bytes()).unwrap();
            let mut buf = [0u8; 1024];
            let n = s.read(&mut buf).unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        };

        let r_g = send_recv(&mut client, "g");
        assert!(r_g.contains("8877665544332211"));

        let r_m = send_recv(&mut client, "m10000,4");
        assert!(r_m.contains("aabbccdd"));

        let r_bp = send_recv(&mut client, "Z0,10004,4");
        assert!(r_bp.contains("OK"));

        let _ = send_recv(&mut client, "k");
        server_thread.join().unwrap();
    }
}
