pub mod gdb;

use std::collections::HashMap;

/// Breakpoint metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakPoint {
    pub addr: u64,
    pub temporary: bool,
    pub enabled: bool,
}

/// Debugger interface (`Debugger`).
pub trait Debugger {
    fn add_breakpoint(&mut self, addr: u64, temporary: bool);
    fn del_breakpoint(&mut self, addr: u64);
    fn has_breakpoint(&self, addr: u64) -> bool;
    fn set_single_step(&mut self, enabled: bool);
    fn is_single_step(&self) -> bool;
}

/// Default ARM32/ARM64 breakpoint & single-step state (`SimpleARMDebugger`).
#[derive(Default)]
pub struct SimpleArmDebugger {
    breakpoints: HashMap<u64, BreakPoint>,
    single_step: bool,
}

impl SimpleArmDebugger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn breakpoints(&self) -> Vec<&BreakPoint> {
        self.breakpoints.values().collect()
    }
}

impl Debugger for SimpleArmDebugger {
    fn add_breakpoint(&mut self, addr: u64, temporary: bool) {
        self.breakpoints.insert(
            addr,
            BreakPoint {
                addr,
                temporary,
                enabled: true,
            },
        );
    }

    fn del_breakpoint(&mut self, addr: u64) {
        self.breakpoints.remove(&addr);
    }

    fn has_breakpoint(&self, addr: u64) -> bool {
        self.breakpoints
            .get(&addr)
            .is_some_and(|bp| bp.enabled)
    }

    fn set_single_step(&mut self, enabled: bool) {
        self.single_step = enabled;
    }

    fn is_single_step(&self) -> bool {
        self.single_step
    }
}
