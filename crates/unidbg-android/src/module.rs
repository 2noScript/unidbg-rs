use std::collections::HashMap;
use unidbg_api::module::{Module, Symbol};

/// Loaded ELF shared library or executable (`LinuxModule`).
#[derive(Debug, Clone)]
pub struct LinuxModule {
    pub name: String,
    pub base: u64,
    pub size: usize,
    pub entry_point: u64,
    pub phdr_addr: u64,
    pub phnum: u16,
    pub phentsize: u16,
    pub needed: Vec<String>,
    pub init_functions: Vec<u64>,
    pub symbols: HashMap<String, u64>,
    pub plt_got: HashMap<String, u64>,
}

impl LinuxModule {
    pub fn find_symbol_addr(&self, name: &str) -> Option<u64> {
        self.symbols.get(name).copied()
    }
}

impl Module for LinuxModule {
    fn name(&self) -> &str {
        &self.name
    }

    fn base(&self) -> u64 {
        self.base
    }

    fn size(&self) -> usize {
        self.size
    }

    fn entry_point(&self) -> u64 {
        self.entry_point
    }

    fn find_symbol(&self, name: &str) -> Option<Symbol> {
        self.symbols.get(name).map(|&address| Symbol {
            name: name.to_string(),
            address,
        })
    }
}
