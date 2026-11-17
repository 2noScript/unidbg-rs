/// Resolved symbol inside a loaded [`Module`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
}

/// Loaded binary module (ELF `.so` / executable or Mach-O).
pub trait Module {
    fn name(&self) -> &str;
    fn base(&self) -> u64;
    fn size(&self) -> usize;
    fn entry_point(&self) -> u64;
    fn find_symbol(&self, name: &str) -> Option<Symbol>;
}
