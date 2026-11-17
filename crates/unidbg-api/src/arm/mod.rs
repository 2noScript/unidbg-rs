pub mod backend;
pub mod svc;

/// Target CPU architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arch {
    Arm32,
    Arm64,
}

/// ARM execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArmMode {
    Arm32,
    Thumb,
    Arm64,
}
