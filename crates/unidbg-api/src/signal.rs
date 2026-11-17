/// POSIX signal mask.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SigSet(pub u64);

impl SigSet {
    pub fn add(&mut self, signum: u32) {
        if (1..=64).contains(&signum) {
            self.0 |= 1u64 << (signum - 1);
        }
    }

    pub fn remove(&mut self, signum: u32) {
        if (1..=64).contains(&signum) {
            self.0 &= !(1u64 << (signum - 1));
        }
    }

    pub fn contains(&self, signum: u32) -> bool {
        (1..=64).contains(&signum) && (self.0 & (1u64 << (signum - 1))) != 0
    }
}

/// Queued guest signal task.
#[derive(Debug, Clone)]
pub struct SignalTask {
    pub signum: u32,
    pub handler: u64,
    pub restorer: u64,
}

/// Signal delivery operations on an emulator thread.
pub trait SignalOps {
    fn sig_procmask(&mut self, how: i32, set: Option<SigSet>) -> SigSet;
    fn send_signal(&mut self, task: SignalTask);
}
