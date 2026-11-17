use crate::arm::backend::{Backend, BackendContext};
use crate::error::Result;
use crate::signal::SigSet;
use std::collections::VecDeque;

/// Cooperative thread state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Runnable,
    Waiting,
    Finished,
}

/// Condition checked before waking a waiting task.
pub trait Waiter {
    fn can_wakeup(&mut self) -> bool;
}

/// A cooperative guest execution task (main thread, cloned pthread, or nested function call).
pub struct Task {
    pub id: u32,
    pub entry: u64,
    pub until: u64,
    pub status: TaskStatus,
    pub context: Box<dyn BackendContext>,
    pub sig_mask: SigSet,
    pub waiter: Option<Box<dyn Waiter>>,
    pub return_value: Option<u64>,
}

/// Cooperative round-robin thread dispatcher (replaces `UniThreadDispatcher`).
pub struct UniThreadDispatcher {
    next_id: u32,
    queue: VecDeque<Task>,
}

impl UniThreadDispatcher {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            queue: VecDeque::new(),
        }
    }

    pub fn add_task(&mut self, backend: &dyn Backend, entry: u64, until: u64) -> Result<u32> {
        let id = self.next_id;
        self.next_id += 1;
        let mut context = backend.context_alloc()?;
        backend.context_save(context.as_mut())?;
        self.queue.push_back(Task {
            id,
            entry,
            until,
            status: TaskStatus::Runnable,
            context,
            sig_mask: SigSet::default(),
            waiter: None,
            return_value: None,
        });
        Ok(id)
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Pop the next runnable task (waking any waiting task whose [`Waiter`] is ready).
    pub fn pop_runnable(&mut self) -> Option<Task> {
        let count = self.queue.len();
        for _ in 0..count {
            let mut task = self.queue.pop_front()?;
            match task.status {
                TaskStatus::Finished => continue,
                TaskStatus::Waiting => {
                    let ready = task.waiter.as_mut().map_or(true, |w| w.can_wakeup());
                    if ready {
                        task.status = TaskStatus::Runnable;
                        task.waiter = None;
                        return Some(task);
                    }
                    self.queue.push_back(task);
                }
                TaskStatus::Runnable => return Some(task),
            }
        }
        None
    }

    pub fn push_task(&mut self, task: Task) {
        if task.status != TaskStatus::Finished {
            self.queue.push_back(task);
        }
    }
}

impl Default for UniThreadDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arm::backend::tests::MockBackend;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct FlagWaiter(Arc<AtomicBool>);
    impl Waiter for FlagWaiter {
        fn can_wakeup(&mut self) -> bool {
            self.0.load(Ordering::Relaxed)
        }
    }

    #[test]
    fn cooperative_scheduler_wakes_waiter() {
        let backend = MockBackend::new();
        let mut disp = UniThreadDispatcher::new();
        let ready = Arc::new(AtomicBool::new(false));

        let t1 = disp.add_task(&backend, 0x1000, 0x2000).unwrap();
        let mut task1 = disp.pop_runnable().unwrap();
        assert_eq!(task1.id, t1);
        task1.status = TaskStatus::Waiting;
        task1.waiter = Some(Box::new(FlagWaiter(ready.clone())));
        disp.push_task(task1);

        // Not ready yet
        assert!(disp.pop_runnable().is_none());

        // Signal waiter
        ready.store(true, Ordering::Relaxed);
        let woken = disp.pop_runnable().unwrap();
        assert_eq!(woken.id, t1);
        assert_eq!(woken.status, TaskStatus::Runnable);
    }
}
