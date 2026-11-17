use std::collections::VecDeque;
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::JoinHandle;

/// Per-thread worker holding an isolated emulator instance (`Worker`).
/// Created on the worker thread itself via [`WorkerFactory::create`], so `Worker` does not require `Send`.
pub trait Worker: 'static {
    type Input: Send + 'static;
    type Output: Send + 'static;

    fn handle(&mut self, input: Self::Input) -> Self::Output;
}

/// Factory creating one [`Worker`] per pool thread (`WorkerFactory`).
pub trait WorkerFactory<W: Worker>: Send + Sync + 'static {
    fn create(&self) -> W;
}

type Job<I, O> = (I, mpsc::Sender<O>);

struct SharedQueue<I, O> {
    jobs: VecDeque<Job<I, O>>,
    closed: bool,
}

/// Multi-threaded pool of isolated emulator workers (`WorkerPool` / `DefaultWorkerPool`).
pub struct WorkerPool<I: Send + 'static, O: Send + 'static> {
    state: Arc<(Mutex<SharedQueue<I, O>>, Condvar)>,
    threads: Vec<JoinHandle<()>>,
}

impl<I: Send + 'static, O: Send + 'static> WorkerPool<I, O> {
    pub fn new<W, F>(worker_count: usize, factory: Arc<F>) -> Self
    where
        W: Worker<Input = I, Output = O>,
        F: WorkerFactory<W>,
    {
        let count = worker_count.max(1);
        let state = Arc::new((
            Mutex::new(SharedQueue {
                jobs: VecDeque::new(),
                closed: false,
            }),
            Condvar::new(),
        ));

        let mut threads = Vec::with_capacity(count);
        for _ in 0..count {
            let st = state.clone();
            let fac = factory.clone();
            threads.push(std::thread::spawn(move || {
                let mut worker = fac.create();
                loop {
                    let job = {
                        let (lock, cv) = &*st;
                        let mut q = lock.lock().unwrap();
                        while q.jobs.is_empty() && !q.closed {
                            q = cv.wait(q).unwrap();
                        }
                        if let Some(j) = q.jobs.pop_front() {
                            j
                        } else if q.closed {
                            break;
                        } else {
                            continue;
                        }
                    };
                    let (input, reply_tx) = job;
                    let out = worker.handle(input);
                    let _ = reply_tx.send(out);
                }
            }));
        }

        Self { state, threads }
    }

    pub fn submit(&self, input: I) -> mpsc::Receiver<O> {
        let (tx, rx) = mpsc::channel();
        let (lock, cv) = &*self.state;
        let mut q = lock.lock().unwrap();
        q.jobs.push_back((input, tx));
        cv.notify_one();
        rx
    }
}

impl<I: Send + 'static, O: Send + 'static> Drop for WorkerPool<I, O> {
    fn drop(&mut self) {
        {
            let (lock, cv) = &*self.state;
            let mut q = lock.lock().unwrap();
            q.closed = true;
            cv.notify_all();
        }
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SquareWorker;
    impl Worker for SquareWorker {
        type Input = u64;
        type Output = u64;
        fn handle(&mut self, input: Self::Input) -> Self::Output {
            input * input
        }
    }

    struct SquareFactory;
    impl WorkerFactory<SquareWorker> for SquareFactory {
        fn create(&self) -> SquareWorker {
            SquareWorker
        }
    }

    #[test]
    fn worker_pool_executes_100_jobs_in_parallel() {
        let pool = WorkerPool::new(4, Arc::new(SquareFactory));
        let receivers: Vec<_> = (0..100u64).map(|i| (i, pool.submit(i))).collect();
        for (i, rx) in receivers {
            assert_eq!(rx.recv().unwrap(), i * i);
        }
    }
}
