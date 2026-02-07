//! Signal-of-Stop: cooperative cancellation primitive.
//!
//! Provides a thread-safe, async-aware cancellation token that can be:
//! - Cloned and shared across tasks
//! - Awaited for cancellation notification
//! - Used in select! patterns to cancel futures

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use tokio::sync::Notify;

/// A cooperative cancellation token.
///
/// Clones share the same underlying state, so cancelling any clone
/// notifies all waiters.
#[derive(Debug, Default)]
pub struct SignalOfStop {
    internal: Arc<SharedState>,
}

#[derive(Debug, Default)]
struct SharedState {
    closing: AtomicBool,
    notify: Notify,
    mutex: Mutex<()>,
    condvar: Condvar,
}

impl SignalOfStop {
    /// Create a new, uncancelled signal.
    pub fn new() -> Self {
        Self {
            internal: Arc::new(SharedState {
                closing: AtomicBool::new(false),
                notify: Notify::new(),
                mutex: Mutex::new(()),
                condvar: Condvar::new(),
            }),
        }
    }

    /// Signal cancellation to all waiters.
    ///
    /// After this call, `cancelled()` returns `true` and all pending
    /// `wait()` futures complete.
    pub fn cancel(&self) {
        self.internal.closing.store(true, Ordering::Release);
        self.internal.notify.notify_waiters();

        if let Ok(_guard) = self.internal.mutex.lock() {
            self.internal.condvar.notify_all();
        }
    }

    /// Check if cancellation has been signaled.
    pub fn cancelled(&self) -> bool {
        self.internal.closing.load(Ordering::Acquire)
    }

    /// Wait for cancellation to be signaled.
    ///
    /// Returns immediately if already cancelled.
    pub async fn wait(&self) -> bool {
        if self.cancelled() {
            return true;
        }
        self.internal.notify.notified().await;
        self.cancelled()
    }

    /// Race a future against cancellation.
    ///
    /// Returns `Ok(T)` if the future completes first,
    /// `Err(())` if cancellation is signaled first.
    pub async fn select<F, T>(&self, fut: F) -> Result<T, ()>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let clone = self.clone();
        tokio::select! {
            res = fut => Ok(res),
            _ = clone.wait() => Err(()),
        }
    }
}

impl Clone for SignalOfStop {
    fn clone(&self) -> Self {
        Self {
            internal: Arc::clone(&self.internal),
        }
    }
}
