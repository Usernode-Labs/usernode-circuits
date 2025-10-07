use std::sync::{Mutex, OnceLock};

/// Global guard for Barretenberg entry points that are not reentrant.
pub(crate) static BB_GUARD: OnceLock<Mutex<()>> = OnceLock::new();

/// Execute `f` while holding the Barretenberg mutex.
pub(crate) fn with_bb_lock<F, T>(f: F) -> T
where
    F: FnOnce() -> T,
{
    let guard = BB_GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("barretenberg mutex poisoned");
    let result = f();
    drop(guard);
    result
}
