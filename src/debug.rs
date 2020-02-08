use std::sync::atomic;

/// If `DEBUG` is true, the library will print debugging information to stderr.
pub static DEBUG: atomic::AtomicBool = atomic::AtomicBool::new(false);

macro_rules! debug {
    ($($x:tt)*) => {
        if crate::debug::DEBUG.load(::std::sync::atomic::Ordering::Relaxed) {
            eprintln!($($x)*);
        }
    }
}
