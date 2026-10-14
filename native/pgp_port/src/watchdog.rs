//! Stdin EOF means the Erlang port closed, i.e. its owner died: stop at once and take any
//! unauthenticated plaintext (OUT.partial) with us instead of running on as an orphan.
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

/// Exit status when the owner is gone: neither 0 nor 1, so a caller would see a crash.
const OWNER_GONE: i32 = 3;

/// The OUT.partial being written, if any. Hold this lock while creating, renaming or removing
/// it, so the watchdog never sees a file that is not registered or a registration without a file.
static PARTIAL: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Set by `spawn()`. Without a watchdog (`PGP_PORT_NO_WATCHDOG`, or code using the library
/// directly) the PARTIAL slot is never touched.
static ENABLED: AtomicBool = AtomicBool::new(false);

fn lock() -> MutexGuard<'static, Option<PathBuf>> {
    PARTIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// The registration slot for OUT.partial, or `None` if no watchdog is running.
pub fn partial() -> Option<MutexGuard<'static, Option<PathBuf>>> {
    ENABLED.load(Ordering::Acquire).then(lock)
}

/// Set by command-line callers (scripts piping `echo JSON | pgp_port ...`), whose stdin closes
/// right after the request. The Erlang port never sets it.
const OPT_OUT: &str = "PGP_PORT_NO_WATCHDOG";

/// Call once this process has finished reading its request: the watchdog consumes the rest of
/// stdin through the same global (buffered) handle.
pub fn spawn() {
    if std::env::var_os(OPT_OUT).is_some() {
        return;
    }
    ENABLED.store(true, Ordering::Release);
    std::thread::spawn(|| {
        let mut buf = [0u8; 512];
        loop {
            match std::io::stdin().read(&mut buf) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        // Keep the lock until exit so the main thread cannot publish or re-create the file meanwhile.
        // If main is exiting at this very moment too, either status may win: harmless, the owner is gone.
        let registered = lock();
        if let Some(path) = registered.as_ref() {
            let _ = fs::remove_file(path);
        }
        std::process::exit(OWNER_GONE);
    });
}
