//! The OpenPGP core behind the `pgp_port` binary. Nothing here has side effects on load; the
//! stdin watchdog only runs if `watchdog::spawn()` is called, which only the binary does.
pub mod error;
pub mod keys;
pub mod ops;
pub mod watchdog;
