//! skillward library: the orchestrator behind the CLI — target resolution, the
//! hardened sandbox, the scanner adapters, SARIF fusion, and report rendering. The
//! binary in `main.rs` wires these together; tests drive them directly.
//!
//! This surface exists for the `skillward` binary and its test suite, not as a
//! stable public API: items are `pub` so integration tests can reach them. Treat it
//! as unstable and exempt from semver.

pub mod batch;
pub mod bundle;
pub mod cli;
pub mod color;
pub mod error;
pub mod finding;
pub mod fusion;
pub mod remote;
pub mod report;
pub mod sandbox;
pub mod sarif;
pub mod scanners;
pub mod skills;
pub mod target;
