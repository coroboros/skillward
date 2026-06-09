//! Shared helpers for the integration test crates. Lives in a subdirectory so
//! Cargo does not compile it as its own test binary.
#![allow(dead_code)] // each test binary uses a subset
#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;

/// A binary invocation with ambient color env neutralized, so a test only sees the
/// color signal it sets itself.
pub fn skillward() -> Command {
    let mut cmd = Command::cargo_bin("skillward").expect("skillward binary builds");
    cmd.env_remove("NO_COLOR")
        .env_remove("CLICOLOR")
        .env_remove("CLICOLOR_FORCE");
    cmd
}
