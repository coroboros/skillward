//! Structured failure taxonomy with stable, documented exit codes.
//!
//! Every runtime failure is one [`SkillwardError`] rendered as a single actionable
//! line, and each variant maps to a fixed exit code so CI can branch on `$?`.
//! Argument errors (bad flags, unknown values) are owned by `clap`, and
//! configuration/usage errors print their own line and exit `2` outside this enum
//! rather than inventing a code per case. Exit codes are stable across releases —
//! only ever added, never renumbered.

use std::fmt;
use std::path::PathBuf;

use crate::finding::Severity;

/// A user-facing failure carrying enough context to render an actionable line.
#[derive(Debug)]
pub enum SkillwardError {
    /// A local target path does not exist.
    TargetNotFound { path: PathBuf },
    /// A remote target could not be cloned (network, auth, or hardening refusal).
    CloneFailed { url: String, detail: String },
    /// A host-mode target refused for safety — e.g. a symlink escaping the skill root
    /// that host scanners would follow off-skill. The Docker sandbox contains the
    /// escape; `--sandbox host` cannot, so an untrusted such target is refused.
    UnsafeTarget { display: String, detail: String },
    /// The scan engine itself failed — Docker missing, daemon down, or every
    /// scanner errored so the run produced no usable result.
    ScanEngine { detail: String },
    /// The scanner bundle image is not available locally (scan path). Hint: run install.
    BundleUnavailable { image: String, detail: String },
    /// `skillward install` / `update` could not pull the image. Separate from
    /// [`BundleUnavailable`](Self::BundleUnavailable) so the hint names the real cause rather
    /// than re-suggesting the command that just failed. Shares exit 13.
    BundlePullFailed { image: String, detail: String },
    /// At least one fused finding is at or above the `--fail-on` threshold. Carries
    /// the gate severity and the count at/above it for the closing line.
    ThresholdExceeded { severity: Severity, count: usize },
    /// An unexpected I/O failure, such as writing the report file.
    Io { detail: String },
}

impl SkillwardError {
    /// The process exit code for this failure. Stable across releases.
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::TargetNotFound { .. } => 10,
            Self::CloneFailed { .. } => 11,
            Self::UnsafeTarget { .. } => 14,
            Self::ScanEngine { .. } => 12,
            Self::BundleUnavailable { .. } | Self::BundlePullFailed { .. } => 13,
            Self::ThresholdExceeded { .. } => 20,
            Self::Io { .. } => 1,
        }
    }
}

impl fmt::Display for SkillwardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TargetNotFound { path } => write!(
                f,
                "no such target: {}. Pass a skill folder, a directory of skills, or an https Git URL.",
                path.display(),
            ),
            Self::CloneFailed { url, detail } => write!(
                f,
                "could not clone {url}: {detail}. Check the URL and network, or scan a local checkout instead.",
            ),
            Self::UnsafeTarget { display, detail } => write!(
                f,
                "refuse to scan {display}: {detail}. Use the default Docker sandbox, which contains the escape.",
            ),
            Self::ScanEngine { detail } => write!(
                f,
                "scan engine failed: {detail}. Ensure Docker is installed and running, or pass `--sandbox host` to use locally-installed scanners.",
            ),
            Self::BundleUnavailable { image, detail } => write!(
                f,
                "scanner bundle {image} is unavailable: {detail}. Run `skillward install` to pull it.",
            ),
            Self::BundlePullFailed { image, detail } => write!(
                f,
                "could not pull scanner bundle {image}: {detail}. Check network access, registry authentication, and that the tag exists.",
            ),
            Self::ThresholdExceeded { severity, count } => write!(
                f,
                "{count} finding(s) at or above {severity}; the verdict fails `--fail-on {severity}`.",
            ),
            Self::Io { detail } => write!(f, "I/O error: {detail}"),
        }
    }
}

impl std::error::Error for SkillwardError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_the_documented_contract() {
        let cases: [(SkillwardError, i32); 8] = [
            (
                SkillwardError::Io {
                    detail: String::new(),
                },
                1,
            ),
            (
                SkillwardError::TargetNotFound {
                    path: PathBuf::new(),
                },
                10,
            ),
            (
                SkillwardError::CloneFailed {
                    url: String::new(),
                    detail: String::new(),
                },
                11,
            ),
            (
                SkillwardError::UnsafeTarget {
                    display: String::new(),
                    detail: String::new(),
                },
                14,
            ),
            (
                SkillwardError::ScanEngine {
                    detail: String::new(),
                },
                12,
            ),
            (
                SkillwardError::BundleUnavailable {
                    image: String::new(),
                    detail: String::new(),
                },
                13,
            ),
            (
                SkillwardError::BundlePullFailed {
                    image: String::new(),
                    detail: String::new(),
                },
                13,
            ),
            (
                SkillwardError::ThresholdExceeded {
                    severity: Severity::High,
                    count: 1,
                },
                20,
            ),
        ];
        for (err, code) in cases {
            assert_eq!(err.exit_code(), code, "{err:?}");
        }
    }

    #[test]
    fn display_messages_carry_their_actionable_token() {
        let cases: [(SkillwardError, &str); 8] = [
            (
                SkillwardError::TargetNotFound {
                    path: PathBuf::from("/x"),
                },
                "https Git URL",
            ),
            (
                SkillwardError::CloneFailed {
                    url: "u".to_owned(),
                    detail: String::new(),
                },
                "local checkout",
            ),
            (
                SkillwardError::UnsafeTarget {
                    display: "x".to_owned(),
                    detail: String::new(),
                },
                "Docker sandbox",
            ),
            (
                SkillwardError::ScanEngine {
                    detail: String::new(),
                },
                "--sandbox host",
            ),
            (
                SkillwardError::BundleUnavailable {
                    image: "img".to_owned(),
                    detail: String::new(),
                },
                "skillward install",
            ),
            (
                SkillwardError::BundlePullFailed {
                    image: "img".to_owned(),
                    detail: String::new(),
                },
                "registry authentication",
            ),
            (
                SkillwardError::ThresholdExceeded {
                    severity: Severity::Critical,
                    count: 3,
                },
                "--fail-on critical",
            ),
            (
                SkillwardError::Io {
                    detail: String::new(),
                },
                "I/O error",
            ),
        ];
        for (err, token) in cases {
            let rendered = err.to_string();
            assert!(rendered.contains(token), "{rendered:?} lacks {token:?}");
        }
    }

    #[test]
    fn install_failure_does_not_loop_back_to_the_failed_command() {
        let pull = SkillwardError::BundlePullFailed {
            image: "img".to_owned(),
            detail: "docker pull failed".to_owned(),
        }
        .to_string();
        assert!(
            !pull.contains("skillward install"),
            "install-failure hint loops back to the failed command: {pull:?}"
        );
        let scan = SkillwardError::BundleUnavailable {
            image: "img".to_owned(),
            detail: "image not present locally".to_owned(),
        }
        .to_string();
        assert!(
            scan.contains("skillward install"),
            "scan-path hint must still point at install: {scan:?}"
        );
    }
}
