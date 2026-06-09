//! The unified finding model every adapter normalizes into, plus the severity
//! scale and the rule-class taxonomy that lets findings from different tools
//! correlate. Nine scanners speak nine dialects; this is the one vocabulary the
//! fusion stage reasons over.

use std::fmt;

use clap::ValueEnum;
use serde::Serialize;

/// The unified severity scale. Ordered: `Low < Medium < High < Critical`, so a
/// fused finding's severity is `max` over its sources and `--fail-on` is a simple
/// comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Every severity, ascending — the single source for iterating the scale (counts
    /// rendering, etc.) so a new variant is picked up everywhere it is enumerated.
    pub const ALL: [Self; 4] = [Self::Low, Self::Medium, Self::High, Self::Critical];

    /// Map a SARIF `result.level` to a severity. SARIF has no "critical", so
    /// `error` lands at High; a tool's numeric `security-severity` promotes it to
    /// Critical separately (see [`from_security_severity`](Self::from_security_severity)).
    pub fn from_sarif_level(level: &str) -> Self {
        match level {
            "error" => Self::High,
            "warning" => Self::Medium,
            // "note", "none", or anything unrecognized — the floor.
            _ => Self::Low,
        }
    }

    /// Map the GitHub `security-severity` property (a CVSS-style 0.0–10.0 score)
    /// to a severity, the convention trivy/semgrep/others emit in SARIF rule
    /// metadata. `None` when the string does not parse, so the caller keeps the
    /// level-derived severity.
    pub fn from_security_severity(score: &str) -> Option<Self> {
        let value: f64 = score.trim().parse().ok()?;
        Some(if value >= 9.0 {
            Self::Critical
        } else if value >= 7.0 {
            Self::High
        } else if value >= 4.0 {
            Self::Medium
        } else {
            Self::Low
        })
    }

    /// Lowercase label used in JSON, SARIF, and the terminal report.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// The `--fail-on` threshold. `None` never fails; otherwise the run exits non-zero
/// when any fused finding is at or above the wrapped severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOn {
    /// Never gate on findings — report only, always exit 0.
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl FailOn {
    /// The severity floor that trips the gate, or `None` to never gate.
    pub const fn threshold(self) -> Option<Severity> {
        match self {
            Self::None => Option::None,
            Self::Low => Some(Severity::Low),
            Self::Medium => Some(Severity::Medium),
            Self::High => Some(Severity::High),
            Self::Critical => Some(Severity::Critical),
        }
    }
}

/// A normalized detection class. Different tools name the same threat differently;
/// mapping every rule into this small set is what lets a secret found by gitleaks,
/// trivy, and SkillSpector fuse into one corroborated finding instead of three rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleClass {
    /// Hardcoded credential, token, or key.
    Secret,
    /// Prompt injection / hidden instruction in skill content.
    Injection,
    /// Data/exfil taint reaching an execution or network sink.
    TaintExec,
    /// Vulnerable, yanked, or typosquatted dependency.
    VulnerableDep,
    /// Misconfiguration (IaC, permissions, unsafe defaults).
    Misconfig,
    /// Known-malware signature (YARA, hash).
    MalwareSig,
    /// MCP/agent tool over-permission or capability sprawl.
    OverPermission,
    /// Unsafe CI/GitHub Action or pipeline construct.
    UnsafeAction,
    /// Anything not yet classified — kept distinct so it never silently merges.
    Other,
}

impl RuleClass {
    /// Classify a raw rule into a normalized class from the tool, rule id, and
    /// message. Keyword heuristics over the lowercased text; deliberately ordered
    /// most-specific first so `secret` wins over a generic `injection` substring.
    pub fn classify(tool: &str, rule_id: &str, message: &str) -> Self {
        let hay = format!("{tool} {rule_id} {message}").to_lowercase();
        let has = |needles: &[&str]| needles.iter().any(|n| hay.contains(n));

        if has(&[
            "secret",
            "api-key",
            "api key",
            "credential",
            "token",
            "password",
            "private-key",
        ]) {
            Self::Secret
        } else if has(&[
            "malware",
            "yara",
            "signature-match",
            "known-bad",
            "virustotal",
        ]) {
            Self::MalwareSig
        } else if has(&[
            "prompt-injection",
            "prompt injection",
            "hidden-instruction",
            "jailbreak",
        ]) {
            Self::Injection
        } else if has(&[
            "taint",
            "exfil",
            "data-flow",
            "dataflow",
            "command-injection",
            "rce",
            "eval",
            "exec-sink",
        ]) {
            Self::TaintExec
        } else if has(&[
            "cve-",
            "vuln",
            "advisory",
            "yanked",
            "typosquat",
            "outdated-dep",
            "ghsa-",
        ]) {
            Self::VulnerableDep
        } else if has(&[
            "over-permission",
            "overpermission",
            "excessive-permission",
            "capability",
            "scope-creep",
            "mcp-permission",
        ]) {
            Self::OverPermission
        } else if has(&[
            "github-action",
            "gha-",
            "workflow",
            "pipeline",
            "unpinned-action",
        ]) {
            Self::UnsafeAction
        } else if has(&[
            "misconfig",
            "insecure-default",
            "iac",
            "dockerfile",
            "permission",
        ]) {
            Self::Misconfig
        } else {
            Self::Other
        }
    }

    /// Stable kebab-case label for reports.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Injection => "injection",
            Self::TaintExec => "taint-exec",
            Self::VulnerableDep => "vulnerable-dep",
            Self::Misconfig => "misconfig",
            Self::MalwareSig => "malware-sig",
            Self::OverPermission => "over-permission",
            Self::UnsafeAction => "unsafe-action",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for RuleClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A source-code region, when a tool reports one. All fields optional — many
/// findings are file- or repo-scoped with no line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize)]
pub struct Region {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
}

impl Region {
    /// `true` when no positional information is present.
    pub const fn is_empty(&self) -> bool {
        self.start_line.is_none()
            && self.end_line.is_none()
            && self.start_column.is_none()
            && self.end_column.is_none()
    }
}

/// A scanner that could not contribute — missing, crashed, timed out, or emitted
/// unparseable output. Recorded so a degraded run is loud, never silently partial:
/// a missing tool must not look like a clean skill.
#[derive(Debug, Clone, Serialize)]
pub struct ToolError {
    pub tool: String,
    pub detail: String,
}

/// One raw finding from one tool, already normalized onto the unified scale and
/// taxonomy by its adapter.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// The adapter id that produced it (e.g. `gitleaks`).
    pub tool: String,
    /// The tool's own rule identifier.
    pub rule_id: String,
    /// Human-readable detail.
    pub message: String,
    pub severity: Severity,
    pub class: RuleClass,
    /// Path relative to the scanned skill root, when the finding is file-scoped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Region::is_empty")]
    pub region: Region,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn severity_orders_low_to_critical() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
        assert_eq!(
            [Severity::Low, Severity::Critical, Severity::Medium]
                .into_iter()
                .max(),
            Some(Severity::Critical)
        );
    }

    #[test]
    fn sarif_level_maps_to_scale() {
        assert_eq!(Severity::from_sarif_level("error"), Severity::High);
        assert_eq!(Severity::from_sarif_level("warning"), Severity::Medium);
        assert_eq!(Severity::from_sarif_level("note"), Severity::Low);
        assert_eq!(Severity::from_sarif_level("anything-else"), Severity::Low);
    }

    #[test]
    fn security_severity_score_promotes_to_critical() {
        assert_eq!(
            Severity::from_security_severity("9.8"),
            Some(Severity::Critical)
        );
        assert_eq!(
            Severity::from_security_severity("7.5"),
            Some(Severity::High)
        );
        assert_eq!(
            Severity::from_security_severity("4.0"),
            Some(Severity::Medium)
        );
        assert_eq!(Severity::from_security_severity("1.0"), Some(Severity::Low));
        assert_eq!(Severity::from_security_severity("not-a-number"), None);
        // Malformed-but-parseable scores from untrusted SARIF resolve safely (promote-only,
        // never demote): NaN floors to Low, non-finite saturates to Critical, negatives floor.
        let sev = Severity::from_security_severity;
        assert_eq!(sev("NaN"), Some(Severity::Low));
        assert_eq!(sev("inf"), Some(Severity::Critical));
        assert_eq!(sev("-3.0"), Some(Severity::Low));
    }

    #[test]
    fn security_severity_cutoffs_are_exact() {
        // A band edge can flip a `--fail-on critical` verdict, so pin each boundary and below.
        let sev = |s: &str| Severity::from_security_severity(s);
        assert_eq!(sev("9.0"), Some(Severity::Critical));
        assert_eq!(sev("8.9"), Some(Severity::High));
        assert_eq!(sev("7.0"), Some(Severity::High));
        assert_eq!(sev("6.9"), Some(Severity::Medium));
        assert_eq!(sev("4.0"), Some(Severity::Medium));
        assert_eq!(sev("3.9"), Some(Severity::Low));
        assert_eq!(sev("0.0"), Some(Severity::Low));
        // The `.trim()` is load-bearing: a real tool may pad the score; it must still promote.
        assert_eq!(sev(" 9.8 "), Some(Severity::Critical));
        assert_eq!(sev("\t7.5\n"), Some(Severity::High));
    }

    #[test]
    fn fail_on_threshold_gate() {
        assert_eq!(FailOn::None.threshold(), None);
        assert_eq!(FailOn::High.threshold(), Some(Severity::High));
        assert!(Severity::High >= FailOn::High.threshold().unwrap());
        assert!(Severity::High < FailOn::Critical.threshold().unwrap());
    }

    #[test]
    fn label_matches_serde_encoding() {
        // `label()` and serde `rename_all` are two encodings of one vocabulary; pin them equal.
        for c in [
            RuleClass::Secret,
            RuleClass::Injection,
            RuleClass::TaintExec,
            RuleClass::VulnerableDep,
            RuleClass::Misconfig,
            RuleClass::MalwareSig,
            RuleClass::OverPermission,
            RuleClass::UnsafeAction,
            RuleClass::Other,
        ] {
            assert_eq!(
                serde_json::to_value(c).unwrap(),
                serde_json::json!(c.label()),
                "{c:?}"
            );
        }
        for s in Severity::ALL {
            assert_eq!(
                serde_json::to_value(s).unwrap(),
                serde_json::json!(s.label()),
                "{s:?}"
            );
        }
    }

    #[test]
    fn classify_picks_the_most_specific_class() {
        assert_eq!(
            RuleClass::classify("gitleaks", "aws-access-token", "AWS secret found"),
            RuleClass::Secret
        );
        assert_eq!(
            RuleClass::classify("trivy", "CVE-2024-1234", "vulnerable dependency"),
            RuleClass::VulnerableDep
        );
        assert_eq!(
            RuleClass::classify("skillspector", "prompt-injection", "hidden instruction"),
            RuleClass::Injection
        );
        assert_eq!(
            RuleClass::classify("agent-audit", "taint-to-exec", "param reaches subprocess"),
            RuleClass::TaintExec
        );
        assert_eq!(
            RuleClass::classify("x", "credential-in-config", "misconfig: hardcoded token"),
            RuleClass::Secret
        );
        assert_eq!(
            RuleClass::classify("x", "unknown-rule", "nothing recognizable"),
            RuleClass::Other
        );
    }

    #[test]
    fn classify_covers_every_class_and_honors_priority_order() {
        assert_eq!(
            RuleClass::classify("x", "yara-sig", "malware signature match"),
            RuleClass::MalwareSig
        );
        assert_eq!(
            RuleClass::classify("x", "excessive-permission", "mcp capability sprawl"),
            RuleClass::OverPermission
        );
        assert_eq!(
            RuleClass::classify("x", "unpinned-action", "github-action workflow"),
            RuleClass::UnsafeAction
        );
        assert_eq!(
            RuleClass::classify("x", "iac", "insecure-default dockerfile"),
            RuleClass::Misconfig
        );
        // Priority: malware is checked before injection, so a rule naming both is
        // classified as MalwareSig, and secret still outranks everything.
        assert_eq!(
            RuleClass::classify("x", "yara", "prompt-injection plus malware"),
            RuleClass::MalwareSig
        );
        assert_eq!(
            RuleClass::classify("x", "api-key", "malware yara token leak"),
            RuleClass::Secret
        );
        // OverPermission's keywords are all compound, so a bare `permission` must fall
        // through to Misconfig — pins the arm order a reorder would silently break.
        assert_eq!(
            RuleClass::classify("x", "file-permission", "loose permission"),
            RuleClass::Misconfig
        );
    }
}
