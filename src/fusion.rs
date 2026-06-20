//! Fuse the ensemble's overlapping findings into one coherent set.
//!
//! Nine scanners flag the same secret, the same injection, the same vulnerable
//! dependency. Reported raw, that reads as nine times the noise. Fusion buckets a finding by
//! its site (class, file, line); an advisory (CVE/GHSA) buckets by its id alone, so the same
//! CVE corroborates across files and tool classifications. Each bucket collapses to one
//! finding citing every tool that agreed, raising confidence with corroboration — so
//! completeness reads as signal, not a flood.

use std::collections::HashMap;

use serde::Serialize;

use crate::finding::{FailOn, Finding, Region, RuleClass, Severity};

/// One tool's contribution to a fused finding.
#[derive(Debug, Clone, Serialize)]
pub struct Source {
    pub tool: String,
    pub rule_id: String,
    pub severity: Severity,
}

/// A finding after fusion: the worst severity across its sources, the tools that
/// corroborate it, and a representative location and message.
#[derive(Debug, Clone, Serialize)]
pub struct FusedFinding {
    pub class: RuleClass,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Region::is_empty")]
    pub region: Region,
    pub message: String,
    pub sources: Vec<Source>,
}

impl FusedFinding {
    /// The distinct tools that flagged this site, sorted — the single source for both
    /// the corroboration count and the report's sources label.
    pub fn distinct_tools(&self) -> Vec<&str> {
        let mut tools: Vec<&str> = self.sources.iter().map(|s| s.tool.as_str()).collect();
        tools.sort_unstable();
        tools.dedup();
        tools
    }

    /// Distinct tools that flagged this site — the corroboration count.
    pub fn tool_count(&self) -> usize {
        self.distinct_tools().len()
    }

    /// `true` when more than one tool flagged the same site.
    pub fn corroborated(&self) -> bool {
        is_corroborated(self.tool_count())
    }
}

/// `true` when at least two distinct tools flag a site — the single definition of
/// "corroborated", shared by [`FusedFinding::corroborated`] and the report's badge so
/// the threshold lives in one place.
pub const fn is_corroborated(tool_count: usize) -> bool {
    tool_count >= 2
}

/// The PASS/FAIL vocabulary, defined once for both the per-skill [`Verdict::label`]
/// and the run-level aggregate in the report layer.
pub const fn verdict_label(failed: bool) -> &'static str {
    if failed { "FAIL" } else { "PASS" }
}

/// The bucket key: `(class, file, start_line, discriminator)`. How it is built — and
/// why the discriminator exists — is documented on [`bucket_key`].
type Key = (RuleClass, Option<String>, Option<u32>, Option<String>);

/// The bucket a finding fuses into. An advisory (CVE/GHSA) is identified by its id
/// alone, so the same advisory corroborates across tools regardless of the file/line
/// each reported it against. Otherwise the site (class, file, line) identifies it; a
/// location-less non-advisory adds its rule id so two distinct issues at one absent
/// site stay separate.
fn bucket_key(finding: &Finding) -> Key {
    // A CVE/GHSA in the rule_id is an advisory; in free-form message text it counts only when
    // the finding is already a dependency advisory, else a taint/injection finding that merely
    // cites a CVE would be reclassified and over-merged into the dep bucket.
    let advisory = advisory_id(&finding.rule_id).or_else(|| {
        (finding.class == RuleClass::VulnerableDep)
            .then(|| advisory_id(&finding.message))
            .flatten()
    });
    if let Some(adv) = advisory {
        // Id alone is the identity (canonical class), so the same CVE corroborates across tools.
        return (RuleClass::VulnerableDep, None, None, Some(adv));
    }
    // A location-less finding keys on its rule id; when the tool omits the rule id, fold in
    // the message so two distinct no-rule-id findings don't collapse into one bucket.
    let disc = finding.region.start_line.is_none().then(|| {
        if finding.rule_id.is_empty() {
            finding.message.to_lowercase()
        } else {
            finding.rule_id.to_lowercase()
        }
    });
    (
        finding.class,
        finding.file.clone(),
        finding.region.start_line,
        disc,
    )
}

/// Extract a CVE or GHSA identifier (uppercased) from `text` — the cross-tool-stable
/// identity of a vulnerable dependency. The prefix must sit on a left word boundary, so a
/// mid-word substring (`sourcve-2024`) is not mistaken for an advisory id.
fn advisory_id(text: &str) -> Option<String> {
    let upper = text.to_uppercase();
    let bytes = upper.as_bytes();
    ["CVE-", "GHSA-"].into_iter().find_map(|prefix| {
        upper.match_indices(prefix).find_map(|(start, _)| {
            if start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
                return None;
            }
            let token: String = upper[start..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
            (token.len() > prefix.len()).then_some(token)
        })
    })
}

/// Fuse raw findings into deduplicated, corroborated findings, sorted so the
/// highest-severity, most-corroborated findings come first.
pub fn fuse(findings: &[Finding]) -> Vec<FusedFinding> {
    let mut buckets: HashMap<Key, FusedFinding> = HashMap::new();
    let mut order: Vec<Key> = Vec::new();

    for finding in findings {
        let key = bucket_key(finding);
        let source = Source {
            tool: finding.tool.clone(),
            rule_id: finding.rule_id.clone(),
            severity: finding.severity,
        };

        match buckets.get_mut(&key) {
            Some(fused) => {
                // Tie on severity → smallest message wins, so the result is order-independent.
                if finding.severity > fused.severity
                    || (finding.severity == fused.severity && finding.message < fused.message)
                {
                    fused.severity = finding.severity;
                    fused.message = finding.message.clone();
                }
                // Smallest (file, start_line) wins as an atomic pair — order-independent for
                // advisory buckets (which fuse across files), and a line never moves to a
                // different file. An absent line sorts last, so a location-less source never
                // clobbers a lined representative of the same file.
                let line_key = |r: Region| r.start_line.unwrap_or(u32::MAX);
                let adopt_location = match (&fused.file, &finding.file) {
                    (None, Some(_)) => true,
                    (Some(cur), Some(inc)) => {
                        (inc.as_str(), line_key(finding.region))
                            < (cur.as_str(), line_key(fused.region))
                    }
                    _ => false,
                };
                if adopt_location {
                    fused.file = finding.file.clone();
                    fused.region = finding.region;
                } else if fused.file == finding.file
                    && fused.region.is_empty()
                    && !finding.region.is_empty()
                {
                    fused.region = finding.region;
                }
                // Keep one entry per distinct (tool, rule_id) so a tool repeating a
                // rule at the same line does not inflate the corroboration count.
                if !fused
                    .sources
                    .iter()
                    .any(|s| s.tool == source.tool && s.rule_id == source.rule_id)
                {
                    fused.sources.push(source);
                }
            }
            None => {
                let class = key.0;
                order.push(key.clone());
                buckets.insert(
                    key,
                    FusedFinding {
                        class,
                        severity: finding.severity,
                        file: finding.file.clone(),
                        region: finding.region,
                        message: finding.message.clone(),
                        sources: vec![source],
                    },
                );
            }
        }
    }

    // Corroboration is fixed once a bucket is fully built, so compute it once per
    // finding and sort on the precomputed count — rather than re-deriving it (a fresh
    // alloc + sort + dedup) inside every comparison.
    let mut decorated: Vec<(usize, FusedFinding)> = order
        .into_iter()
        .filter_map(|k| buckets.remove(&k))
        .map(|mut f| {
            // Sort sources so the serialized `sources` array is a pure function of the
            // source set, not of the order scanners reported in.
            f.sources
                .sort_by(|a, b| a.tool.cmp(&b.tool).then_with(|| a.rule_id.cmp(&b.rule_id)));
            (f.tool_count(), f)
        })
        .collect();

    // A total order over distinct buckets (message + source signature break the final ties),
    // so the report is a pure function of the finding set, not of input order.
    decorated.sort_by(|(ca, a), (cb, b)| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| cb.cmp(ca))
            .then_with(|| a.class.label().cmp(b.class.label()))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.region.start_line.cmp(&b.region.start_line))
            .then_with(|| a.message.cmp(&b.message))
            .then_with(|| {
                a.sources
                    .iter()
                    .map(|s| (&s.tool, &s.rule_id))
                    .cmp(b.sources.iter().map(|s| (&s.tool, &s.rule_id)))
            })
    });
    decorated.into_iter().map(|(_, f)| f).collect()
}

/// The per-skill verdict: worst severity, per-severity counts, corroboration, and
/// whether the `--fail-on` gate tripped.
#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worst: Option<Severity>,
    pub total: usize,
    pub corroborated: usize,
    /// Counts per severity, highest first: `[critical, high, medium, low]`.
    pub counts: SeverityCounts,
    pub failed: bool,
    /// Findings at or above the threshold — the number the gate reports.
    pub at_or_above_threshold: usize,
}

/// Per-severity tallies.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

impl SeverityCounts {
    /// The tally for a given severity. Exhaustive, so adding a `Severity` variant
    /// forces an update here — and thus in every renderer that reads counts by it.
    pub const fn of(&self, severity: Severity) -> usize {
        match severity {
            Severity::Critical => self.critical,
            Severity::High => self.high,
            Severity::Medium => self.medium,
            Severity::Low => self.low,
        }
    }
}

impl Verdict {
    /// Compute the verdict over fused findings against the gate.
    pub fn compute(fused: &[FusedFinding], fail_on: FailOn) -> Self {
        let mut counts = SeverityCounts::default();
        for f in fused {
            match f.severity {
                Severity::Critical => counts.critical += 1,
                Severity::High => counts.high += 1,
                Severity::Medium => counts.medium += 1,
                Severity::Low => counts.low += 1,
            }
        }
        let worst = fused.iter().map(|f| f.severity).max();
        let at_or_above_threshold = fail_on
            .threshold()
            .map_or(0, |t| fused.iter().filter(|f| f.severity >= t).count());
        Self {
            worst,
            total: fused.len(),
            corroborated: fused.iter().filter(|f| f.corroborated()).count(),
            counts,
            failed: at_or_above_threshold > 0,
            at_or_above_threshold,
        }
    }

    /// `PASS` when the gate did not trip, else `FAIL`.
    pub const fn label(&self) -> &'static str {
        verdict_label(self.failed)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn finding(tool: &str, class: RuleClass, sev: Severity, file: &str, line: u32) -> Finding {
        Finding {
            tool: tool.to_owned(),
            rule_id: format!("{tool}-rule"),
            message: format!("{tool} says {class}"),
            severity: sev,
            class,
            file: Some(file.to_owned()),
            region: Region {
                start_line: Some(line),
                ..Region::default()
            },
        }
    }

    #[test]
    fn location_less_findings_without_rule_id_stay_distinct_by_message() {
        let mk = |msg: &str| Finding {
            tool: "x".to_owned(),
            rule_id: String::new(),
            message: msg.to_owned(),
            severity: Severity::High,
            class: RuleClass::Other,
            file: None,
            region: Region::default(),
        };
        let fused = fuse(&[mk("first issue"), mk("second issue")]);
        assert_eq!(fused.len(), 2);
    }

    #[test]
    fn four_tools_one_site_fuse_to_one_corroborated_finding() {
        let raw = vec![
            finding("gitleaks", RuleClass::Secret, Severity::High, "a.yaml", 5),
            finding("trivy", RuleClass::Secret, Severity::Critical, "a.yaml", 5),
            finding(
                "skillspector",
                RuleClass::Secret,
                Severity::Medium,
                "a.yaml",
                5,
            ),
            finding("semgrep", RuleClass::Secret, Severity::High, "a.yaml", 5),
        ];
        let fused = fuse(&raw);
        assert_eq!(fused.len(), 1, "four sources collapse to one finding");
        let f = &fused[0];
        assert_eq!(f.tool_count(), 4);
        assert!(f.corroborated());
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.message, "trivy says secret");
        assert_eq!(f.sources.len(), 4);
        let sevs: Vec<Severity> = f.sources.iter().map(|s| s.severity).collect();
        assert!(sevs.contains(&Severity::Critical) && sevs.contains(&Severity::Medium));
    }

    #[test]
    fn distinct_sites_stay_separate() {
        let raw = vec![
            finding("gitleaks", RuleClass::Secret, Severity::High, "a.yaml", 5),
            finding("gitleaks", RuleClass::Secret, Severity::High, "a.yaml", 9),
            finding(
                "trivy",
                RuleClass::VulnerableDep,
                Severity::High,
                "a.yaml",
                5,
            ),
        ];
        assert_eq!(fuse(&raw).len(), 3);
    }

    #[test]
    fn one_tool_repeating_a_rule_does_not_inflate_corroboration() {
        let raw = vec![
            finding("gitleaks", RuleClass::Secret, Severity::High, "a.yaml", 5),
            finding("gitleaks", RuleClass::Secret, Severity::High, "a.yaml", 5),
        ];
        let fused = fuse(&raw);
        assert_eq!(fused.len(), 1);
        assert_eq!(
            fused[0].tool_count(),
            1,
            "same tool+rule must not double-count"
        );
        assert!(!fused[0].corroborated());
    }

    #[test]
    fn sort_puts_corroborated_criticals_first() {
        let raw = vec![
            finding("a", RuleClass::Misconfig, Severity::Low, "x", 1),
            finding("a", RuleClass::Secret, Severity::Critical, "y", 2),
            finding("b", RuleClass::Secret, Severity::Critical, "y", 2),
        ];
        let fused = fuse(&raw);
        assert_eq!(fused[0].severity, Severity::Critical);
        assert!(fused[0].corroborated());
        assert_eq!(fused[1].severity, Severity::Low);
    }

    #[test]
    fn equal_severity_orders_corroborated_first() {
        let raw = vec![
            finding("solo", RuleClass::Secret, Severity::High, "a.yaml", 1),
            finding("x", RuleClass::Secret, Severity::High, "b.yaml", 2),
            finding("y", RuleClass::Secret, Severity::High, "b.yaml", 2),
        ];
        let fused = fuse(&raw);
        assert_eq!(fused.len(), 2);
        assert_eq!(
            fused[0].tool_count(),
            2,
            "corroborated site leads on the tie-break"
        );
        assert!(fused[0].corroborated());
        assert_eq!(fused[1].tool_count(), 1);
    }

    #[test]
    fn verdict_gate_and_counts() {
        let raw = vec![
            finding("a", RuleClass::Secret, Severity::Critical, "y", 2),
            finding("a", RuleClass::Misconfig, Severity::Medium, "x", 1),
        ];
        let fused = fuse(&raw);

        let high = Verdict::compute(&fused, FailOn::High);
        assert_eq!(high.worst, Some(Severity::Critical));
        assert_eq!(high.counts.critical, 1);
        assert_eq!(high.counts.medium, 1);
        assert!(high.failed);
        assert_eq!(high.at_or_above_threshold, 1);
        assert_eq!(high.label(), "FAIL");

        let none = Verdict::compute(&fused, FailOn::None);
        assert!(!none.failed);
        assert_eq!(none.label(), "PASS");
    }

    #[test]
    fn clean_scan_passes_with_no_findings() {
        let v = Verdict::compute(&[], FailOn::Low);
        assert_eq!(v.worst, None);
        assert_eq!(v.total, 0);
        assert!(!v.failed);
    }

    #[test]
    fn equal_severity_findings_order_by_class_then_file() {
        let raw = vec![
            finding("t", RuleClass::Secret, Severity::Medium, "z.txt", 1),
            finding("t", RuleClass::Misconfig, Severity::Medium, "m.txt", 1),
            finding("t", RuleClass::Misconfig, Severity::Medium, "a.txt", 1),
        ];
        let fused = fuse(&raw);
        assert_eq!(fused.len(), 3);
        assert_eq!(fused[0].class.label(), "misconfig");
        assert_eq!(fused[0].file.as_deref(), Some("a.txt"));
        assert_eq!(fused[1].class.label(), "misconfig");
        assert_eq!(fused[1].file.as_deref(), Some("m.txt"));
        assert_eq!(fused[2].class.label(), "secret");
    }

    #[test]
    fn region_is_backfilled_when_the_first_source_has_none() {
        let mk = |tool: &str, region: Region| Finding {
            tool: tool.to_owned(),
            rule_id: "shared-rule".to_owned(),
            message: tool.to_owned(),
            severity: Severity::High,
            class: RuleClass::Secret,
            file: Some("f.yaml".to_owned()),
            region,
        };
        let bare = mk("a", Region::default());
        let rich = mk(
            "b",
            Region {
                start_column: Some(3),
                end_column: Some(9),
                ..Region::default()
            },
        );
        let fused = fuse(&[bare, rich]);
        assert_eq!(fused.len(), 1, "same file-scoped site fuses to one");
        assert!(
            !fused[0].region.is_empty(),
            "an empty region is backfilled from the later source"
        );
        assert_eq!(fused[0].region.start_column, Some(3));
        assert_eq!(fused[0].region.end_column, Some(9));
    }

    fn dep(tool: &str, rule: &str, sev: Severity, msg: &str) -> Finding {
        Finding {
            tool: tool.to_owned(),
            rule_id: rule.to_owned(),
            message: msg.to_owned(),
            severity: sev,
            class: RuleClass::VulnerableDep,
            file: None,
            region: Region::default(),
        }
    }

    #[test]
    fn advisory_id_requires_a_word_boundary() {
        assert_eq!(
            advisory_id("see CVE-2024-1 here"),
            Some("CVE-2024-1".to_owned())
        );
        assert_eq!(
            advisory_id("GHSA-aaaa-bbbb-cccc"),
            Some("GHSA-AAAA-BBBB-CCCC".to_owned())
        );
        assert_eq!(advisory_id("(CVE-2024-2)"), Some("CVE-2024-2".to_owned()));
        assert_eq!(advisory_id("the sourcve-2024 widget"), None);
        assert_eq!(advisory_id("resource RCVE-2024 thing"), None);
        assert_eq!(advisory_id("CVE-"), None);
        // A non-ASCII preceding byte (UTF-8 continuation ≥ 0x80) counts as a boundary.
        assert_eq!(advisory_id("é CVE-2024-9"), Some("CVE-2024-9".to_owned()));
        assert_eq!(advisory_id("éCVE-2024-9"), Some("CVE-2024-9".to_owned()));
    }

    #[test]
    fn distinct_locationless_findings_stay_separate_and_uncorroborated() {
        let raw = vec![
            dep(
                "trivy",
                "CVE-2024-AAAA",
                Severity::High,
                "vulnerable package alpha",
            ),
            dep(
                "aguara",
                "CVE-2024-BBBB",
                Severity::Medium,
                "vulnerable package beta",
            ),
        ];
        let fused = fuse(&raw);
        assert_eq!(fused.len(), 2, "distinct CVEs must not over-merge");
        assert!(
            fused.iter().all(|f| !f.corroborated()),
            "distinct issues are not corroboration"
        );
        let v = Verdict::compute(&fused, FailOn::High);
        assert_eq!(v.counts.high, 1);
        assert_eq!(v.counts.medium, 1);
        assert_eq!(v.total, 2);
    }

    #[test]
    fn same_advisory_from_two_tools_still_corroborates() {
        let raw = vec![
            dep("trivy", "CVE-2024-AAAA", Severity::High, "alpha"),
            dep("aguara", "cve-2024-aaaa", Severity::High, "alpha dep"),
        ];
        let fused = fuse(&raw);
        assert_eq!(fused.len(), 1, "the same CVE from two tools fuses");
        assert!(fused[0].corroborated());
        assert_eq!(fused[0].tool_count(), 2);
    }

    #[test]
    fn same_advisory_corroborates_across_different_locations() {
        let raw = vec![
            Finding {
                tool: "trivy".to_owned(),
                rule_id: "CVE-2024-9999".to_owned(),
                message: "x".to_owned(),
                severity: Severity::High,
                class: RuleClass::VulnerableDep,
                file: Some("requirements.txt".to_owned()),
                region: Region {
                    start_line: Some(5),
                    ..Region::default()
                },
            },
            Finding {
                tool: "aguara".to_owned(),
                rule_id: "CVE-2024-9999".to_owned(),
                message: "y".to_owned(),
                severity: Severity::High,
                class: RuleClass::VulnerableDep,
                file: None,
                region: Region::default(),
            },
        ];
        let fused = fuse(&raw);
        assert_eq!(
            fused.len(),
            1,
            "same CVE at different locations corroborates"
        );
        assert!(fused[0].corroborated());
    }

    #[test]
    fn advisory_in_message_corroborates_with_advisory_in_rule_id() {
        let raw = vec![
            Finding {
                tool: "trivy".to_owned(),
                rule_id: "CVE-2024-7777".to_owned(),
                message: "vulnerable dep".to_owned(),
                severity: Severity::High,
                class: RuleClass::VulnerableDep,
                file: None,
                region: Region::default(),
            },
            Finding {
                tool: "aguara".to_owned(),
                rule_id: "vulnerable-dependency".to_owned(),
                message: "advisory CVE-2024-7777 affects pkg".to_owned(),
                severity: Severity::High,
                class: RuleClass::VulnerableDep,
                file: None,
                region: Region::default(),
            },
        ];
        let fused = fuse(&raw);
        assert_eq!(
            fused.len(),
            1,
            "advisory in a message fuses with it in a rule id"
        );
        assert!(fused[0].corroborated());
        assert_eq!(fused[0].tool_count(), 2);
    }

    #[test]
    fn distinct_nonadvisory_locationless_findings_stay_separate() {
        let mk = |rule: &str| Finding {
            tool: "ramparts".to_owned(),
            rule_id: rule.to_owned(),
            message: "m".to_owned(),
            severity: Severity::Medium,
            class: RuleClass::OverPermission,
            file: None,
            region: Region::default(),
        };
        let fused = fuse(&[mk("broad-fs-access"), mk("network-egress")]);
        assert_eq!(
            fused.len(),
            2,
            "distinct location-less issues stay separate"
        );
        assert!(fused.iter().all(|f| !f.corroborated()));
    }

    #[test]
    fn one_tool_two_rules_at_one_site_is_not_corroborated() {
        // Two findings from the SAME tool at one site with different rule_ids: both
        // sources are kept, but corroboration counts distinct TOOLS — so tool_count is 1.
        let raw = vec![
            finding("gitleaks", RuleClass::Secret, Severity::High, "a.yaml", 5),
            Finding {
                rule_id: "gitleaks-other".to_owned(),
                ..finding("gitleaks", RuleClass::Secret, Severity::High, "a.yaml", 5)
            },
        ];
        let fused = fuse(&raw);
        assert_eq!(fused.len(), 1);
        assert_eq!(
            fused[0].sources.len(),
            2,
            "two distinct rule_ids → two sources"
        );
        assert_eq!(
            fused[0].tool_count(),
            1,
            "but corroboration counts tools, not rules"
        );
        assert!(!fused[0].corroborated());
    }

    #[test]
    fn advisory_file_is_backfilled_from_a_later_source() {
        let raw = vec![
            Finding {
                tool: "aguara".to_owned(),
                rule_id: "CVE-2024-1111".to_owned(),
                message: "dep".to_owned(),
                severity: Severity::High,
                class: RuleClass::VulnerableDep,
                file: None,
                region: Region::default(),
            },
            Finding {
                tool: "trivy".to_owned(),
                rule_id: "CVE-2024-1111".to_owned(),
                message: "dep".to_owned(),
                severity: Severity::High,
                class: RuleClass::VulnerableDep,
                file: Some("requirements.txt".to_owned()),
                region: Region {
                    start_line: Some(5),
                    ..Region::default()
                },
            },
        ];
        let fused = fuse(&raw);
        assert_eq!(fused.len(), 1);
        assert!(fused[0].corroborated());
        assert_eq!(
            fused[0].file.as_deref(),
            Some("requirements.txt"),
            "file backfilled from the later source"
        );
        assert_eq!(fused[0].region.start_line, Some(5));
    }

    #[test]
    fn columns_not_merged_when_first_source_has_a_line() {
        let base = |rule: &str, region: Region| Finding {
            tool: "gitleaks".to_owned(),
            rule_id: rule.to_owned(),
            message: "m".to_owned(),
            severity: Severity::High,
            class: RuleClass::Secret,
            file: Some("a.yaml".to_owned()),
            region,
        };
        let raw = vec![
            base(
                "r1",
                Region {
                    start_line: Some(12),
                    ..Region::default()
                },
            ),
            base(
                "r2",
                Region {
                    start_line: Some(12),
                    start_column: Some(3),
                    ..Region::default()
                },
            ),
        ];
        let fused = fuse(&raw);
        assert_eq!(fused.len(), 1, "same site fuses");
        assert_eq!(fused[0].region.start_line, Some(12));
        assert_eq!(
            fused[0].region.start_column, None,
            "columns are not enriched once a region already exists"
        );
    }

    #[test]
    fn advisory_does_not_stitch_a_line_from_a_different_file() {
        let raw = vec![
            Finding {
                tool: "aguara".to_owned(),
                rule_id: "CVE-2024-2222".to_owned(),
                message: "dep".to_owned(),
                severity: Severity::High,
                class: RuleClass::VulnerableDep,
                file: Some("requirements.txt".to_owned()),
                region: Region::default(),
            },
            Finding {
                tool: "trivy".to_owned(),
                rule_id: "CVE-2024-2222".to_owned(),
                message: "dep".to_owned(),
                severity: Severity::High,
                class: RuleClass::VulnerableDep,
                file: Some("package.json".to_owned()),
                region: Region {
                    start_line: Some(42),
                    ..Region::default()
                },
            },
        ];
        let fused = fuse(&raw);
        assert_eq!(fused.len(), 1, "same CVE fuses across files");
        // Representative is the minimum (file, line) pair, so package.json carries its own line 42.
        assert_eq!(fused[0].file.as_deref(), Some("package.json"));
        assert_eq!(fused[0].region.start_line, Some(42));
    }

    #[test]
    fn same_advisory_corroborates_across_differing_classifications() {
        let mk = |tool: &str, rule: &str, msg: &str| Finding {
            tool: tool.to_owned(),
            rule_id: rule.to_owned(),
            message: msg.to_owned(),
            severity: Severity::High,
            class: RuleClass::classify(tool, rule, msg),
            file: None,
            region: Region::default(),
        };
        let raw = vec![
            mk("trivy", "CVE-2024-7777", "vulnerable dependency"),
            mk("aguara", "CVE-2024-7777", "rce in foo"),
        ];
        assert_ne!(
            raw[0].class, raw[1].class,
            "sources must classify differently"
        );
        let fused = fuse(&raw);
        assert_eq!(fused.len(), 1, "same CVE fuses despite differing classes");
        assert!(fused[0].corroborated());
        assert_eq!(
            fused[0].class,
            RuleClass::VulnerableDep,
            "advisory class is canonical"
        );
    }

    #[test]
    fn prose_cve_in_a_non_advisory_finding_is_not_reclassified() {
        let taint = Finding {
            tool: "semgrep".to_owned(),
            rule_id: "dangerous-eval".to_owned(),
            message: "tainted exec resembling CVE-2024-1234".to_owned(),
            severity: Severity::High,
            class: RuleClass::TaintExec,
            file: Some("setup.sh".to_owned()),
            region: Region {
                start_line: Some(7),
                ..Region::default()
            },
        };
        let fused = fuse(&[
            taint,
            dep("trivy", "CVE-2024-1234", Severity::High, "vulnerable dep"),
        ]);
        assert_eq!(
            fused.len(),
            2,
            "prose CVE must not merge a taint finding into the dep"
        );
        assert!(fused.iter().any(|f| f.class == RuleClass::TaintExec));
        assert!(fused.iter().any(|f| f.class == RuleClass::VulnerableDep));
    }

    #[test]
    fn advisory_region_is_order_independent_for_lined_and_bare_same_file() {
        let mk = |tool: &str, region: Region| Finding {
            tool: tool.to_owned(),
            rule_id: "CVE-2024-3333".to_owned(),
            message: "vulnerable dep".to_owned(),
            severity: Severity::High,
            class: RuleClass::VulnerableDep,
            file: Some("requirements.txt".to_owned()),
            region,
        };
        let lined = mk(
            "trivy",
            Region {
                start_line: Some(5),
                start_column: Some(3),
                ..Region::default()
            },
        );
        let bare = mk("aguara", Region::default());
        let forward = serde_json::to_string(&fuse(&[lined.clone(), bare.clone()])).unwrap();
        let backward = serde_json::to_string(&fuse(&[bare, lined])).unwrap();
        assert_eq!(forward, backward, "advisory region depends on input order");
        assert_eq!(
            fuse(&[mk("a", Region::default())])[0].region.start_line,
            None
        );
        assert_eq!(
            fuse(&[
                mk(
                    "trivy",
                    Region {
                        start_line: Some(5),
                        ..Region::default()
                    }
                ),
                mk("aguara", Region::default())
            ])[0]
                .region
                .start_line,
            Some(5),
            "the present line survives a location-less source"
        );
    }

    #[test]
    fn fuse_is_byte_identical_for_distinct_locationless_same_class() {
        let mk = |rule: &str, msg: &str| Finding {
            tool: "ramparts".to_owned(),
            rule_id: rule.to_owned(),
            message: msg.to_owned(),
            severity: Severity::Medium,
            class: RuleClass::OverPermission,
            file: None,
            region: Region::default(),
        };
        let raw = vec![
            mk("broad-fs-access", "skill can read the whole filesystem"),
            mk(
                "network-egress",
                "skill can open arbitrary network connections",
            ),
        ];
        let mut reversed = raw.clone();
        reversed.reverse();
        let forward = serde_json::to_string(&fuse(&raw)).unwrap();
        let backward = serde_json::to_string(&fuse(&reversed)).unwrap();
        assert_eq!(forward, backward, "location-less order changed the report");
    }

    #[test]
    fn fuse_advisory_location_is_order_independent() {
        let mk = |tool: &str, file: &str, line: u32| Finding {
            tool: tool.to_owned(),
            rule_id: "CVE-2024-5555".to_owned(),
            message: "vulnerable dependency".to_owned(),
            severity: Severity::High,
            class: RuleClass::VulnerableDep,
            file: Some(file.to_owned()),
            region: Region {
                start_line: Some(line),
                ..Region::default()
            },
        };
        let raw = vec![mk("trivy", "a.txt", 1), mk("aguara", "b.txt", 2)];
        let mut reversed = raw.clone();
        reversed.reverse();
        let forward = serde_json::to_string(&fuse(&raw)).unwrap();
        let backward = serde_json::to_string(&fuse(&reversed)).unwrap();
        assert_eq!(
            forward, backward,
            "advisory location depends on input order"
        );
        let f = &fuse(&raw)[0];
        assert_eq!(f.file.as_deref(), Some("a.txt"));
        assert_eq!(f.region.start_line, Some(1));
    }

    #[test]
    fn fuse_sources_and_message_are_order_independent() {
        let mk = |tool: &str, msg: &str| Finding {
            tool: tool.to_owned(),
            rule_id: format!("{tool}-rule"),
            message: msg.to_owned(),
            severity: Severity::High,
            class: RuleClass::Secret,
            file: Some("a.yaml".to_owned()),
            region: Region {
                start_line: Some(5),
                ..Region::default()
            },
        };
        let raw = vec![
            mk("trivy", "hardcoded credential"),
            mk("gitleaks", "aws access token"),
        ];
        let mut reversed = raw.clone();
        reversed.reverse();
        let forward = fuse(&raw);
        let backward = fuse(&reversed);
        assert_eq!(
            serde_json::to_string(&forward).unwrap(),
            serde_json::to_string(&backward).unwrap(),
            "sources/message order leaked the input order"
        );
        assert_eq!(forward[0].message, "aws access token");
        let tools: Vec<&str> = forward[0].sources.iter().map(|s| s.tool.as_str()).collect();
        assert_eq!(tools, vec!["gitleaks", "trivy"]);
    }

    #[test]
    fn gate_is_inclusive_at_the_threshold() {
        // A `>` instead of `>=` would silently PASS a finding at the threshold — the worst
        // regression for a vetting tool.
        let one = |sev| fuse(&[finding("t", RuleClass::Secret, sev, "f.yaml", 1)]);
        assert!(
            Verdict::compute(&one(Severity::High), FailOn::High).failed,
            "High at --fail-on high must FAIL"
        );
        assert!(
            !Verdict::compute(&one(Severity::High), FailOn::Critical).failed,
            "High below --fail-on critical must PASS"
        );
        assert!(
            Verdict::compute(&one(Severity::Medium), FailOn::Medium).failed,
            "Medium at --fail-on medium must FAIL"
        );
        assert!(
            !Verdict::compute(&one(Severity::Medium), FailOn::High).failed,
            "Medium below --fail-on high must PASS"
        );
    }

    #[test]
    fn fuse_is_independent_of_input_order() {
        let raw = vec![
            finding("a", RuleClass::Secret, Severity::High, "f.yaml", 9),
            finding("b", RuleClass::Secret, Severity::High, "f.yaml", 5),
        ];
        let mut reversed = raw.clone();
        reversed.reverse();
        let forward = serde_json::to_string(&fuse(&raw)).unwrap();
        let backward = serde_json::to_string(&fuse(&reversed)).unwrap();
        assert_eq!(forward, backward, "fuse output depends on input order");
        let fused = fuse(&raw);
        assert_eq!(fused[0].region.start_line, Some(5));
        assert_eq!(fused[1].region.start_line, Some(9));
    }
}
