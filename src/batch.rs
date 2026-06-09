//! Parallel batch orchestration.
//!
//! Skills scan concurrently; within each skill the tools also run concurrently on
//! the shared rayon pool. Each tool is isolated — a crash or timeout becomes a
//! tool-error on that skill's report, never an aborted run — and each skill's
//! findings are fused into one verdict.

use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;

use crate::cli::Sandbox;
use crate::finding::FailOn;
use crate::fusion::{self, Verdict};
use crate::report::ScanReport;
use crate::scanners::{self, Scanner};
use crate::target::SkillTarget;

/// Fallback parallelism when the platform cannot report it.
const DEFAULT_PARALLELISM: usize = 4;

/// The machine's usable parallelism, or a sane default. Always >= 1.
pub fn default_jobs() -> usize {
    std::thread::available_parallelism().map_or(DEFAULT_PARALLELISM, |n| n.get())
}

/// Everything a batch run needs beyond the targets.
pub struct ScanConfig<'a> {
    pub scanners: &'a [Box<dyn Scanner>],
    pub mode: Sandbox,
    pub image: &'a str,
    pub fail_on: FailOn,
    pub timeout: Duration,
    pub jobs: usize,
}

/// Scan every skill, returning one report each. Targets run in parallel on a pool
/// sized to `jobs`; a progress bar tracks completion on stderr so stdout stays
/// clean for piped reports.
pub fn scan(targets: &[SkillTarget], cfg: &ScanConfig<'_>) -> Vec<ScanReport> {
    let bar = ProgressBar::new(targets.len() as u64);
    bar.set_style(
        ProgressStyle::with_template("{bar:30} {pos}/{len} skills  {elapsed_precise}")
            .unwrap_or_else(|_| ProgressStyle::default_bar()),
    );

    let reports = match rayon::ThreadPoolBuilder::new()
        .num_threads(cfg.jobs.max(1))
        .build()
    {
        Ok(pool) => pool.install(|| scan_all(targets, cfg, &bar)),
        // A pool that won't build is not fatal — fall back to the global pool.
        Err(_) => scan_all(targets, cfg, &bar),
    };

    bar.finish_and_clear();
    reports
}

fn scan_all(targets: &[SkillTarget], cfg: &ScanConfig<'_>, bar: &ProgressBar) -> Vec<ScanReport> {
    targets
        .par_iter()
        .map(|target| {
            let report = scan_target(target, cfg);
            bar.inc(1);
            report
        })
        .collect()
}

fn scan_target(target: &SkillTarget, cfg: &ScanConfig<'_>) -> ScanReport {
    let outcomes: Vec<scanners::ScanOutcome> = cfg
        .scanners
        .par_iter()
        .map(|scanner| {
            scanners::scan_one(
                scanner.as_ref(),
                cfg.mode,
                cfg.image,
                &target.root,
                cfg.timeout,
            )
        })
        .collect();

    let mut findings = Vec::new();
    let mut tool_errors = Vec::new();
    for outcome in outcomes {
        findings.extend(outcome.findings);
        if let Some(e) = outcome.error {
            tool_errors.push(e);
        }
    }

    let fused = fusion::fuse(&findings);
    let verdict = Verdict::compute(&fused, cfg.fail_on);
    ScanReport {
        target: target.display.clone(),
        raw: findings,
        fused,
        verdict,
        tool_errors,
    }
}

/// The first skill that failed to scan at all — every tool errored and it produced no
/// result. Such a skill was never vetted, so it must not read as a clean PASS; the caller
/// turns it into exit 12 (engine failure) even when other skills scanned fine. Returns the
/// offending report so the caller surfaces its tool-error without re-deriving the predicate.
pub fn first_unscanned(reports: &[ScanReport], total_tools: usize) -> Option<&ScanReport> {
    if total_tools == 0 {
        return None;
    }
    reports
        .iter()
        .find(|r| r.raw.is_empty() && r.tool_errors.len() >= total_tools)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::finding::{Finding, Region, RuleClass, Severity, ToolError};
    #[cfg(unix)]
    use crate::sandbox::{Output, Plan};

    #[test]
    fn default_jobs_is_at_least_one() {
        assert!(default_jobs() >= 1);
    }

    /// A scanner that emits a fixed SARIF document via `printf` — exercises the full
    /// host-mode path (spawn → capture stdout → parse → fuse) with no Docker.
    #[cfg(unix)]
    struct StubScanner(String);
    #[cfg(unix)]
    impl Scanner for StubScanner {
        fn id(&self) -> &'static str {
            "stub"
        }
        fn commands(&self, _scan: &str, _out: &str) -> Vec<Plan> {
            vec![Plan {
                program: "printf".to_owned(),
                args: vec!["%s".to_owned(), self.0.clone()],
                output: Output::Stdout,
            }]
        }
    }

    #[cfg(unix)]
    #[test]
    fn scan_target_fuses_a_stub_scanner_end_to_end() {
        let sarif = r#"{"runs":[{"tool":{"driver":{"name":"stub"}},
            "results":[{"ruleId":"hardcoded-secret","level":"error",
            "message":{"text":"hardcoded token"},
            "locations":[{"physicalLocation":{"artifactLocation":{"uri":"s.yaml"},
            "region":{"startLine":3}}}]}]}]}"#;
        let scanners: Vec<Box<dyn Scanner>> = vec![Box::new(StubScanner(sarif.to_owned()))];
        let tmp = tempfile::tempdir().unwrap();
        let target = SkillTarget {
            display: "stub-skill".to_owned(),
            root: tmp.path().to_path_buf(),
        };
        let cfg = ScanConfig {
            scanners: &scanners,
            mode: Sandbox::Host,
            image: "unused",
            fail_on: FailOn::High,
            timeout: Duration::from_secs(10),
            jobs: 1,
        };
        let report = scan_target(&target, &cfg);
        assert!(report.tool_errors.is_empty(), "stub must not error");
        assert_eq!(report.fused.len(), 1);
        assert_eq!(report.fused[0].severity, Severity::High);
        assert!(report.verdict.failed, "a HIGH finding trips --fail-on high");
    }

    #[cfg(unix)]
    #[test]
    fn missing_tool_becomes_a_tool_error_not_a_crash() {
        struct MissingScanner;
        impl Scanner for MissingScanner {
            fn id(&self) -> &'static str {
                "missing"
            }
            fn commands(&self, _scan: &str, _out: &str) -> Vec<Plan> {
                vec![Plan {
                    program: "definitely-not-a-real-binary-xyz".to_owned(),
                    args: vec![],
                    output: Output::Stdout,
                }]
            }
        }
        let scanners: Vec<Box<dyn Scanner>> = vec![Box::new(MissingScanner)];
        let tmp = tempfile::tempdir().unwrap();
        let target = SkillTarget {
            display: "t".to_owned(),
            root: tmp.path().to_path_buf(),
        };
        let cfg = ScanConfig {
            scanners: &scanners,
            mode: Sandbox::Host,
            image: "unused",
            fail_on: FailOn::High,
            timeout: Duration::from_secs(10),
            jobs: 1,
        };
        let report = scan_target(&target, &cfg);
        assert_eq!(report.tool_errors.len(), 1);
        assert!(report.fused.is_empty());
        assert!(first_unscanned(std::slice::from_ref(&report), 1).is_some());
    }

    fn engine_report(raw: Vec<Finding>, errors: Vec<ToolError>) -> ScanReport {
        ScanReport {
            target: "t".to_owned(),
            raw,
            fused: Vec::new(),
            verdict: Verdict::compute(&[], FailOn::High),
            tool_errors: errors,
        }
    }

    fn tool_err(tool: &str) -> ToolError {
        ToolError {
            tool: tool.to_owned(),
            detail: "boom".to_owned(),
        }
    }

    fn a_finding() -> Finding {
        Finding {
            tool: "x".to_owned(),
            rule_id: "r".to_owned(),
            message: "m".to_owned(),
            severity: Severity::Low,
            class: RuleClass::Other,
            file: None,
            region: Region::default(),
        }
    }

    #[test]
    fn unscanned_false_when_a_skill_produced_output() {
        let r = engine_report(vec![a_finding()], vec![tool_err("a"), tool_err("b")]);
        assert!(first_unscanned(std::slice::from_ref(&r), 2).is_none());
    }

    #[test]
    fn unscanned_true_when_one_skill_is_fully_dead() {
        // A fully-dead skill gates the run even when another scanned clean — never a silent PASS.
        let clean = engine_report(Vec::new(), Vec::new());
        let dead = engine_report(Vec::new(), vec![tool_err("a"), tool_err("b")]);
        assert!(first_unscanned(&[clean, dead], 2).is_some());
    }

    #[test]
    fn unscanned_false_when_a_skill_has_a_clean_tool_among_errors() {
        let r = engine_report(Vec::new(), vec![tool_err("a")]);
        assert!(
            first_unscanned(std::slice::from_ref(&r), 2).is_none(),
            "a single clean tool among errors means the skill was scanned"
        );
    }

    #[test]
    fn unscanned_false_with_no_tools_or_no_reports() {
        let dead = engine_report(Vec::new(), vec![tool_err("a")]);
        assert!(
            first_unscanned(std::slice::from_ref(&dead), 0).is_none(),
            "zero tools is never an engine failure"
        );
        assert!(
            first_unscanned(&[], 1).is_none(),
            "no reports is never an engine failure"
        );
    }

    /// A multi-plan scanner (aguara's `scan`+`check` shape): one adapter, several
    /// plans, every plan's findings stamped with the one adapter id.
    #[cfg(unix)]
    struct TwoPass(String, String);
    #[cfg(unix)]
    impl Scanner for TwoPass {
        fn id(&self) -> &'static str {
            "twopass"
        }
        fn commands(&self, _scan: &str, _out: &str) -> Vec<Plan> {
            let plan = |body: &str| Plan {
                program: "printf".to_owned(),
                args: vec!["%s".to_owned(), body.to_owned()],
                output: Output::Stdout,
            };
            vec![plan(&self.0), plan(&self.1)]
        }
    }

    #[cfg(unix)]
    fn sarif_with_rule(rule: &str) -> String {
        let mut s = String::from(
            r#"{"runs":[{"tool":{"driver":{"name":"twopass"}},"results":[{"ruleId":""#,
        );
        s.push_str(rule);
        s.push_str(r#"","level":"error","message":{"text":"x"}}]}]}"#);
        s
    }

    #[cfg(unix)]
    #[test]
    fn multi_plan_scanner_merges_findings_from_every_plan() {
        let tmp = tempfile::tempdir().unwrap();
        let scanner = TwoPass(sarif_with_rule("pass-one"), sarif_with_rule("pass-two"));
        let findings = scanners::scan_one(
            &scanner,
            Sandbox::Host,
            "unused",
            tmp.path(),
            Duration::from_secs(10),
        )
        .findings;
        assert_eq!(findings.len(), 2, "both passes' findings survive");
        assert!(findings.iter().all(|f| f.tool == "twopass"));
        assert!(findings.iter().any(|f| f.rule_id == "pass-one"));
        assert!(findings.iter().any(|f| f.rule_id == "pass-two"));
    }

    #[cfg(unix)]
    #[test]
    fn aguara_shape_merges_two_distinct_file_outputs() {
        // Mirrors aguara: two File plans in one out dir, merged under one adapter id.
        struct TwoFile;
        impl Scanner for TwoFile {
            fn id(&self) -> &'static str {
                "twofile"
            }
            fn commands(&self, _scan: &str, out: &str) -> Vec<Plan> {
                let plan = |name: &str, rule: &str| Plan {
                    program: "sh".to_owned(),
                    args: vec![
                        "-c".to_owned(),
                        format!("printf '%s' '{}' > '{out}/{name}'", sarif_with_rule(rule)),
                    ],
                    output: Output::File(name.to_owned()),
                };
                vec![
                    plan("scan.sarif", "from-scan"),
                    plan("check.sarif", "from-check"),
                ]
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let findings = scanners::scan_one(
            &TwoFile,
            Sandbox::Host,
            "unused",
            tmp.path(),
            Duration::from_secs(10),
        )
        .findings;
        assert_eq!(findings.len(), 2, "both file-output passes are merged");
        assert!(findings.iter().any(|f| f.rule_id == "from-scan"));
        assert!(findings.iter().any(|f| f.rule_id == "from-check"));
        assert!(findings.iter().all(|f| f.tool == "twofile"));
    }

    #[cfg(unix)]
    #[test]
    fn host_mode_strips_the_absolute_scan_root_from_paths() {
        struct AbsPathScanner;
        impl Scanner for AbsPathScanner {
            fn id(&self) -> &'static str {
                "abs"
            }
            fn commands(&self, scan: &str, _out: &str) -> Vec<Plan> {
                let mut sarif = String::from(
                    r#"{"runs":[{"tool":{"driver":{"name":"abs"}},"results":[{"ruleId":"r","level":"error","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":""#,
                );
                sarif.push_str(scan);
                sarif.push_str(r#"/nested/file.yaml"}}}]}]}]}"#);
                vec![Plan {
                    program: "printf".to_owned(),
                    args: vec!["%s".to_owned(), sarif],
                    output: Output::Stdout,
                }]
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let findings = scanners::scan_one(
            &AbsPathScanner,
            Sandbox::Host,
            "unused",
            tmp.path(),
            Duration::from_secs(10),
        )
        .findings;
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].file.as_deref(),
            Some("nested/file.yaml"),
            "the absolute scan-root prefix is stripped to a skill-relative path"
        );
    }

    #[cfg(unix)]
    #[test]
    fn multi_plan_partial_success_is_not_a_tool_error() {
        let tmp = tempfile::tempdir().unwrap();
        let scanner = TwoPass(sarif_with_rule("only-pass"), String::new());
        let findings = scanners::scan_one(
            &scanner,
            Sandbox::Host,
            "unused",
            tmp.path(),
            Duration::from_secs(10),
        )
        .findings;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "only-pass");
    }

    #[cfg(unix)]
    #[test]
    fn host_mode_reads_a_file_reporting_scanner() {
        struct FileScanner;
        impl Scanner for FileScanner {
            fn id(&self) -> &'static str {
                "filer"
            }
            fn commands(&self, _scan: &str, out: &str) -> Vec<Plan> {
                let sarif = r#"{"runs":[{"tool":{"driver":{"name":"filer"}},"results":[{"ruleId":"r","level":"error","message":{"text":"m"}}]}]}"#;
                vec![Plan {
                    program: "sh".to_owned(),
                    args: vec![
                        "-c".to_owned(),
                        format!("printf '%s' '{sarif}' > '{out}/x.sarif'"),
                    ],
                    output: Output::File("x.sarif".to_owned()),
                }]
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let findings = scanners::scan_one(
            &FileScanner,
            Sandbox::Host,
            "unused",
            tmp.path(),
            Duration::from_secs(10),
        )
        .findings;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "r");
    }

    #[cfg(unix)]
    #[test]
    fn file_output_never_written_becomes_a_tool_error() {
        struct NoFileScanner;
        impl Scanner for NoFileScanner {
            fn id(&self) -> &'static str {
                "nofile"
            }
            fn commands(&self, _scan: &str, _out: &str) -> Vec<Plan> {
                vec![Plan {
                    program: "true".to_owned(),
                    args: vec![],
                    output: Output::File("x.sarif".to_owned()),
                }]
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let err = scanners::scan_one(
            &NoFileScanner,
            Sandbox::Host,
            "unused",
            tmp.path(),
            Duration::from_secs(10),
        )
        .error
        .unwrap();
        assert!(
            err.detail.contains("no report produced"),
            "detail: {}",
            err.detail
        );
    }

    #[cfg(unix)]
    #[test]
    fn unparseable_output_becomes_a_tool_error() {
        let tmp = tempfile::tempdir().unwrap();
        let err = scanners::scan_one(
            &StubScanner("not json at all".to_owned()),
            Sandbox::Host,
            "unused",
            tmp.path(),
            Duration::from_secs(10),
        )
        .error
        .unwrap();
        assert!(
            err.detail.contains("unparseable report"),
            "detail: {}",
            err.detail
        );
    }

    #[cfg(unix)]
    #[test]
    fn empty_output_becomes_a_tool_error() {
        let tmp = tempfile::tempdir().unwrap();
        let err = scanners::scan_one(
            &StubScanner(String::new()),
            Sandbox::Host,
            "unused",
            tmp.path(),
            Duration::from_secs(10),
        )
        .error
        .unwrap();
        assert!(
            err.detail.contains("no report produced"),
            "detail: {}",
            err.detail
        );
    }

    #[cfg(unix)]
    #[test]
    fn unresolvable_target_becomes_a_tool_error() {
        let tmp = tempfile::tempdir().unwrap();
        let err = scanners::scan_one(
            &StubScanner(String::new()),
            Sandbox::Host,
            "unused",
            &tmp.path().join("does-not-exist"),
            Duration::from_secs(10),
        )
        .error
        .unwrap();
        assert!(
            err.detail.contains("cannot resolve target path"),
            "detail: {}",
            err.detail
        );
    }

    #[cfg(unix)]
    #[test]
    fn docker_mode_refuses_a_comma_in_the_target_path() {
        // A `,` in the mount source would corrupt the `--mount` CSV, so fail-closed.
        let tmp = tempfile::tempdir().unwrap();
        let weird = tmp.path().join("has,comma");
        std::fs::create_dir(&weird).unwrap();
        let err = scanners::scan_one(
            &StubScanner(String::new()),
            Sandbox::Docker,
            "img",
            &weird,
            Duration::from_secs(10),
        )
        .error
        .unwrap();
        assert!(
            err.detail.contains("cannot be bind-mounted"),
            "detail: {}",
            err.detail
        );
    }

    #[cfg(unix)]
    #[test]
    fn multi_plan_surfaces_both_findings_and_a_later_plan_failure() {
        struct ProduceThenHang(String);
        impl Scanner for ProduceThenHang {
            fn id(&self) -> &'static str {
                "producehang"
            }
            fn commands(&self, _scan: &str, _out: &str) -> Vec<Plan> {
                vec![
                    Plan {
                        program: "printf".to_owned(),
                        args: vec!["%s".to_owned(), self.0.clone()],
                        output: Output::Stdout,
                    },
                    Plan {
                        program: "sleep".to_owned(),
                        args: vec!["10".to_owned()],
                        output: Output::Stdout,
                    },
                ]
            }
        }
        let sarif = r#"{"runs":[{"tool":{"driver":{"name":"producehang"}},"results":[{"ruleId":"real-hit","level":"error","message":{"text":"m"}}]}]}"#;
        let tmp = tempfile::tempdir().unwrap();
        let outcome = scanners::scan_one(
            &ProduceThenHang(sarif.to_owned()),
            Sandbox::Host,
            "unused",
            tmp.path(),
            Duration::from_millis(300),
        );
        assert_eq!(
            outcome.findings.len(),
            1,
            "the earlier plan's real finding survives"
        );
        assert_eq!(outcome.findings[0].rule_id, "real-hit");
        assert!(
            outcome.error.is_some(),
            "the later plan's timeout surfaces as a tool-error, never silent"
        );
    }

    #[cfg(unix)]
    #[test]
    fn per_tool_timeout_is_shared_across_plans() {
        // The timeout (not plan 2's finding) proves the budget is shared across plans, not per-plan.
        struct SlowThenFast(String);
        impl Scanner for SlowThenFast {
            fn id(&self) -> &'static str {
                "slowfast"
            }
            fn commands(&self, _scan: &str, _out: &str) -> Vec<Plan> {
                vec![
                    Plan {
                        program: "sleep".to_owned(),
                        args: vec!["10".to_owned()],
                        output: Output::Stdout,
                    },
                    Plan {
                        program: "printf".to_owned(),
                        args: vec!["%s".to_owned(), self.0.clone()],
                        output: Output::Stdout,
                    },
                ]
            }
        }
        let sarif = r#"{"runs":[{"tool":{"driver":{"name":"slowfast"}},"results":[{"ruleId":"r","level":"error","message":{"text":"m"}}]}]}"#;
        let tmp = tempfile::tempdir().unwrap();
        let err = scanners::scan_one(
            &SlowThenFast(sarif.to_owned()),
            Sandbox::Host,
            "unused",
            tmp.path(),
            Duration::from_millis(300),
        )
        .error
        .unwrap();
        assert!(err.detail.contains("timed out"), "detail: {}", err.detail);
    }

    #[cfg(unix)]
    #[test]
    fn timed_out_tool_becomes_a_tool_error() {
        struct SleepScanner;
        impl Scanner for SleepScanner {
            fn id(&self) -> &'static str {
                "sleeper"
            }
            fn commands(&self, _scan: &str, _out: &str) -> Vec<Plan> {
                vec![Plan {
                    program: "sleep".to_owned(),
                    args: vec!["30".to_owned()],
                    output: Output::Stdout,
                }]
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let err = scanners::scan_one(
            &SleepScanner,
            Sandbox::Host,
            "unused",
            tmp.path(),
            Duration::from_millis(200),
        )
        .error
        .unwrap();
        assert!(err.detail.contains("timed out"), "detail: {}", err.detail);
    }
}
