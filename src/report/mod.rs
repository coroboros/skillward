//! Report rendering: one fused result per skill into terminal, Markdown, JSON, or
//! SARIF. The verdict leads, corroborated findings come first, and a degraded run
//! (a tool that errored) is always visible so a missing scanner never reads as a
//! clean skill.

use std::fmt::Write as _;
use std::path::Path;

use serde::Serialize;

use crate::cli::Format;
use crate::color;
use crate::error::SkillwardError;
use crate::finding::{FailOn, Finding, Severity, ToolError};
use crate::fusion::{FusedFinding, Verdict};

/// Bumped when the JSON schema changes incompatibly.
const JSON_SCHEMA_VERSION: u32 = 1;

/// The complete result for one scanned skill.
pub struct ScanReport {
    /// Display name (the skill path or remote URL).
    pub target: String,
    /// Raw per-tool findings, kept for SARIF emission.
    pub raw: Vec<Finding>,
    /// Deduplicated, corroborated findings.
    pub fused: Vec<FusedFinding>,
    pub verdict: Verdict,
    /// Scanners that could not contribute to this skill's result.
    pub tool_errors: Vec<ToolError>,
}

/// Render every skill's report in the requested format, with an aggregate verdict.
pub fn render(reports: &[ScanReport], format: Format) -> String {
    match format {
        Format::Terminal => render_terminal(reports),
        Format::Markdown => render_markdown(reports),
        Format::Json => render_json(reports),
        Format::Sarif => render_sarif(reports),
    }
}

/// `true` when any skill tripped its gate — the run's overall fail signal.
pub fn any_failed(reports: &[ScanReport]) -> bool {
    reports.iter().any(|r| r.verdict.failed)
}

/// Findings at or above the gate, summed across skills — for the closing error line.
pub fn total_at_or_above_threshold(reports: &[ScanReport]) -> usize {
    reports
        .iter()
        .map(|r| r.verdict.at_or_above_threshold)
        .sum()
}

/// The CI gate: fail with [`SkillwardError::ThresholdExceeded`] (exit 20) when any
/// skill has a finding at or above `--fail-on`. `FailOn::None` never gates. This is
/// the "never a silent PASS, never a spurious FAIL" contract, kept here so it is
/// testable rather than buried in `main`.
pub fn gate(reports: &[ScanReport], fail_on: FailOn) -> Result<(), SkillwardError> {
    if let Some(severity) = fail_on.threshold()
        && any_failed(reports)
    {
        return Err(SkillwardError::ThresholdExceeded {
            severity,
            count: total_at_or_above_threshold(reports),
        });
    }
    Ok(())
}

/// Write a rendered report to `path`, stripped of ANSI: `std::fs::write` bypasses
/// anstream's stream-level stripping, so a terminal-format report would otherwise
/// carry color into the file. A write failure maps to an Io error (exit 1).
pub fn write_to_file(path: &Path, rendered: &str) -> Result<(), SkillwardError> {
    std::fs::write(path, color::strip(rendered)).map_err(|e| SkillwardError::Io {
        detail: format!("could not write {}: {e}", path.display()),
    })
}

fn severity_style(severity: Severity) -> anstyle::Style {
    match severity {
        Severity::Critical | Severity::High => color::ERROR,
        Severity::Medium => color::WARN,
        Severity::Low => color::DIM,
    }
}

/// The fail/pass color rule, defined once: failed → error red, clean → success green.
const fn pass_fail_style(failed: bool) -> anstyle::Style {
    if failed { color::ERROR } else { color::SUCCESS }
}

fn verdict_style(verdict: &Verdict) -> anstyle::Style {
    pass_fail_style(verdict.failed)
}

/// The shared per-skill verdict fragment `N finding(s), M corroborated`, so the
/// terminal and Markdown lines can't drift apart.
fn verdict_summary(verdict: &Verdict) -> String {
    format!(
        "{} finding(s), {} corroborated",
        verdict.total, verdict.corroborated
    )
}

fn counts_line(verdict: &Verdict) -> String {
    // Iterate the scale (highest first) so a new severity is rendered automatically;
    // `SeverityCounts::of` is the exhaustive accessor that forces the count to exist.
    Severity::ALL
        .iter()
        .rev()
        .map(|s| format!("{}:{}", s.label(), verdict.counts.of(*s)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn location(f: &FusedFinding) -> String {
    match (&f.file, f.region.start_line) {
        (Some(file), Some(line)) => format!("{}:{line}", sanitize(file)),
        (Some(file), None) => sanitize(file),
        (None, _) => "—".to_owned(),
    }
}

fn sources_label(tools: &[&str]) -> String {
    format!("[{}]", tools.join(", "))
}

/// Escape the Markdown table-cell delimiter so a `|` in a scanned skill's filename
/// or in a finding message cannot break the row's column layout.
fn md_cell(s: &str) -> String {
    s.replace('|', "\\|")
}

/// Wrap attacker-derived text in an inline code span: GFM parses code-span content as
/// literal, so no link, image, bare-URL autolink, or raw HTML renders inside it (GFM §6.3).
/// A backtick can't be escaped inside a span, so it is replaced; a pipe is `\|`-escaped so it
/// can't split a table row. Runs after [`sanitize`].
fn md_code(s: &str) -> String {
    format!("`{}`", s.replace('`', "'").replace('|', "\\|"))
}

fn render_terminal(reports: &[ScanReport]) -> String {
    let mut out = String::new();
    for report in reports {
        let _ = writeln!(
            out,
            "{}  {}",
            color::paint(color::ACCENT, "skillward"),
            sanitize(&report.target),
        );
        let _ = writeln!(
            out,
            "  {}  {}  {}",
            color::paint(verdict_style(&report.verdict), report.verdict.label()),
            color::paint(color::DIM, &counts_line(&report.verdict)),
            color::paint(
                color::DIM,
                &format!("({})", verdict_summary(&report.verdict))
            ),
        );
        for f in &report.fused {
            let tools = f.distinct_tools();
            let corrob = if crate::fusion::is_corroborated(tools.len()) {
                color::paint(color::ACCENT, &format!("×{}", tools.len()))
            } else {
                String::new()
            };
            let _ = writeln!(
                out,
                "  {} {:<9} {:<14} {:<24} {} {} {}",
                color::paint(severity_style(f.severity), "●"),
                color::paint(severity_style(f.severity), f.severity.label()),
                f.class.label(),
                location(f),
                truncate(&f.message, 60),
                color::paint(color::DIM, &sources_label(&tools)),
                corrob,
            );
        }
        for e in &report.tool_errors {
            let _ = writeln!(
                out,
                "  {} {}: {}",
                color::paint(color::WARN, "tool-error"),
                e.tool,
                color::paint(color::DIM, &sanitize(&e.detail)),
            );
        }
        out.push('\n');
    }
    let _ = write!(out, "{}", aggregate_line(reports));
    out
}

/// The run-level rollup: how many skills failed their gate, and the PASS/FAIL label.
/// One source for what terminal, Markdown, and JSON each report about the whole run.
fn aggregate(reports: &[ScanReport]) -> (usize, &'static str) {
    let failed = reports.iter().filter(|r| r.verdict.failed).count();
    (failed, crate::fusion::verdict_label(failed > 0))
}

fn aggregate_line(reports: &[ScanReport]) -> String {
    let (failed, label) = aggregate(reports);
    color::paint(
        pass_fail_style(failed > 0),
        &format!(
            "aggregate: {label} · {} of {} skill(s) failed",
            failed,
            reports.len()
        ),
    )
}

const REPORT_TITLE: &str = "# skillward report";

fn render_markdown(reports: &[ScanReport]) -> String {
    let mut out = format!("{REPORT_TITLE}\n\n");
    let (failed, label) = aggregate(reports);
    let _ = writeln!(
        out,
        "**Aggregate:** {label} — {} of {} skill(s) failed\n",
        failed,
        reports.len(),
    );
    for report in reports {
        let _ = writeln!(out, "## {}\n", md_code(&sanitize(&report.target)));
        let _ = writeln!(
            out,
            "**Verdict:** {} · {} · {}\n",
            report.verdict.label(),
            counts_line(&report.verdict),
            verdict_summary(&report.verdict),
        );
        if !report.fused.is_empty() {
            out.push_str("| severity | class | location | sources | detail |\n");
            out.push_str("| --- | --- | --- | --- | --- |\n");
            for f in &report.fused {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} | {} |",
                    f.severity.label(),
                    f.class.label(),
                    md_code(&location(f)),
                    md_cell(&sources_label(&f.distinct_tools())),
                    md_code(&truncate(&f.message, 100)),
                );
            }
            out.push('\n');
        }
        for e in &report.tool_errors {
            let _ = writeln!(
                out,
                "> tool-error — `{}`: {}\n",
                e.tool,
                md_code(&sanitize(&e.detail))
            );
        }
    }
    out
}

fn render_json(reports: &[ScanReport]) -> String {
    #[derive(Serialize)]
    struct Doc<'a> {
        schema_version: u32,
        skillward_version: &'a str,
        summary: Summary,
        results: Vec<Result_<'a>>,
    }
    #[derive(Serialize)]
    struct Summary {
        failed: bool,
        skills: usize,
        skills_failed: usize,
    }
    #[derive(Serialize)]
    struct Result_<'a> {
        target: &'a str,
        verdict: &'a Verdict,
        findings: &'a [FusedFinding],
        tool_errors: &'a [ToolError],
    }

    let doc = Doc {
        schema_version: JSON_SCHEMA_VERSION,
        skillward_version: env!("CARGO_PKG_VERSION"),
        summary: Summary {
            failed: any_failed(reports),
            skills: reports.len(),
            skills_failed: aggregate(reports).0,
        },
        results: reports
            .iter()
            .map(|r| Result_ {
                target: &r.target,
                verdict: &r.verdict,
                findings: &r.fused,
                tool_errors: &r.tool_errors,
            })
            .collect(),
    };
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_owned())
}

fn render_sarif(reports: &[ScanReport]) -> String {
    let all: Vec<Finding> = reports.iter().flat_map(|r| r.raw.iter().cloned()).collect();
    crate::sarif::render(&all)
}

/// Neutralize attacker-derived text for a terminal/Markdown report: an ANSI escape could
/// rewrite the verdict line, a bidi/zero-width char could disguise a path. Tabs/newlines/CR
/// collapse to a space; Cc controls plus the bidi/format/separator chars `is_control` misses
/// become U+FFFD. JSON/SARIF need no pass — serde escapes them.
pub fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\t' | '\n' | '\r' => ' ',
            '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{feff}' => '\u{fffd}',
            c if c.is_control() => '\u{fffd}',
            c => c,
        })
        .collect()
}

/// Sanitize, then truncate to `max` chars with an ellipsis, on a char boundary so
/// multi-byte messages never panic the slice.
fn truncate(text: &str, max: usize) -> String {
    let flat = sanitize(text);
    if flat.chars().count() <= max {
        return flat;
    }
    let cut: String = flat.chars().take(max.saturating_sub(1)).collect();
    format!("{cut}…")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::finding::{FailOn, Region, RuleClass};
    use crate::fusion::{FusedFinding, Source, fuse};

    fn report(target: &str, fused: Vec<FusedFinding>, fail_on: FailOn) -> ScanReport {
        let verdict = Verdict::compute(&fused, fail_on);
        ScanReport {
            target: target.to_owned(),
            raw: Vec::new(),
            fused,
            verdict,
            tool_errors: Vec::new(),
        }
    }

    fn fused_secret() -> FusedFinding {
        let raw = vec![
            Finding {
                tool: "gitleaks".to_owned(),
                rule_id: "aws".to_owned(),
                message: "AWS token".to_owned(),
                severity: Severity::Critical,
                class: RuleClass::Secret,
                file: Some("config.yaml".to_owned()),
                region: Region {
                    start_line: Some(12),
                    ..Region::default()
                },
            },
            Finding {
                tool: "trivy".to_owned(),
                rule_id: "secret".to_owned(),
                message: "secret".to_owned(),
                severity: Severity::High,
                class: RuleClass::Secret,
                file: Some("config.yaml".to_owned()),
                region: Region {
                    start_line: Some(12),
                    ..Region::default()
                },
            },
        ];
        fuse(&raw).into_iter().next().unwrap()
    }

    #[test]
    fn json_is_versioned_and_carries_the_verdict() {
        let r = report("skill-a", vec![fused_secret()], FailOn::High);
        let json = render_json(&[r]);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["schema_version"], JSON_SCHEMA_VERSION);
        assert_eq!(v["skillward_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(v["summary"]["failed"], true);
        assert_eq!(v["summary"]["skills"], 1);
        assert_eq!(v["summary"]["skills_failed"], 1);
        assert_eq!(v["results"][0]["target"], "skill-a");
        let finding = &v["results"][0]["findings"][0];
        assert_eq!(finding["severity"], "critical");
        assert_eq!(finding["class"], "secret");
        assert_eq!(finding["sources"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn json_serializes_the_full_verdict() {
        let r = report("skill", vec![fused_secret()], FailOn::High);
        let v: serde_json::Value =
            serde_json::from_str(&render_json(std::slice::from_ref(&r))).unwrap();
        let verdict = &v["results"][0]["verdict"];
        assert_eq!(verdict["failed"], true);
        assert_eq!(verdict["worst"], "critical");
        assert_eq!(verdict["total"], 1);
        assert_eq!(verdict["corroborated"], 1);
        assert_eq!(verdict["at_or_above_threshold"], 1);
        assert_eq!(verdict["counts"]["critical"], 1);
    }

    #[test]
    fn terminal_marks_corroboration_and_verdict() {
        let r = report("skill-a", vec![fused_secret()], FailOn::High);
        let out = render_terminal(&[r]);
        assert!(out.contains("FAIL"));
        assert!(out.contains("config.yaml:12"));
        assert!(out.contains("×2"), "corroboration count shown:\n{out}");
        assert!(out.contains("aggregate:"));
    }

    #[test]
    fn markdown_has_a_table_and_aggregate() {
        let r = report("skill-a", vec![fused_secret()], FailOn::High);
        let md = render_markdown(&[r]);
        assert!(md.contains(REPORT_TITLE));
        assert!(md.contains("| severity | class |"));
        assert!(md.contains("config.yaml:12"));
    }

    #[test]
    fn clean_report_passes_and_pipes_without_ansi_markers_in_json() {
        let r = report("clean", Vec::new(), FailOn::Low);
        assert!(!any_failed(&[report("clean", Vec::new(), FailOn::Low)]));
        let json = render_json(&[r]);
        assert!(json.contains("\"failed\": false"));
    }

    #[test]
    fn tool_error_is_rendered_loud() {
        let mut r = report("skill", Vec::new(), FailOn::High);
        r.tool_errors.push(ToolError {
            tool: "ramparts".to_owned(),
            detail: "timed out".to_owned(),
        });
        let out = render_terminal(&[r]);
        assert!(out.contains("tool-error"));
        assert!(out.contains("ramparts"));
    }

    #[test]
    fn tool_error_detail_control_chars_are_neutralized() {
        let mut r = report("skill", Vec::new(), FailOn::High);
        r.tool_errors.push(ToolError {
            tool: "ramparts".to_owned(),
            detail: "boom\u{1b}[31m\u{07}".to_owned(),
        });
        let term = render_terminal(std::slice::from_ref(&r));
        assert!(!term.contains('\u{07}'), "BEL neutralized in terminal");
        assert!(
            !crate::color::strip(&term).contains('\u{1b}'),
            "no escape survives"
        );
        let md = render_markdown(std::slice::from_ref(&r));
        assert!(
            !md.contains('\u{07}') && !md.contains('\u{1b}'),
            "neutralized in markdown"
        );
    }

    #[test]
    fn sanitize_neutralizes_bidi_and_zero_width_chars() {
        for c in ['\u{202e}', '\u{200b}', '\u{2066}', '\u{2028}', '\u{feff}'] {
            let out = sanitize(&format!("a{c}b"));
            assert!(!out.contains(c), "{c:?} not neutralized");
            assert!(out.contains('\u{fffd}'));
        }
    }

    #[test]
    fn truncate_keeps_short_input_and_ellipsizes_long_input() {
        assert_eq!(truncate("abc", 10), "abc");
        assert_eq!(truncate("abcdefghijk", 5), "abcd…");
        let t = truncate(&"é".repeat(100), 10);
        assert!(t.chars().count() <= 10 && t.ends_with('…'));
    }

    #[test]
    fn unused_source_field_is_constructible() {
        let s = Source {
            tool: "t".to_owned(),
            rule_id: "r".to_owned(),
            severity: Severity::Low,
        };
        assert_eq!(s.severity, Severity::Low);
    }

    #[test]
    fn terminal_neutralizes_untrusted_control_characters() {
        let mut f = fused_secret();
        f.message = "evil\u{1b}[31mFAKE-PASS\u{1b}[0m".to_owned();
        f.file = Some("a\u{1b}]0;pwned\u{07}.yaml".to_owned());
        let out = render_terminal(&[report("skill", vec![f], FailOn::High)]);
        assert!(
            !out.contains('\u{07}'),
            "BEL from the filename must be neutralized"
        );
        assert!(
            out.contains('\u{fffd}'),
            "control chars replaced with U+FFFD"
        );
        let plain = crate::color::strip(&out);
        assert!(
            !plain.contains('\u{1b}'),
            "no injected escape survives:\n{plain:?}"
        );
        assert!(
            plain.contains("FAKE-PASS"),
            "printable message text is preserved"
        );
    }

    #[test]
    fn aggregate_count_agrees_across_formats() {
        let reports = [
            report("ok", Vec::new(), FailOn::High),
            report("bad", vec![fused_secret()], FailOn::High),
        ];
        assert!(render_terminal(&reports).contains("1 of 2 skill(s) failed"));
        assert!(render_markdown(&reports).contains("1 of 2 skill(s) failed"));
        let v: serde_json::Value = serde_json::from_str(&render_json(&reports)).unwrap();
        assert_eq!(v["summary"]["skills_failed"], 1);
        assert_eq!(v["summary"]["skills"], 2);
    }

    #[test]
    fn verdict_summary_agrees_across_formats() {
        let reports = [report("skill-a", vec![fused_secret()], FailOn::High)];
        let frag = "1 finding(s), 1 corroborated";
        assert!(render_terminal(&reports).contains(frag));
        assert!(render_markdown(&reports).contains(frag));
    }

    #[test]
    fn markdown_escapes_pipes_in_untrusted_cells() {
        let mut f = fused_secret();
        f.file = Some("we|ird.yaml".to_owned());
        f.message = "a | b".to_owned();
        let md = render_markdown(&[report("skill", vec![f], FailOn::High)]);
        let row = md
            .lines()
            .find(|l| l.starts_with("| ") && l.contains("ird.yaml"))
            .unwrap();
        assert!(
            row.contains("we\\|ird.yaml"),
            "filename pipe escaped: {row}"
        );
        assert!(
            !row.contains("we|ird.yaml"),
            "no raw pipe in the filename cell"
        );
        assert!(row.contains("a \\| b"), "message pipe escaped: {row}");
    }

    #[test]
    fn markdown_neutralizes_inline_injection_in_untrusted_cells() {
        let mut f = fused_secret();
        f.message = "see [click](http://evil) and <img src=http://attacker/?leak>".to_owned();
        f.file = Some("a`b.yaml".to_owned());
        let md = render_markdown(&[report("re[po]<x>#1", vec![f], FailOn::High)]);
        assert!(
            md.contains("`see [click](http://evil) and <img src=http://attacker/?leak>`"),
            "message not wrapped in a code span:\n{md}"
        );
        assert!(md.contains("a'b.yaml"), "backtick not neutralized:\n{md}");
        assert!(!md.contains("a`b.yaml"), "raw backtick survived:\n{md}");
        let heading = md.lines().find(|l| l.starts_with("## ")).unwrap();
        assert!(
            heading.contains("`re[po]<x>#1`"),
            "heading not wrapped: {heading}"
        );
    }

    #[test]
    fn markdown_does_not_autolink_bare_urls_in_untrusted_cells() {
        let mut f = fused_secret();
        f.message = "exfil to https://evil.example/?leak and www.evil.example".to_owned();
        let md = render_markdown(&[report("skill", vec![f], FailOn::High)]);
        assert!(
            md.contains("`exfil to https://evil.example/?leak and www.evil.example`"),
            "bare URL not wrapped in a code span (would autolink):\n{md}"
        );
    }

    #[test]
    fn counts_line_renders_all_four_severities_in_order() {
        let fused = vec![
            fused_at("c.yaml", 1, Severity::Critical),
            fused_at("h.yaml", 2, Severity::High),
            fused_at("m.yaml", 3, Severity::Medium),
            fused_at("l.yaml", 4, Severity::Low),
        ];
        let r = report("skill", fused, FailOn::High);
        let frag = "critical:1 high:1 medium:1 low:1";
        assert!(render_terminal(std::slice::from_ref(&r)).contains(frag));
        assert!(render_markdown(std::slice::from_ref(&r)).contains(frag));
    }

    #[test]
    fn sarif_dedupes_one_tool_across_skills_into_one_run() {
        let mk = |tool: &str, rule: &str| Finding {
            tool: tool.to_owned(),
            rule_id: rule.to_owned(),
            message: "m".to_owned(),
            severity: Severity::High,
            class: RuleClass::Secret,
            file: None,
            region: Region::default(),
        };
        let mut a = report("skill-a", Vec::new(), FailOn::High);
        a.raw = vec![mk("gitleaks", "g-a")];
        let mut b = report("skill-b", Vec::new(), FailOn::High);
        b.raw = vec![mk("gitleaks", "g-b"), mk("trivy", "t-b")];
        let v: serde_json::Value = serde_json::from_str(&render(&[a, b], Format::Sarif)).unwrap();
        let runs = v["runs"].as_array().unwrap();
        assert_eq!(
            runs.len(),
            2,
            "gitleaks across two skills → one run, plus trivy"
        );
        let gitleaks = runs
            .iter()
            .find(|r| r["tool"]["driver"]["name"] == "gitleaks")
            .unwrap();
        assert_eq!(gitleaks["results"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn sarif_format_aggregates_raw_across_skills() {
        let mk = |tool: &str, rule: &str| Finding {
            tool: tool.to_owned(),
            rule_id: rule.to_owned(),
            message: "m".to_owned(),
            severity: Severity::High,
            class: RuleClass::Secret,
            file: None,
            region: Region::default(),
        };
        let mut a = report("skill-a", Vec::new(), FailOn::High);
        a.raw = vec![mk("gitleaks", "g1")];
        let mut b = report("skill-b", Vec::new(), FailOn::High);
        b.raw = vec![mk("trivy", "t1")];
        let v: serde_json::Value = serde_json::from_str(&render(&[a, b], Format::Sarif)).unwrap();
        let runs = v["runs"].as_array().unwrap();
        assert_eq!(
            runs.len(),
            2,
            "one run per distinct tool across both skills"
        );
        let names: Vec<&str> = runs
            .iter()
            .map(|r| r["tool"]["driver"]["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"gitleaks") && names.contains(&"trivy"));
    }

    #[test]
    fn gate_trips_on_threshold_and_passes_on_none() {
        let bad = report("bad", vec![fused_secret()], FailOn::High);
        assert_eq!(
            gate(std::slice::from_ref(&bad), FailOn::High)
                .unwrap_err()
                .exit_code(),
            20
        );
        let none = report("bad", vec![fused_secret()], FailOn::None);
        assert!(gate(std::slice::from_ref(&none), FailOn::None).is_ok());
        let clean = report("ok", Vec::new(), FailOn::High);
        assert!(gate(std::slice::from_ref(&clean), FailOn::High).is_ok());
    }

    fn fused_at(file: &str, line: u32, sev: Severity) -> FusedFinding {
        let raw = vec![Finding {
            tool: "t".to_owned(),
            rule_id: "r".to_owned(),
            message: "m".to_owned(),
            severity: sev,
            class: RuleClass::Secret,
            file: Some(file.to_owned()),
            region: Region {
                start_line: Some(line),
                ..Region::default()
            },
        }];
        fuse(&raw).into_iter().next().unwrap()
    }

    #[test]
    fn gate_count_sums_findings_across_skills() {
        let many = report(
            "a",
            vec![
                fused_at("a.yaml", 1, Severity::Critical),
                fused_at("b.yaml", 2, Severity::High),
            ],
            FailOn::High,
        );
        let one = report(
            "b",
            vec![fused_at("c.yaml", 3, Severity::Critical)],
            FailOn::High,
        );
        let reports = [many, one];
        let err = gate(&reports, FailOn::High).unwrap_err();
        assert_eq!(err.exit_code(), 20);
        let count = match err {
            crate::error::SkillwardError::ThresholdExceeded { count, .. } => count,
            _ => 0,
        };
        assert_eq!(count, 3, "2 from skill a + 1 from skill b, summed");
    }

    #[test]
    fn json_carries_tool_errors() {
        let mut r = report("skill", Vec::new(), FailOn::High);
        r.tool_errors.push(ToolError {
            tool: "ramparts".to_owned(),
            detail: "timed out".to_owned(),
        });
        let v: serde_json::Value = serde_json::from_str(&render_json(&[r])).unwrap();
        let te = &v["results"][0]["tool_errors"][0];
        assert_eq!(te["tool"], "ramparts");
        assert_eq!(te["detail"], "timed out");
    }

    #[test]
    fn gate_passes_when_a_skill_is_clean_despite_tool_errors() {
        let mut r = report("degraded", Vec::new(), FailOn::High);
        r.tool_errors.push(ToolError {
            tool: "ramparts".to_owned(),
            detail: "timed out".to_owned(),
        });
        assert!(gate(std::slice::from_ref(&r), FailOn::High).is_ok());
        assert!(!any_failed(std::slice::from_ref(&r)));
    }

    #[test]
    fn location_renders_file_only_and_no_location_branches() {
        let mut file_only = fused_secret();
        file_only.region = Region::default();
        file_only.file = Some("repo-scoped.txt".to_owned());
        assert_eq!(location(&file_only), "repo-scoped.txt");

        let mut no_loc = fused_secret();
        no_loc.region = Region::default();
        no_loc.file = None;
        assert_eq!(location(&no_loc), "—");
    }

    #[test]
    fn target_name_control_chars_are_neutralized() {
        let evil = "repo\u{1b}[31m#sub\u{07}dir";
        let term = render_terminal(std::slice::from_ref(&report(
            evil,
            Vec::new(),
            FailOn::High,
        )));
        assert!(!term.contains('\u{07}'), "BEL in target neutralized");
        assert!(
            !crate::color::strip(&term).contains('\u{1b}'),
            "no injected escape survives from the target"
        );
        let md = render_markdown(std::slice::from_ref(&report(
            evil,
            Vec::new(),
            FailOn::High,
        )));
        assert!(!md.contains('\u{07}'));
        assert!(!md.contains('\u{1b}'));
    }

    #[test]
    fn write_to_file_strips_ansi_and_maps_io_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("r.txt");
        let painted = crate::color::paint(crate::color::ACCENT, "report-body");
        write_to_file(&path, &painted).unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(!written.contains('\u{1b}'), "a file report carries no ANSI");
        assert_eq!(written, "report-body");
        let err = write_to_file(&tmp.path().join("nope").join("r.txt"), "x").unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }
}
