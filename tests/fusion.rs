//! Coverage-completeness proof at the fusion layer.
//!
//! The bundle's real-tool completeness is proven by the bundle repo's `smoke-test.sh`
//! (`coroboros/security/infrastructure/skillward-bundle`) against
//! the malicious fixture (out of band, needs the image). Here we prove the other
//! half with no Docker: given each tool's SARIF for that same fixture, fusion must
//! surface every planted threat class, corroborate the sites multiple tools agree
//! on, and a clean corpus must pass with nothing surviving dedup.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use skillward::finding::{FailOn, Finding, RuleClass, Severity};
use skillward::fusion::{Verdict, fuse};
use skillward::sarif;

fn load(tool: &str, fixture: &str) -> Vec<Finding> {
    let path = format!(
        "{}/tests/fixtures/sarif/{fixture}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).expect("fixture readable");
    // Fixtures report against the `/scan` Docker mount, as a real bundle scan does.
    sarif::parse(tool, &text, "/scan").expect("fixture is valid SARIF")
}

#[test]
fn malicious_corpus_is_fully_caught_and_corroborated() {
    let mut all = Vec::new();
    // All nine default tools contribute, so every adapter id is exercised end to end.
    for (tool, fixture) in [
        ("gitleaks", "gitleaks.sarif"),
        ("trivy", "trivy.sarif"),
        ("skillspector", "skillspector.sarif"),
        ("semgrep", "semgrep.sarif"),
        ("agent-audit", "agent-audit.sarif"),
        ("aguara", "aguara.sarif"),
        ("cc-audit", "cc-audit.sarif"),
        ("cisco", "cisco.sarif"),
        ("ramparts", "ramparts.sarif"),
    ] {
        all.extend(load(tool, fixture));
    }

    let fused = fuse(&all);

    // Every planted threat class must appear in the fused report — zero misses.
    for class in [
        RuleClass::Secret,
        RuleClass::Injection,
        RuleClass::TaintExec,
        RuleClass::VulnerableDep,
        RuleClass::OverPermission,
        RuleClass::UnsafeAction,
        RuleClass::MalwareSig,
    ] {
        assert!(
            fused.iter().any(|f| f.class == class),
            "fusion missed the {class} axis"
        );
    }

    // Same secret from gitleaks + trivy → one finding, two sources, raised to Critical by score.
    let secret = fused
        .iter()
        .find(|f| f.class == RuleClass::Secret)
        .expect("secret present");
    assert_eq!(secret.severity, Severity::Critical);
    assert!(secret.corroborated(), "secret should cite gitleaks + trivy");
    assert!(secret.tool_count() >= 2);

    let taint = fused
        .iter()
        .find(|f| f.class == RuleClass::TaintExec)
        .expect("taint-exec present");
    assert!(taint.corroborated(), "taint-exec should cite two tools");

    let overperm = fused
        .iter()
        .find(|f| f.class == RuleClass::OverPermission)
        .expect("over-permission present");
    assert!(
        overperm.corroborated(),
        "over-permission should cite agent-audit + cc-audit"
    );

    let injection = fused
        .iter()
        .find(|f| f.class == RuleClass::Injection)
        .expect("injection present");
    assert!(
        injection.corroborated(),
        "injection should cite skillspector + ramparts"
    );

    // Exact count (not `>= 2`) so a regression splitting any of the four axes fails loudly.
    let verdict = Verdict::compute(&fused, FailOn::High);
    assert!(verdict.failed);
    assert_eq!(verdict.worst, Some(Severity::Critical));
    assert_eq!(
        verdict.corroborated, 4,
        "secret + taint + over-permission + injection each corroborate"
    );

    // Overlapping rows dedup, so the fused count drops below the raw count.
    assert!(fused.len() < all.len(), "overlapping findings must dedup");
}

#[test]
fn malicious_corpus_report_is_byte_identical_under_reordering() {
    // Determinism through the real parse→classify→fuse pipeline: reversing input must not change a byte.
    let fixtures = [
        ("gitleaks", "gitleaks.sarif"),
        ("trivy", "trivy.sarif"),
        ("skillspector", "skillspector.sarif"),
        ("semgrep", "semgrep.sarif"),
        ("agent-audit", "agent-audit.sarif"),
        ("aguara", "aguara.sarif"),
        ("cc-audit", "cc-audit.sarif"),
        ("cisco", "cisco.sarif"),
        ("ramparts", "ramparts.sarif"),
    ];
    let mut forward = Vec::new();
    for (tool, fixture) in fixtures {
        forward.extend(load(tool, fixture));
    }
    let mut backward = forward.clone();
    backward.reverse();

    let a = serde_json::to_string(&fuse(&forward)).expect("serialize forward");
    let b = serde_json::to_string(&fuse(&backward)).expect("serialize reversed");
    assert_eq!(a, b, "the fused report depends on input order");
}

#[test]
fn clean_corpus_passes_with_no_surviving_findings() {
    let findings = load("gitleaks", "clean.sarif");
    let fused = fuse(&findings);
    assert!(fused.is_empty());
    let verdict = Verdict::compute(&fused, FailOn::Low);
    assert!(!verdict.failed);
    assert_eq!(verdict.label(), "PASS");
}
