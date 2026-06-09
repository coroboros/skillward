//! The scanner adapter layer: one adapter per bundled tool, each knowing the
//! tool's deterministic-mode invocation and writing SARIF that the generic reader
//! normalizes. The default ensemble is the complete maintained deterministic set;
//! `--without` trims it; `--with` re-adds a tool excluded by `--without`.
//!
//! Per-tool isolation is the rule: a missing, crashed, timed-out, or
//! unparseable-output scanner becomes a [`ToolError`] recorded on the report. It
//! never aborts the run — completeness means the other eight still finish.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::cli::{Sandbox, ToolId};
use crate::finding::{Finding, ToolError};
use crate::sandbox::{self, Output, Plan};
use crate::sarif;

/// One scanner adapter. `Send + Sync` so the batch can run adapters across skills
/// in parallel behind shared references.
pub trait Scanner: Send + Sync {
    /// The tool's id, matching its `ToolId` value name and SARIF source stamp.
    fn id(&self) -> &'static str;
    /// The commands to run. Most adapters return one; a few (aguara) return several
    /// — every command's findings are stamped with this adapter's id.
    fn commands(&self, scan: &str, out: &str) -> Vec<Plan>;
}

/// The complete default ensemble — every maintained deterministic scanner that
/// adds a unique detection axis. cisco is included: its license is Apache-2.0,
/// which permits redistribution in the bundle.
pub const DEFAULT_TOOLS: [ToolId; 9] = [
    ToolId::Skillspector,
    ToolId::CcAudit,
    ToolId::Aguara,
    ToolId::Cisco,
    ToolId::AgentAudit,
    ToolId::Ramparts,
    ToolId::Semgrep,
    ToolId::Trivy,
    ToolId::Gitleaks,
];

/// Resolve the active tool set: the default ensemble minus `--without`, plus any
/// `--with` not already present, preserving the default order then appended extras.
pub fn resolve(without: &[ToolId], with: &[ToolId]) -> Vec<ToolId> {
    let mut set: Vec<ToolId> = DEFAULT_TOOLS
        .into_iter()
        .filter(|t| !without.contains(t))
        .collect();
    for tool in with {
        if !set.contains(tool) {
            set.push(*tool);
        }
    }
    set
}

/// The adapters for a resolved tool set.
pub fn selected(without: &[ToolId], with: &[ToolId]) -> Vec<Box<dyn Scanner>> {
    resolve(without, with).into_iter().map(build).collect()
}

/// Build the adapter for a tool.
pub fn build(tool: ToolId) -> Box<dyn Scanner> {
    match tool {
        ToolId::Skillspector => Box::new(SkillSpector),
        ToolId::CcAudit => Box::new(CcAudit),
        ToolId::Aguara => Box::new(Aguara),
        ToolId::Cisco => Box::new(Cisco),
        ToolId::AgentAudit => Box::new(AgentAudit),
        ToolId::Ramparts => Box::new(Ramparts),
        ToolId::Semgrep => Box::new(Semgrep),
        ToolId::Trivy => Box::new(Trivy),
        ToolId::Gitleaks => Box::new(Gitleaks),
    }
}

/// Build an argv from string parts.
fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(ToString::to_string).collect()
}

/// A SARIF output path under the chosen out dir.
fn out_file(out: &str, name: &str) -> String {
    format!("{out}/{name}")
}

/// Run one scanner over `target` and return its normalized findings, or a
/// [`ToolError`] if it could not contribute. In Docker mode determinism is enforced by
/// the sandbox (`--network=none`, no API keys in the image), so a hybrid tool's
/// optional LLM/CVE stage cannot activate regardless of its flags; `--sandbox host`
/// trades that isolation for a local install, relying on each adapter's
/// deterministic-mode flags and the absence of API keys in the host environment.
/// One scanner's result: its findings (possibly empty) and a tool-error if any plan
/// degraded. A multi-plan adapter can carry BOTH — findings from a plan that ran plus an
/// error from a sibling plan that hard-failed — so a partial run is never silent.
pub struct ScanOutcome {
    pub findings: Vec<Finding>,
    pub error: Option<ToolError>,
}

/// Run one scanner over `target`, capturing its findings and any partial-plan error.
pub fn scan_one(
    scanner: &dyn Scanner,
    mode: Sandbox,
    image: &str,
    target: &Path,
    timeout: Duration,
) -> ScanOutcome {
    match scan_one_inner(scanner, mode, image, target, timeout) {
        Ok(outcome) => outcome,
        // A setup failure (no out dir, unresolvable path) is a tool-error with no findings.
        Err(error) => ScanOutcome {
            findings: Vec::new(),
            error: Some(error),
        },
    }
}

fn scan_one_inner(
    scanner: &dyn Scanner,
    mode: Sandbox,
    image: &str,
    target: &Path,
    timeout: Duration,
) -> Result<ScanOutcome, ToolError> {
    let terr = |detail: String| ToolError {
        tool: scanner.id().to_owned(),
        detail,
    };
    // One source for the per-tool-deadline message, used by both timeout arms below.
    let timed_out = || format!("timed out after {}s", timeout.as_secs());

    // `_out_guard` holds the private 0700 parent alive for the whole scan; `out_dir`
    // is the world-writable dir nested inside it that the container writes into.
    let (_out_guard, out_dir) = sandbox::out_dir().map_err(|e| terr(e.to_string()))?;

    let target_abs = target
        .canonicalize()
        .map_err(|e| terr(format!("cannot resolve target path: {e}")))?;

    // In Docker mode both paths become `--mount` sources; refuse one that would
    // corrupt the spec rather than risk mounting the wrong host path.
    if mode == Sandbox::Docker {
        sandbox::mountable(&target_abs).map_err(&terr)?;
        sandbox::mountable(&out_dir).map_err(&terr)?;
    }

    let (scan_s, out_s) = match mode {
        Sandbox::Docker => (
            sandbox::SCAN_MOUNT.to_owned(),
            sandbox::OUT_MOUNT.to_owned(),
        ),
        Sandbox::Host => (
            target_abs.display().to_string(),
            out_dir.display().to_string(),
        ),
    };

    let plans = scanner.commands(&scan_s, &out_s);
    let mut findings = Vec::new();
    let mut last_err: Option<String> = None;
    let mut produced = false;

    // `timeout` is the per-TOOL ceiling, not per-plan: a multi-plan adapter (aguara)
    // shares one budget across its plans, so a hung tool can't run N× the ceiling.
    let deadline = Instant::now() + timeout;

    for plan in &plans {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            last_err = Some(timed_out());
            continue;
        }
        // In Docker mode the container is named so a timeout can reap it; SIGKILL to the
        // `docker run` client does not stop the daemon-owned container on its own.
        let container = match mode {
            Sandbox::Docker => Some(sandbox::container_name()),
            Sandbox::Host => None,
        };
        let (program, args) = match (mode, &container) {
            (Sandbox::Docker, Some(name)) => (
                "docker".to_owned(),
                sandbox::docker_argv(plan, &target_abs, &out_dir, image, name),
            ),
            _ => (plan.program.clone(), plan.args.clone()),
        };

        match sandbox::execute(&program, &args, remaining) {
            Ok(exec) => {
                if exec.timed_out {
                    if let Some(name) = &container {
                        sandbox::docker_rm(name);
                    }
                    last_err = Some(timed_out());
                    continue;
                }
                let report = match &plan.output {
                    Output::Stdout => exec.stdout.clone(),
                    Output::File(name) => {
                        let path = out_dir.join(name);
                        // Refuse a non-regular report: the out dir is world-writable to the
                        // container's foreign uid, so a misbehaving bundle could write the
                        // fixed report name as a symlink escaping the dir. A read error
                        // surfaces as the tool-error cause, never a silent empty.
                        match std::fs::symlink_metadata(&path) {
                            Ok(meta) if meta.is_file() => match std::fs::read_to_string(&path) {
                                Ok(s) => s,
                                Err(e) => {
                                    last_err = Some(format!("could not read report {name}: {e}"));
                                    continue;
                                }
                            },
                            Ok(_) => {
                                last_err = Some(format!("report {name} is not a regular file"));
                                continue;
                            }
                            Err(_) => String::new(),
                        }
                    }
                };
                if report.trim().is_empty() {
                    last_err = Some(format!("no report produced ({})", exec.stderr_tail()));
                    continue;
                }
                match sarif::parse(scanner.id(), &report, &scan_s) {
                    // A clean scan is a valid empty result — `produced` flips true so
                    // it is reported as PASS, never as a tool-error.
                    Ok(mut parsed) => {
                        produced = true;
                        findings.append(&mut parsed);
                    }
                    Err(e) => last_err = Some(format!("unparseable report: {e}")),
                }
            }
            Err(e) => last_err = Some(e),
        }
    }

    // Carry findings AND a partial error together: a later plan failing after real
    // findings still records a tool-error, so a degraded multi-plan run is never silent.
    let error = if findings.is_empty() && !produced && last_err.is_none() {
        Some(terr("produced no usable output".to_owned()))
    } else {
        last_err.map(terr)
    };
    Ok(ScanOutcome { findings, error })
}

// ── Adapters ──────────────────────────────────────────────────────────────────
// Each adapter's argv runs the tool in its deterministic, offline-capable mode and
// writes SARIF to a file (or stdout for ramparts). A change here must land in the
// bundle repo's `smoke-test.sh` too, or the image and the orchestrator drift.

/// NVIDIA SkillSpector — deepest SKILL.md taint→exec. `--no-llm` is static-only;
/// its lone OSV call is severed by `--network=none`.
struct SkillSpector;
impl Scanner for SkillSpector {
    fn id(&self) -> &'static str {
        "skillspector"
    }
    fn commands(&self, scan: &str, out: &str) -> Vec<Plan> {
        let report = "skillspector.sarif";
        vec![Plan {
            program: "skillspector".to_owned(),
            args: argv(&[
                "scan",
                scan,
                "--no-llm",
                "--format",
                "sarif",
                "--output",
                &out_file(out, report),
            ]),
            output: Output::File(report.to_owned()),
        }]
    }
}

/// cc-audit — AI-free Claude Skills/Hooks/MCP auditor (Rust).
struct CcAudit;
impl Scanner for CcAudit {
    fn id(&self) -> &'static str {
        "cc-audit"
    }
    fn commands(&self, scan: &str, out: &str) -> Vec<Plan> {
        let report = "cc-audit.sarif";
        vec![Plan {
            program: "cc-audit".to_owned(),
            args: argv(&[
                "check",
                scan,
                "--format",
                "sarif",
                "--output",
                &out_file(out, report),
            ]),
            output: Output::File(report.to_owned()),
        }]
    }
}

/// aguara — local-first supply-chain + agent content. Two passes: `scan` (agent
/// content + MCP) and `check` (lockfiles, embedded threat-intel). Both offline.
struct Aguara;
impl Scanner for Aguara {
    fn id(&self) -> &'static str {
        "aguara"
    }
    fn commands(&self, scan: &str, out: &str) -> Vec<Plan> {
        let scan_report = "aguara-scan.sarif";
        let check_report = "aguara-check.sarif";
        vec![
            Plan {
                program: "aguara".to_owned(),
                args: argv(&[
                    "scan",
                    scan,
                    "--format",
                    "sarif",
                    "-o",
                    &out_file(out, scan_report),
                ]),
                output: Output::File(scan_report.to_owned()),
            },
            Plan {
                program: "aguara".to_owned(),
                args: argv(&[
                    "check",
                    scan,
                    "--format",
                    "sarif",
                    "-o",
                    &out_file(out, check_report),
                ]),
                output: Output::File(check_report.to_owned()),
            },
        ]
    }
}

/// Cisco skill-scanner — multi-engine static (YAML + YARA + bytecode + pipeline
/// taint). Static analyzers run with no keys; LLM/VirusTotal layers stay opt-in off.
struct Cisco;
impl Scanner for Cisco {
    fn id(&self) -> &'static str {
        "cisco"
    }
    fn commands(&self, scan: &str, out: &str) -> Vec<Plan> {
        let report = "cisco.sarif";
        vec![Plan {
            program: "skill-scanner".to_owned(),
            args: argv(&[
                "scan",
                scan,
                "--format",
                "sarif",
                "--output",
                &out_file(out, report),
            ]),
            output: Output::File(report.to_owned()),
        }]
    }
}

/// agent-audit — OWASP Agentic Top 10, tool-boundary taint (Python).
struct AgentAudit;
impl Scanner for AgentAudit {
    fn id(&self) -> &'static str {
        "agent-audit"
    }
    fn commands(&self, scan: &str, out: &str) -> Vec<Plan> {
        let report = "agent-audit.sarif";
        vec![Plan {
            program: "agent-audit".to_owned(),
            args: argv(&[
                "scan",
                scan,
                "--format",
                "sarif",
                "--output",
                &out_file(out, report),
            ]),
            output: Output::File(report.to_owned()),
        }]
    }
}

/// ramparts — MCP + agent skills (Rust). Pure-static with no LLM key set (the
/// sandbox guarantees none); reports to stdout (no `--output` flag).
struct Ramparts;
impl Scanner for Ramparts {
    fn id(&self) -> &'static str {
        "ramparts"
    }
    fn commands(&self, scan: &str, _out: &str) -> Vec<Plan> {
        vec![Plan {
            program: "ramparts".to_owned(),
            args: argv(&["skills", "scan", scan, "--format", "sarif"]),
            output: Output::Stdout,
        }]
    }
}

/// semgrep — AST/dataflow with the OWASP-LLM ruleset, vendored at `/rules/llm-security`
/// in the image (the registry is unreachable under `--network=none`). Metrics and
/// version checks off so no call leaves the box.
struct Semgrep;
impl Scanner for Semgrep {
    fn id(&self) -> &'static str {
        "semgrep"
    }
    fn commands(&self, scan: &str, out: &str) -> Vec<Plan> {
        let report = "semgrep.sarif";
        vec![Plan {
            program: "semgrep".to_owned(),
            args: argv(&[
                "--config",
                "/rules/llm-security",
                "--sarif",
                "--output",
                &out_file(out, report),
                "--metrics=off",
                "--disable-version-check",
                scan,
            ]),
            output: Output::File(report.to_owned()),
        }]
    }
}

/// trivy — SCA + misconfig + secrets, DB baked at `/opt/trivy-cache`. `--offline-scan`,
/// `--skip-db-update`, and `--skip-check-update` keep it from reaching the network — the
/// last so misconfig uses trivy's embedded checks instead of fetching the rego bundle.
struct Trivy;
impl Scanner for Trivy {
    fn id(&self) -> &'static str {
        "trivy"
    }
    fn commands(&self, scan: &str, out: &str) -> Vec<Plan> {
        let report = "trivy.sarif";
        vec![Plan {
            program: "trivy".to_owned(),
            args: argv(&[
                "fs",
                scan,
                "--scanners",
                "vuln,misconfig,secret",
                "--skip-db-update",
                "--skip-check-update",
                "--offline-scan",
                "--cache-dir",
                "/opt/trivy-cache",
                "--format",
                "sarif",
                "--output",
                &out_file(out, report),
            ]),
            output: Output::File(report.to_owned()),
        }]
    }
}

/// gitleaks — offline secret detection over the directory tree.
struct Gitleaks;
impl Scanner for Gitleaks {
    fn id(&self) -> &'static str {
        "gitleaks"
    }
    fn commands(&self, scan: &str, out: &str) -> Vec<Plan> {
        let report = "gitleaks.sarif";
        vec![Plan {
            program: "gitleaks".to_owned(),
            args: argv(&[
                "dir",
                scan,
                "--report-format",
                "sarif",
                "--report-path",
                &out_file(out, report),
                "--no-banner",
                "--exit-code",
                "0",
            ]),
            output: Output::File(report.to_owned()),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::ValueEnum;

    #[test]
    fn default_set_is_the_complete_nine() {
        assert_eq!(DEFAULT_TOOLS.len(), 9);
        // A new ToolId must be a deliberate add to DEFAULT_TOOLS, never a silent omission.
        assert_eq!(DEFAULT_TOOLS.len(), ToolId::value_variants().len());
        assert!(
            DEFAULT_TOOLS.contains(&ToolId::Cisco),
            "cisco is Apache-2.0 → default"
        );
    }

    #[test]
    fn resolve_preserves_default_order() {
        assert_eq!(resolve(&[], &[]), DEFAULT_TOOLS.to_vec());
    }

    #[test]
    fn resolve_trims_without_and_appends_with() {
        let set = resolve(&[ToolId::Cisco, ToolId::Semgrep], &[]);
        assert_eq!(set.len(), 7);
        assert!(!set.contains(&ToolId::Cisco));
        let restored = resolve(&[ToolId::Cisco], &[ToolId::Cisco]);
        assert!(restored.contains(&ToolId::Cisco));
        assert_eq!(restored.iter().filter(|t| **t == ToolId::Cisco).count(), 1);
    }

    #[test]
    fn every_tool_has_an_adapter_with_a_matching_id() {
        // Iterate the enum's variants, not DEFAULT_TOOLS, so an opt-in tool is still checked.
        for tool in ToolId::value_variants() {
            let adapter = build(*tool);
            assert_eq!(adapter.id(), tool.to_string());
            assert!(!adapter.commands("/scan", "/out").is_empty());
        }
    }

    #[test]
    fn semgrep_runs_offline_with_vendored_rules() {
        let plan = &Semgrep.commands("/scan", "/out")[0];
        let joined = plan.args.join(" ");
        assert!(
            joined.contains("/rules/llm-security"),
            "vendored ruleset path"
        );
        assert!(joined.contains("--metrics=off"));
        assert!(joined.contains("--disable-version-check"));
    }

    #[test]
    fn trivy_runs_against_the_baked_db_offline() {
        let plan = &Trivy.commands("/scan", "/out")[0];
        let joined = plan.args.join(" ");
        assert!(joined.contains("--skip-db-update"));
        assert!(joined.contains("--skip-check-update"));
        assert!(joined.contains("--offline-scan"));
        assert!(joined.contains("/opt/trivy-cache"));
    }

    #[test]
    fn ramparts_reports_to_stdout() {
        let plan = &Ramparts.commands("/scan", "/out")[0];
        assert_eq!(plan.output, Output::Stdout);
        assert!(plan.args.join(" ").contains("skills scan"));
    }

    #[test]
    fn aguara_runs_two_passes() {
        let plans = Aguara.commands("/scan", "/out");
        assert_eq!(plans.len(), 2);
        assert!(plans.iter().any(|p| p.args.contains(&"scan".to_owned())));
        assert!(plans.iter().any(|p| p.args.contains(&"check".to_owned())));
    }

    #[test]
    fn skillspector_disables_the_llm_stage() {
        let plan = &SkillSpector.commands("/scan", "/out")[0];
        assert!(plan.args.contains(&"--no-llm".to_owned()));
    }
}
