//! CLI surface acceptance tests — the user-facing CLI contract.
//!
//! Pins the help surface, the color layer in both directions, the bad-flag and
//! unknown-tool usage errors, the no-panic guarantee, and the target exit codes
//! that need no Docker (missing path, refused offline remote). The end-to-end scan
//! pipeline is covered by the library `batch` tests with a stub scanner, since a
//! real scan needs the tool bundle.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use predicates::prelude::*;

mod common;
use common::skillward;

/// ANSI escape introducer — its presence means color was emitted.
const ESC: &str = "\u{1b}";

/// Excludes the eight non-skillspector tools, isolating skillspector for host-mode scans.
#[cfg(unix)]
const WITHOUT_THE_OTHER_EIGHT: &str =
    "cc-audit,aguara,cisco,agent-audit,ramparts,semgrep,trivy,gitleaks";

/// Fake `skillspector` on PATH so a host-mode scan runs end to end without the bundle.
#[cfg(unix)]
fn fake_skillspector(sarif: &str) -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let bin = tempfile::tempdir().unwrap();
    let script = format!(
        "#!/bin/sh\nout=\"\"\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = \"--output\" ]; then out=\"$2\"; fi\n  shift\ndone\n[ -n \"$out\" ] && printf '%s' '{sarif}' > \"$out\"\n"
    );
    let path = bin.path().join("skillspector");
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

#[test]
fn help_lists_every_flag_and_subcommand_and_exits_zero() {
    skillward()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--fail-on"))
        .stdout(predicate::str::contains("--format"))
        .stdout(predicate::str::contains("--without"))
        .stdout(predicate::str::contains("--with"))
        .stdout(predicate::str::contains("--sandbox"))
        .stdout(predicate::str::contains("--offline"))
        .stdout(predicate::str::contains("--no-color"))
        .stdout(predicate::str::contains("--jobs"))
        .stdout(predicate::str::contains("install"))
        .stdout(predicate::str::contains("update"))
        .stdout(predicate::str::contains("skills"))
        .stdout(predicate::str::contains("Agents:"))
        .stdout(predicate::str::contains(
            "npx skills add coroboros/skillward",
        ));
}

#[test]
fn version_exits_zero() {
    skillward()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn no_targets_exits_usage_error() {
    skillward()
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("no targets"));
}

#[test]
fn bad_flag_is_a_clap_usage_error() {
    skillward()
        .args(["--definitely-not-a-flag", "./x"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn unknown_tool_lists_valid_tools_and_exits_two() {
    skillward()
        .args(["--without", "bogus", "./x"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("gitleaks"));
}

#[test]
fn excluding_every_tool_is_a_usage_error() {
    // Emptying the ensemble is an exit-2 branch checked before target resolution — no Docker.
    skillward()
        .args([
            "--sandbox",
            "host",
            "--without",
            "skillspector,cc-audit,aguara,cisco,agent-audit,ramparts,semgrep,trivy,gitleaks",
            "./x",
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("no scanners selected"));
}

#[test]
fn missing_local_target_exits_ten() {
    // `--sandbox host` skips the Docker check so target resolution is what runs.
    skillward()
        .args(["--sandbox", "host", "definitely-not-a-real-path.xyz"])
        .assert()
        .failure()
        .code(10)
        .stderr(predicate::str::contains("no such target"))
        .stderr(predicate::str::contains("panicked").not());
}

#[test]
fn offline_remote_is_refused_with_exit_eleven() {
    // No network touched: the offline guard refuses before any clone is attempted.
    skillward()
        .args(["--offline", "--sandbox", "host", "https://github.com/o/r"])
        .assert()
        .failure()
        .code(11)
        .stderr(predicate::str::contains("offline"));
}

#[test]
fn host_scan_with_uninstalled_scanner_exits_engine_failure() {
    // Exercises scan() orchestration past the usage/target checks, without Docker.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("SKILL.md"), b"# skill\n").unwrap();
    skillward()
        .args([
            "--sandbox",
            "host",
            "--without",
            "cc-audit,aguara,cisco,agent-audit,ramparts,semgrep,trivy,gitleaks",
        ])
        .arg(dir.path())
        .assert()
        .failure()
        .code(12)
        .stderr(predicate::str::contains("scan engine failed"));
}

#[cfg(unix)]
#[test]
fn output_flag_writes_report_to_file_and_keeps_stdout_clean() {
    use std::os::unix::fs::PermissionsExt;
    // A fake clean scanner exercises the --output write path end to end without the bundle.
    let bin = tempfile::tempdir().unwrap();
    let fake = bin.path().join("skillspector");
    let script = r#"#!/bin/sh
out=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--output" ]; then out="$2"; fi
  shift
done
[ -n "$out" ] && printf '{"runs":[]}' > "$out"
"#;
    std::fs::write(&fake, script).unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

    let skill = tempfile::tempdir().unwrap();
    std::fs::write(skill.path().join("SKILL.md"), b"# skill\n").unwrap();
    let report = bin.path().join("report.json");

    let path = std::env::var("PATH").unwrap_or_default();
    skillward()
        .env("PATH", format!("{}:{}", bin.path().display(), path))
        .args([
            "--sandbox",
            "host",
            "--without",
            "cc-audit,aguara,cisco,agent-audit,ramparts,semgrep,trivy,gitleaks",
            "--format",
            "json",
            "-o",
        ])
        .arg(&report)
        .arg(skill.path())
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("report:"));

    let written = std::fs::read_to_string(&report).unwrap();
    assert!(!written.contains(ESC), "a file report carries no ANSI");
    assert!(
        written.contains("schema_version"),
        "the JSON report was written"
    );
}

#[cfg(unix)]
#[test]
fn host_scan_refuses_escaping_symlink() {
    // Host mode has no container to contain a root-escaping symlink, so it must be refused.
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("SKILL.md"), b"# skill\n").unwrap();
    symlink("/etc/passwd", dir.path().join("link")).unwrap();
    skillward()
        .args(["--sandbox", "host"])
        .arg(dir.path())
        .assert()
        .failure()
        .code(14)
        .stderr(predicate::str::contains("symlink(s) escape the skill root"))
        .stderr(predicate::str::contains("panicked").not());
}

// ── color layer, exercised via the always-printed error line ────────────────────

#[test]
fn piped_stderr_has_no_ansi() {
    // assert_cmd pipes (never a TTY), so a bare run strips color like a real pipe.
    skillward()
        .assert()
        .failure()
        .stderr(predicate::str::contains(ESC).not());
}

#[test]
fn no_color_env_strips_ansi() {
    skillward()
        .env("NO_COLOR", "1")
        .assert()
        .failure()
        .stderr(predicate::str::contains(ESC).not());
}

#[test]
fn no_color_flag_strips_ansi() {
    skillward()
        .arg("--no-color")
        .assert()
        .failure()
        .stderr(predicate::str::contains(ESC).not());
}

#[test]
fn clicolor_force_emits_ansi() {
    // CLICOLOR_FORCE=1 stands in for a color-capable terminal.
    skillward()
        .env("CLICOLOR_FORCE", "1")
        .assert()
        .failure()
        .stderr(predicate::str::contains(ESC));
}

// ── bundled agent skill ─────────────────────────────────────────────────────────

#[test]
fn skills_list_shows_the_bundled_skill() {
    skillward()
        .args(["skills", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("skillward"))
        .stdout(predicate::str::contains(
            "npx skills add coroboros/skillward",
        ))
        // Piped (no TTY), so the styled list strips ANSI like a real pipe.
        .stdout(predicate::str::contains(ESC).not());
}

#[test]
fn skills_get_prints_the_skill_markdown_verbatim() {
    // Emitted unstyled (no ANSI) so an agent can pipe the embedded SKILL.md verbatim.
    skillward()
        .args(["skills", "get", "skillward"])
        .assert()
        .success()
        .stdout(predicate::str::contains("name: skillward"))
        .stdout(predicate::str::contains("## Install"))
        .stdout(predicate::str::contains(ESC).not());
}

#[test]
fn skills_get_defaults_to_skillward() {
    skillward()
        .args(["skills", "get"])
        .assert()
        .success()
        .stdout(predicate::str::contains("name: skillward"));
}

#[test]
fn skills_get_unknown_name_exits_usage_error() {
    skillward()
        .args(["skills", "get", "bogus"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("unknown skill `bogus`"))
        .stderr(predicate::str::contains("skillward"));
}

// ── end-to-end scan, host mode with a fake scanner ──────────────────────────────

#[cfg(unix)]
#[test]
fn a_finding_at_threshold_exits_20_and_writes_the_report_first() {
    // main writes the report before it gates; inverting that order would lose the CI artifact on failing runs.
    let sarif = r#"{"runs":[{"tool":{"driver":{"name":"skillspector"}},"results":[{"ruleId":"hardcoded-secret","level":"error","message":{"text":"token"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"s.yaml"},"region":{"startLine":1}}}]}]}]}"#;
    let bin = fake_skillspector(sarif);
    let skill = tempfile::tempdir().unwrap();
    std::fs::write(skill.path().join("SKILL.md"), b"# skill\n").unwrap();
    let report = bin.path().join("report.json");
    let path = std::env::var("PATH").unwrap_or_default();
    skillward()
        .env("PATH", format!("{}:{}", bin.path().display(), path))
        .args([
            "--sandbox",
            "host",
            "--without",
            WITHOUT_THE_OTHER_EIGHT,
            "--format",
            "json",
            "-o",
        ])
        .arg(&report)
        .arg(skill.path())
        .assert()
        .failure()
        .code(20)
        .stderr(predicate::str::contains("--fail-on"));
    let written = std::fs::read_to_string(&report).unwrap();
    assert!(
        written.contains("\"failed\": true"),
        "the report must be written before the gate trips:\n{written}"
    );
}

#[cfg(unix)]
#[test]
fn markdown_and_sarif_formats_wire_through_the_binary() {
    // Pin the markdown and sarif render arms reachable through the binary, not just unit tests.
    let bin = fake_skillspector(r#"{"runs":[]}"#);
    let skill = tempfile::tempdir().unwrap();
    std::fs::write(skill.path().join("SKILL.md"), b"# skill\n").unwrap();
    let path = std::env::var("PATH").unwrap_or_default();
    for (fmt, token) in [("markdown", "# skillward report"), ("sarif", "2.1.0")] {
        let report = bin.path().join(format!("report-{fmt}"));
        skillward()
            .env("PATH", format!("{}:{}", bin.path().display(), path))
            .args([
                "--sandbox",
                "host",
                "--without",
                WITHOUT_THE_OTHER_EIGHT,
                "--format",
                fmt,
                "-o",
            ])
            .arg(&report)
            .arg(skill.path())
            .assert()
            .success();
        let written = std::fs::read_to_string(&report).unwrap();
        assert!(
            written.contains(token),
            "{fmt} report missing {token:?}:\n{written}"
        );
    }
}

#[cfg(unix)]
#[test]
fn with_re_adds_a_tool_excluded_by_without() {
    // Pin that `--with` re-adds the tool, via the resolved `tools=` banner on stderr.
    let bin = fake_skillspector(r#"{"runs":[]}"#);
    let skill = tempfile::tempdir().unwrap();
    std::fs::write(skill.path().join("SKILL.md"), b"# skill\n").unwrap();
    let path = std::env::var("PATH").unwrap_or_default();
    skillward()
        .env("PATH", format!("{}:{}", bin.path().display(), path))
        .args([
            "--sandbox",
            "host",
            "--without",
            WITHOUT_THE_OTHER_EIGHT,
            "--without",
            "skillspector",
            "--with",
            "skillspector",
        ])
        .arg(skill.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("tools=skillspector"));
}

#[cfg(unix)]
#[test]
fn fail_on_boundary_crosses_the_binary_for_a_sub_critical_finding() {
    // The inclusive `--fail-on` boundary through the binary: Medium FAILs medium, PASSes critical.
    let sarif = r#"{"runs":[{"tool":{"driver":{"name":"skillspector"}},"results":[{"ruleId":"insecure-default","level":"warning","message":{"text":"insecure default"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"s.yaml"},"region":{"startLine":1}}}]}]}]}"#;
    let bin = fake_skillspector(sarif);
    let skill = tempfile::tempdir().unwrap();
    std::fs::write(skill.path().join("SKILL.md"), b"# skill\n").unwrap();
    let path = std::env::var("PATH").unwrap_or_default();
    let run = |fail_on: &str| {
        skillward()
            .env("PATH", format!("{}:{}", bin.path().display(), path))
            .args([
                "--sandbox",
                "host",
                "--without",
                WITHOUT_THE_OTHER_EIGHT,
                "--fail-on",
                fail_on,
            ])
            .arg(skill.path())
            .assert()
    };
    run("medium").failure().code(20);
    run("critical").success();
}

#[cfg(unix)]
#[test]
fn fail_on_none_reports_without_gating() {
    // `--fail-on none` reports a real finding but never gates: exit 0, report still written.
    let sarif = r#"{"runs":[{"tool":{"driver":{"name":"skillspector"}},"results":[{"ruleId":"hardcoded-secret","level":"error","message":{"text":"token"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"s.yaml"},"region":{"startLine":1}}}]}]}]}"#;
    let bin = fake_skillspector(sarif);
    let skill = tempfile::tempdir().unwrap();
    std::fs::write(skill.path().join("SKILL.md"), b"# skill\n").unwrap();
    let report = bin.path().join("report.json");
    let path = std::env::var("PATH").unwrap_or_default();
    skillward()
        .env("PATH", format!("{}:{}", bin.path().display(), path))
        .args([
            "--sandbox",
            "host",
            "--without",
            WITHOUT_THE_OTHER_EIGHT,
            "--fail-on",
            "none",
            "--format",
            "json",
            "-o",
        ])
        .arg(&report)
        .arg(skill.path())
        .assert()
        .success();
    let written = std::fs::read_to_string(&report).unwrap();
    assert!(
        written.contains("\"failed\": false"),
        "report-only must not flag failed:\n{written}"
    );
}
