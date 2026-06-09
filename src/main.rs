//! skillward entry point: parse the CLI, set up color, dispatch, and translate any
//! failure into its stable exit code.

use clap::Parser;

use skillward::batch::{self, ScanConfig};
use skillward::cli::{Cli, Command, Sandbox, SkillsAction};
use skillward::error::SkillwardError;
use skillward::sandbox::DEFAULT_TIMEOUT;
use skillward::scanners::Scanner;
use skillward::{bundle, color, remote, report, scanners, skills, target};

/// Exit code for argument/usage problems, matching clap's own convention.
const USAGE_ERROR: i32 = 2;

fn main() {
    std::process::exit(run());
}

/// Parse, configure color, dispatch. Returns the process exit code.
fn run() -> i32 {
    let cli = Cli::parse();
    // A report written to a file must never carry ANSI; force plain there too.
    color::init(cli.no_color || cli.output.is_some());

    match dispatch(&cli) {
        Ok(code) => code,
        Err(err) => {
            print_error(&err);
            err.exit_code()
        }
    }
}

fn dispatch(cli: &Cli) -> Result<i32, SkillwardError> {
    match &cli.command {
        Some(Command::Install | Command::Update) => bundle::pull(),
        Some(Command::Skills { action }) => Ok(run_skills(action)),
        None => scan(cli),
    }
}

/// The default action: resolve targets, run the ensemble, fuse, report, and gate.
fn scan(cli: &Cli) -> Result<i32, SkillwardError> {
    if cli.targets.is_empty() {
        return Ok(usage_error(
            "no targets. Pass a skill folder, a directory of skills, or an https Git URL.",
        ));
    }

    let selected = scanners::selected(&cli.without, &cli.with);
    if selected.is_empty() {
        return Ok(usage_error(
            "no scanners selected — `--without` excluded them all.",
        ));
    }

    // Resolve targets first so a typo'd path (exit 10) or a refused remote (exit 11)
    // fails before any engine concern.
    let prepared = target::prepare(&cli.targets, cli.offline)?;

    // Host mode runs scanners directly on the host, with no container to contain a
    // symlink that escapes the skill root — the scanners would follow it off-skill and
    // read arbitrary host files into the report. Refuse such a target (exit 14); the
    // Docker sandbox contains the escape. The check never touches the user's files.
    if cli.sandbox == Sandbox::Host {
        for skill in &prepared.skills {
            if remote::has_escaping_symlink(&skill.root) {
                return Err(SkillwardError::UnsafeTarget {
                    // display is attacker-influenced (a remote subpath); sanitize like the report.
                    display: report::sanitize(&skill.display),
                    detail:
                        "symlink(s) escape the skill root and `--sandbox host` would follow them"
                            .to_owned(),
                });
            }
        }
    }

    // Then resolve the bundle, so a missing Docker (exit 12) or un-pulled image
    // (exit 13) fails before scanning, not as nine identical tool-errors.
    let image = match cli.sandbox {
        Sandbox::Docker => bundle::ensure_available()?,
        Sandbox::Host => "host".to_owned(),
    };

    let jobs = cli.jobs.unwrap_or_else(batch::default_jobs);
    print_plan(cli, &selected, prepared.skills.len(), jobs);

    let cfg = ScanConfig {
        scanners: &selected,
        mode: cli.sandbox,
        image: &image,
        fail_on: cli.fail_on,
        timeout: DEFAULT_TIMEOUT,
        jobs,
    };
    let reports = batch::scan(&prepared.skills, &cfg);

    // A skill where every tool errored produced nothing — it was never vetted, so the
    // run fails loud (exit 12) rather than letting it read as a clean PASS.
    if let Some(dead) = batch::first_unscanned(&reports, selected.len()) {
        let detail = dead
            .tool_errors
            .first()
            .map(|e| format!("{}: {}", e.tool, report::sanitize(&e.detail)))
            .unwrap_or_else(|| "no scanner produced output".to_owned());
        return Err(SkillwardError::ScanEngine { detail });
    }

    let rendered = report::render(&reports, cli.format);
    write_output(cli, &rendered)?;

    // The verdict is in the report; the gate fails loud with a coded exit (20).
    report::gate(&reports, cli.fail_on)?;
    Ok(0)
}

/// Write the rendered report to `--output`, or print it to stdout (kept clean for
/// piping; the plan banner and status go to stderr).
fn write_output(cli: &Cli, rendered: &str) -> Result<(), SkillwardError> {
    match &cli.output {
        Some(path) => {
            report::write_to_file(path, rendered)?;
            anstream::eprintln!(
                "{} {}",
                color::paint(color::SUCCESS, "report:"),
                path.display(),
            );
        }
        None => anstream::println!("{rendered}"),
    }
    Ok(())
}

/// Print the fully-resolved invocation on stderr, so the plan is the single source
/// of truth for what a run will do and stdout stays clean for the report.
fn print_plan(cli: &Cli, selected: &[Box<dyn Scanner>], skills: usize, jobs: usize) {
    let tools = selected
        .iter()
        .map(|s| s.id())
        .collect::<Vec<_>>()
        .join(",");
    let config = format!(
        "skills={skills} tools={tools} sandbox={} fail-on={} format={} jobs={jobs} offline={}",
        cli.sandbox, cli.fail_on, cli.format, cli.offline,
    );
    anstream::eprintln!(
        "{}  {}",
        color::paint(color::ACCENT, "skillward"),
        color::paint(color::DIM, &config),
    );
}

/// Dispatch `skillward skills`. Returns the process exit code: `0` on success, or
/// the usage code when `get` is asked for a skill the binary does not bundle.
fn run_skills(action: &SkillsAction) -> i32 {
    match action {
        SkillsAction::List => {
            list_skills();
            0
        }
        SkillsAction::Get { name } => {
            let requested = name.as_deref().unwrap_or(skills::SKILLWARD.name);
            match skills::find(requested) {
                // Verbatim Markdown on a clean stdout, so an agent can pipe or read
                // it directly; the skill is meant to be consumed, not styled.
                Some(skill) => {
                    anstream::print!("{}", skill.body);
                    0
                }
                None => {
                    let available = skills::BUNDLED
                        .iter()
                        .map(|skill| skill.name)
                        .collect::<Vec<_>>()
                        .join(", ");
                    usage_error(&format!(
                        "unknown skill `{requested}`. Available: {available}."
                    ))
                }
            }
        }
    }
}

fn list_skills() {
    anstream::println!(
        "{}  {}",
        color::paint(color::ACCENT, "Agent skills"),
        color::paint(
            color::DIM,
            &format!(
                "(bundled — install with `{}`)",
                skillward::cli::SKILL_INSTALL_CMD
            )
        ),
    );
    for skill in skills::BUNDLED {
        anstream::println!(
            "  {:<10} {}",
            skill.name,
            color::paint(color::DIM, skill.summary),
        );
    }
}

fn print_error(err: &SkillwardError) {
    anstream::eprintln!("{} {err}", color::paint(color::ERROR, "error:"),);
}

/// Print a configuration/usage error and return the clap-aligned exit code. These
/// live outside `SkillwardError` by design; this keeps the print-then-exit-2
/// contract in one place.
fn usage_error(message: &str) -> i32 {
    anstream::eprintln!("{} {message}", color::paint(color::ERROR, "error:"));
    USAGE_ERROR
}
