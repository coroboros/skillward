//! The `clap` command surface: the default scan action plus the `install`, `update`,
//! and `skills` subcommands.
//! Restricted-choice flags are `ValueEnum`s, so an invalid value is rejected with
//! the list of valid ones.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::finding::FailOn;

/// The `npx skills add` install command for the bundled skill, single-sourced so the
/// `--help` footer and the `skills list` footer can't silently drift.
pub const SKILL_INSTALL_CMD: &str = "npx skills add coroboros/skillward";

/// The `Agents:` footer under the `--help` flag list: how an AI agent loads skillward's
/// bundled skill or installs it. Composed from [`SKILL_INSTALL_CMD`] so the install
/// command lives in one place (`concat!` cannot interpolate a const).
fn agents_help() -> String {
    format!(
        "Agents:\n  skillward skills get skillward      print the bundled CLI skill to stdout\n  {SKILL_INSTALL_CMD}  install the skill into your agent"
    )
}

/// skillward — vet an agent skill before you install it. Runs the complete
/// deterministic scanner ensemble, offline, and fuses the findings into one verdict.
#[derive(Debug, Parser)]
#[command(name = "skillward", version, about, long_about = None, propagate_version = true, after_help = agents_help())]
pub struct Cli {
    /// Skill folders, directories of skills, or https Git URLs to scan.
    #[arg(value_name = "TARGETS")]
    pub targets: Vec<String>,

    /// Fail (exit 20) when any finding is at or above this severity.
    #[arg(long, value_enum, default_value_t = FailOn::High)]
    pub fail_on: FailOn,

    /// Report format.
    #[arg(long, value_enum, default_value_t = Format::Terminal)]
    pub format: Format,

    /// Write the report to a file instead of stdout.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Tools to exclude from the default ensemble, comma-separated.
    #[arg(long, value_enum, value_delimiter = ',', value_name = "TOOLS")]
    pub without: Vec<ToolId>,

    /// Tools to re-add to the ensemble (e.g. one excluded by `--without`), comma-separated.
    #[arg(long, value_enum, value_delimiter = ',', value_name = "TOOLS")]
    pub with: Vec<ToolId>,

    /// Where the scanners run: the hardened Docker bundle, or locally-installed binaries.
    #[arg(long, value_enum, default_value_t = Sandbox::Docker)]
    pub sandbox: Sandbox,

    /// Worker threads for the scan; skills and their tools share the pool. Device-aware when omitted.
    #[arg(long, short = 'j', value_name = "N")]
    pub jobs: Option<usize>,

    /// Refuse remote targets; the default Docker sandbox already severs the network for every scan.
    #[arg(long)]
    pub offline: bool,

    /// Disable colored output.
    #[arg(long, global = true)]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Pull the scanner bundle image.
    Install,
    /// Re-pull the pinned scanner bundle image.
    Update,
    /// Print or list the agent skills bundled with skillward.
    Skills {
        #[command(subcommand)]
        action: SkillsAction,
    },
}

/// Actions under `skillward skills`. The binary ships a skill for AI agents;
/// install it the proper way with `npx skills add coroboros/skillward`, or read it
/// inline here.
#[derive(Debug, Subcommand)]
pub enum SkillsAction {
    /// List the agent skills bundled with the binary.
    List,
    /// Print a bundled skill's Markdown to stdout (defaults to `skillward`).
    Get {
        /// Skill name; defaults to skillward's own usage guide.
        name: Option<String>,
    },
}

/// Report serialization formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Colored, human-readable summary (default).
    Terminal,
    /// GitHub-flavored Markdown table report.
    Markdown,
    /// Versioned JSON schema for downstream tooling.
    Json,
    /// SARIF 2.1.0, one run per contributing tool.
    Sarif,
}

/// Where the scanners execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Sandbox {
    /// Inside the hardened, network-isolated Docker bundle (default).
    Docker,
    /// Directly via locally-installed scanner binaries on `PATH`.
    Host,
}

/// The scanners skillward can orchestrate. Value names match the `--with` /
/// `--without` tokens and each adapter's id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum)]
pub enum ToolId {
    #[value(name = "skillspector")]
    Skillspector,
    #[value(name = "cc-audit")]
    CcAudit,
    #[value(name = "aguara")]
    Aguara,
    #[value(name = "cisco")]
    Cisco,
    #[value(name = "agent-audit")]
    AgentAudit,
    #[value(name = "ramparts")]
    Ramparts,
    #[value(name = "semgrep")]
    Semgrep,
    #[value(name = "trivy")]
    Trivy,
    #[value(name = "gitleaks")]
    Gitleaks,
}

/// `Display` via each enum's `ValueEnum` name, so resolved config prints the exact
/// value users pass on the command line.
macro_rules! display_via_value_enum {
    ($($t:ty),+ $(,)?) => {$(
        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self.to_possible_value() {
                    Some(value) => f.write_str(value.get_name()),
                    // Unreachable: every derived variant names a value. Render the
                    // Debug name rather than silently emitting nothing.
                    None => write!(f, "{self:?}"),
                }
            }
        }
    )+};
}

display_via_value_enum!(FailOn, Format, Sandbox, ToolId);

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parses_targets_and_defaults() {
        let cli = Cli::try_parse_from(["skillward", "./skill"]).unwrap();
        assert_eq!(cli.targets, vec!["./skill".to_owned()]);
        assert_eq!(cli.fail_on, FailOn::High);
        assert_eq!(cli.format, Format::Terminal);
        assert_eq!(cli.sandbox, Sandbox::Docker);
        assert!(cli.command.is_none());
    }

    #[test]
    fn without_accepts_comma_separated_tool_ids() {
        let cli = Cli::try_parse_from(["skillward", "--without", "cisco,semgrep", "./s"]).unwrap();
        assert_eq!(cli.without, vec![ToolId::Cisco, ToolId::Semgrep]);
    }

    #[test]
    fn unknown_tool_id_is_a_usage_error() {
        let err = Cli::try_parse_from(["skillward", "--without", "bogus", "./s"]).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("gitleaks"), "{rendered}");
    }

    #[test]
    fn tool_id_round_trips_through_value_enum() {
        for tool in ToolId::value_variants() {
            assert_eq!(
                tool.to_string(),
                tool.to_possible_value().unwrap().get_name()
            );
        }
    }

    #[test]
    fn install_subcommand_parses() {
        let cli = Cli::try_parse_from(["skillward", "install"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Install)));
    }

    #[test]
    fn help_footers_share_one_install_command() {
        assert!(agents_help().contains(SKILL_INSTALL_CMD));
    }
}
