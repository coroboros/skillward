//! The execution sandbox: how a scanner's command is wrapped and run.
//!
//! Determinism and isolation are enforced here, not trusted per-tool. Every scan
//! runs the bundle image with the network severed, a read-only root filesystem,
//! all capabilities dropped, no privilege escalation, and pid/memory caps — so a
//! tool's optional LLM or CVE-lookup call cannot reach out, and a hostile skill
//! cannot escape the container. `--sandbox host` drops the wrapper for users who
//! install the scanners themselves; it trades isolation for not needing Docker.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::{NamedTempFile, TempDir};

/// Mount point for the scanned skill inside the container (read-only).
pub const SCAN_MOUNT: &str = "/scan";
/// Mount point for the writable output directory inside the container.
pub const OUT_MOUNT: &str = "/out";
/// Per-tool wall-clock ceiling. A tool past it is killed and recorded as a
/// tool-error, so one hung scanner never stalls the batch.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// Child-wait poll backoff: start tight so a fast tool is seen quickly, ramp up so a long
/// scan polls cheaply. The cap stays well under any timeout, so a deadline is still prompt.
const POLL_MIN: Duration = Duration::from_millis(1);
const POLL_MAX: Duration = Duration::from_millis(64);

/// Where a tool writes its report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// A SARIF/JSON file written into the output dir, by bare filename.
    File(String),
    /// The report is the tool's stdout (e.g. ramparts).
    Stdout,
}

/// One command a scanner runs: the program, its args (already built against the
/// scan/out paths the caller chose), and where the report lands.
#[derive(Debug, Clone)]
pub struct Plan {
    pub program: String,
    pub args: Vec<String>,
    pub output: Output,
}

/// `--mount` parses comma-separated `key=value` pairs, so a `,` in a bind-mount
/// source path corrupts the spec and could mount the wrong host path. No mount form
/// is robust against every character (`-v` splits on `:`, `--mount` on `,`), so a
/// path carrying the active delimiter is refused fail-closed rather than emitted as a
/// corruptible spec.
pub fn mountable(path: &Path) -> Result<(), String> {
    if path.to_string_lossy().contains(',') {
        return Err(format!(
            "path cannot be bind-mounted (contains ','): {}",
            path.display()
        ));
    }
    Ok(())
}

/// The hardened `docker run` argv that wraps `plan`. Pure and deterministic — the
/// flags are the isolation floor and are asserted by tests so a dropped
/// `--network=none` fails loudly rather than silently de-fanging the sandbox. `name`
/// labels the container so a timeout can reap it by name (see [`docker_rm`]).
pub fn docker_argv(
    plan: &Plan,
    target: &Path,
    out_dir: &Path,
    image: &str,
    name: &str,
) -> Vec<String> {
    let mut argv: Vec<String> = [
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=512",
        "--memory=2g",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=256m",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();

    // Name the container so a timed-out scan can reap it: `--rm` only fires on the
    // container's own exit, and SIGKILL to the `docker run` client (how a timeout is
    // enforced) orphans an otherwise-running container holding its `--memory` budget.
    argv.push("--name".to_owned());
    argv.push(name.to_owned());

    // `--mount` (keyed CSV) rather than `-v` (positional, colon-split): `:` is a legal
    // character in a Linux path and would corrupt a `-v source:dest:opts` spec, either
    // mounting the wrong host path or failing the run.
    argv.push("--mount".to_owned());
    argv.push(format!(
        "type=bind,source={},target={SCAN_MOUNT},readonly",
        target.display()
    ));
    if matches!(plan.output, Output::File(_)) {
        argv.push("--mount".to_owned());
        argv.push(format!(
            "type=bind,source={},target={OUT_MOUNT}",
            out_dir.display()
        ));
    }
    argv.push(image.to_owned());
    argv.push(plan.program.clone());
    argv.extend(plan.args.iter().cloned());
    argv
}

/// Best-effort removal of a container left running after a timeout. Killing the
/// `docker run` client SIGKILLs only the client, not the daemon-owned container, so a
/// hung scanner would otherwise keep its `--memory` budget until reaped. Errors are
/// ignored — the container may already be gone (clean exit honored `--rm`).
pub fn docker_rm(name: &str) {
    let _ = Command::new("docker").args(["rm", "-f", name]).output();
}

/// A process-unique container name, so two concurrent scans never collide and a
/// timeout can reap exactly the container it started.
pub fn container_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("skillward-{}-{n}", std::process::id())
}

/// Captured result of one execution.
#[derive(Debug)]
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub code: Option<i32>,
}

impl ExecOutput {
    /// A short stderr tail for a tool-error message.
    pub fn stderr_tail(&self) -> String {
        let tail: String = self
            .stderr
            .lines()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .join(" | ");
        if tail.is_empty() {
            format!("exit {:?}", self.code)
        } else {
            tail
        }
    }
}

/// Run `program args`, capturing stdout/stderr to temp files (no pipe deadlock) and
/// killing the child past `timeout`. Returns the captured output; an `Err` is a
/// spawn/IO failure (e.g. the program is missing), distinct from a tool that ran
/// and exited non-zero (which many scanners do when they find something).
pub fn execute(program: &str, args: &[String], timeout: Duration) -> Result<ExecOutput, String> {
    let out_tmp = NamedTempFile::new().map_err(|e| e.to_string())?;
    let err_tmp = NamedTempFile::new().map_err(|e| e.to_string())?;
    let stdout = out_tmp.reopen().map_err(|e| e.to_string())?;
    let stderr = err_tmp.reopen().map_err(|e| e.to_string())?;

    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    scrub_credentials(&mut cmd);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("could not spawn `{program}`: {e}"))?;

    let start = Instant::now();
    let mut timed_out = false;
    let mut backoff = POLL_MIN;
    let code = loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => break status.code(),
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(POLL_MAX);
            }
        }
    };

    Ok(ExecOutput {
        stdout: std::fs::read_to_string(out_tmp.path()).unwrap_or_default(),
        stderr: std::fs::read_to_string(err_tmp.path()).unwrap_or_default(),
        timed_out,
        code,
    })
}

/// Strip credential env vars before spawning a scanner. In `--sandbox host` mode the
/// child inherits skillward's environment and runs on the live network, so a hybrid
/// tool's LLM/CVE/VirusTotal stage could exfiltrate the operator's keys and the
/// untrusted skill's content. Removing the keys forces those stages static-only — the
/// posture the Docker sandbox gets for free from `--network=none` and a key-less image.
fn scrub_credentials(cmd: &mut Command) {
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.ends_with("_KEY")
            || name.ends_with("_TOKEN")
            || name.ends_with("_SECRET")
            || name.ends_with("_CREDENTIALS")
            || name.ends_with("_PASSWORD")
            || name.contains("OPENAI")
            || name.contains("ANTHROPIC")
            || name.contains("AWS_")
            || name.contains("AZURE_")
            || name.contains("GOOGLE_")
            || name.contains("GCP_")
        {
            cmd.env_remove(&key);
        }
    }
}

/// Make a directory world-writable so the container's non-root user can write its
/// report into the bind-mounted output dir regardless of uid mapping. No-op off
/// Unix, where Docker Desktop handles bind-mount permissions itself.
fn make_writable(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o777));
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// A writable per-scan output directory, shielded inside a private (0700) parent.
/// The container's foreign uid needs a world-writable dir to drop its report, but a
/// world-writable dir directly under the shared temp root would let any local user
/// tamper with the SARIF between the container write and the host read-back. Nesting
/// it under a 0700 parent (which no other user can traverse) closes that window while
/// the bind mount still reaches the inner dir directly. Returns the parent guard —
/// drop it to remove everything — and the directory to mount.
pub fn out_dir() -> std::io::Result<(TempDir, PathBuf)> {
    let parent = tempfile::tempdir()?;
    // Force 0700 rather than trust the umask-dependent default — the shielding is the
    // whole point, so a 0755 parent would silently defeat it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let dir = parent.path().join("out");
    std::fs::create_dir(&dir)?;
    make_writable(&dir);
    Ok((parent, dir))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::path::PathBuf;

    fn plan_file() -> Plan {
        Plan {
            program: "gitleaks".to_owned(),
            args: vec!["dir".to_owned(), SCAN_MOUNT.to_owned()],
            output: Output::File("gitleaks.sarif".to_owned()),
        }
    }

    #[test]
    fn docker_argv_carries_every_isolation_flag() {
        let argv = docker_argv(
            &plan_file(),
            &PathBuf::from("/abs/skill"),
            &PathBuf::from("/tmp/out"),
            "img:0",
            "skillward-test-0",
        );
        let joined = argv.join(" ");
        // The isolation floor — each flag is load-bearing.
        for flag in [
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=512",
            "--memory=2g",
        ] {
            assert!(joined.contains(flag), "missing {flag} in: {joined}");
        }
        assert!(
            joined.contains("/tmp:rw,noexec,nosuid,nodev,size=256m"),
            "tmpfs must be hardened: {joined}"
        );
        assert!(joined.contains("--name skillward-test-0"), "{joined}");
        assert!(joined.contains("type=bind,source=/abs/skill,target=/scan,readonly"));
        assert!(joined.contains("type=bind,source=/tmp/out,target=/out"));
        assert!(joined.contains("img:0 gitleaks dir /scan"));
    }

    #[test]
    fn mountable_refuses_a_comma_in_the_source_path() {
        assert!(mountable(Path::new("/ok/path/skill")).is_ok());
        assert!(mountable(Path::new("/has,comma/skill")).is_err());
    }

    #[test]
    fn docker_argv_mounts_a_path_with_a_colon_unambiguously() {
        let argv = docker_argv(
            &plan_file(),
            &PathBuf::from("/weird:dir/skill"),
            &PathBuf::from("/tmp/out"),
            "img",
            "skillward-test-1",
        );
        assert!(
            argv.join(" ")
                .contains("type=bind,source=/weird:dir/skill,target=/scan,readonly")
        );
    }

    #[test]
    fn stdout_output_omits_the_writable_mount() {
        let plan = Plan {
            program: "ramparts".to_owned(),
            args: vec![
                "skills".to_owned(),
                "scan".to_owned(),
                SCAN_MOUNT.to_owned(),
            ],
            output: Output::Stdout,
        };
        let argv = docker_argv(
            &plan,
            &PathBuf::from("/s"),
            &PathBuf::from("/o"),
            "img",
            "n",
        );
        assert!(
            argv.join(" ")
                .contains("type=bind,source=/s,target=/scan,readonly")
        );
        assert!(!argv.join(" ").contains("target=/out"));
    }

    #[test]
    fn stderr_tail_takes_last_lines_or_falls_back_to_exit_code() {
        let with_err = ExecOutput {
            stdout: String::new(),
            stderr: "a\nb\nc\nd\ne".to_owned(),
            timed_out: false,
            code: Some(1),
        };
        assert_eq!(with_err.stderr_tail(), "e | d | c");
        let empty = ExecOutput {
            stdout: String::new(),
            stderr: String::new(),
            timed_out: false,
            code: Some(2),
        };
        assert_eq!(empty.stderr_tail(), "exit Some(2)");
    }

    #[test]
    fn execute_captures_stdout_and_exit_code() {
        let out = execute("echo", &["hello".to_owned()], DEFAULT_TIMEOUT).unwrap();
        assert_eq!(out.code, Some(0));
        assert!(out.stdout.contains("hello"));
        assert!(!out.timed_out);
    }

    #[test]
    fn execute_reports_a_missing_program_as_err() {
        assert!(execute("definitely-not-a-real-binary-xyz", &[], DEFAULT_TIMEOUT).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn execute_times_out_and_kills() {
        let out = execute("sleep", &["30".to_owned()], Duration::from_millis(200)).unwrap();
        assert!(
            out.timed_out,
            "a long command must be killed at the deadline"
        );
    }

    #[cfg(unix)]
    #[test]
    fn out_dir_is_shielded_by_a_private_parent() {
        use std::os::unix::fs::PermissionsExt;
        let (parent, dir) = out_dir().unwrap();
        let mode = std::fs::metadata(parent.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "parent must not be group/other accessible (mode {mode:o})"
        );
        assert!(dir.starts_with(parent.path()));
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o777, "inner dir must be world-writable");
        std::fs::write(dir.join("probe"), b"ok").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn execute_nonzero_exit_is_not_an_err() {
        let out = execute("false", &[], DEFAULT_TIMEOUT).unwrap();
        assert_eq!(out.code, Some(1));
    }
}
