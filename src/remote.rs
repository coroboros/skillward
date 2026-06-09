//! Untrusted-remote handling: clone a remote Git repo (a GitHub URL or any https
//! host) for scanning without ever trusting it.
//!
//! The clone is depth-1, hooks disabled, submodules and LFS not fetched, and
//! symlinks written as plain files (`core.symlinks=false`) so a link to
//! `/etc/passwd` becomes inert text rather than a read of the host. A post-clone
//! sweep removes any symlink that still escapes the clone root. The scan then runs
//! inside the `--network=none --read-only` container, the isolation floor under all
//! of this. The clone lands in a [`TempDir`] removed when the guard drops.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use tempfile::TempDir;

use crate::error::SkillwardError;

/// Whether a raw target is a remote URL rather than a local path.
pub fn is_remote(target: &str) -> bool {
    target.starts_with("https://")
        || target.starts_with("http://")
        || target.starts_with("github.com/")
        || target.starts_with("git@")
}

/// Normalize a remote target to an `https://` URL. Only https and the
/// `github.com/owner/repo` shorthand are allowed; plaintext http (unauthenticated,
/// MITM-able) and ssh/git/file/ext transports (which can run code or read local
/// files) are refused. The host is not restricted to GitHub — the clone hardening is
/// host-agnostic — so any https Git repo is accepted.
pub fn normalize_url(target: &str) -> Result<String, String> {
    if let Some(rest) = target.strip_prefix("github.com/") {
        return Ok(format!("https://github.com/{rest}"));
    }
    if target.starts_with("https://") {
        return Ok(target.to_owned());
    }
    Err(format!(
        "unsupported remote `{target}` — only https URLs or the `github.com/owner/repo` shorthand are accepted (no http/ssh/git/file transports)"
    ))
}

/// The hardened `git clone` argv. Pure and asserted by tests so a dropped guard
/// (hooks, submodules, symlinks, prompts) fails loudly.
pub fn clone_argv(url: &str, dir: &Path) -> Vec<String> {
    [
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.symlinks=false",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "protocol.file.allow=never",
        "clone",
        "--depth",
        "1",
        "--no-tags",
        "--no-recurse-submodules",
        "--quiet",
        // End of options: the url and dir are positionals even if a future relaxation
        // of `normalize_url` ever let a `-`-leading value through.
        "--",
        url,
    ]
    .iter()
    .map(ToString::to_string)
    .chain(std::iter::once(dir.display().to_string()))
    .collect()
}

/// Strip any `user:pass@` userinfo from a URL so a pasted credential is never echoed
/// into an error line (which prints to stderr). Pure string surgery on the authority;
/// the unredacted url is still what `clone_argv` hands to git for authentication.
fn redact_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let (authority, path) = rest.split_at(authority_end);
    match authority.rsplit_once('@') {
        Some((_userinfo, host)) => format!("{scheme}://{host}{path}"),
        None => url.to_owned(),
    }
}

/// Scrub a pasted credential out of git's stderr, which historically echoes the clone url.
/// git gets the exact `url`, so replace it with the redacted form; strip a bare `user:pass@`
/// as a backstop for a reformatted echo.
fn redact_in_text(text: &str, url: &str) -> String {
    let mut out = text.replace(url, &redact_url(url));
    if let Some((_scheme, rest)) = url.split_once("://") {
        let authority_end = rest.find('/').unwrap_or(rest.len());
        if let Some((userinfo, _host)) = rest[..authority_end].rsplit_once('@') {
            out = out.replace(&format!("{userinfo}@"), "");
        }
    }
    out
}

/// A short, credential-scrubbed tail of git's captured stderr for the [`CloneFailed`] detail,
/// so the user still gets git's reason (auth, DNS, not found) without the leak.
///
/// [`CloneFailed`]: SkillwardError::CloneFailed
fn clone_failure_detail(stderr: &str, url: &str) -> String {
    let scrubbed = redact_in_text(stderr, url);
    let lines: Vec<&str> = scrubbed.lines().filter(|l| !l.trim().is_empty()).collect();
    let tail = lines[lines.len().saturating_sub(2)..].join(" | ");
    if tail.is_empty() {
        "git clone failed".to_owned()
    } else {
        // git's stderr is semi-untrusted (a hostile remote shapes it) — neutralize control chars.
        format!("git clone failed: {}", crate::report::sanitize(&tail))
    }
}

/// Clone `target` into a fresh temp dir and return the guard. `offline` refuses
/// the remote outright. The caller holds the [`TempDir`] for the scan's lifetime.
pub fn prepare(target: &str, offline: bool) -> Result<TempDir, SkillwardError> {
    let url = normalize_url(target).map_err(|detail| SkillwardError::CloneFailed {
        url: redact_url(target),
        detail,
    })?;
    // The url stored in every error is redacted; the unredacted `url` goes only to git.
    let safe = redact_url(&url);
    if offline {
        return Err(SkillwardError::CloneFailed {
            url: safe,
            detail: "--offline forbids remote targets; scan a local checkout instead".to_owned(),
        });
    }

    let dir = tempfile::tempdir().map_err(|e| SkillwardError::CloneFailed {
        url: safe.clone(),
        detail: e.to_string(),
    })?;

    let output = Command::new("git")
        .args(clone_argv(&url, dir.path()))
        // Belt to the argv suspenders: no global/system config, no credential
        // prompt, no LFS smudge can pull extra content.
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        // Capture git's stderr rather than inheriting it: git echoes the url (with any
        // userinfo) there, which would bypass the redaction CloneFailed applies. We scrub it.
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| SkillwardError::CloneFailed {
            url: safe.clone(),
            detail: format!("git is not available: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SkillwardError::CloneFailed {
            url: safe,
            detail: clone_failure_detail(&stderr, &url),
        });
    }

    let removed = sweep_symlinks(dir.path());
    if removed > 0 {
        anstream::eprintln!(
            "{} neutralized {removed} escaping symlink(s) in the clone",
            crate::color::paint(crate::color::WARN, "hardening:"),
        );
    }
    Ok(dir)
}

/// Whether `link` is a symlink whose target resolves outside `root` — a traversal
/// escape (e.g. a link to `/etc/passwd`). A link that stays inside the tree is safe.
pub fn symlink_escapes_root(root: &Path, link: &Path) -> bool {
    let Ok(target) = std::fs::read_link(link) else {
        return false; // not a symlink
    };
    let Ok(base) = root.canonicalize() else {
        return true; // an unresolvable root cannot be trusted — treat as an escape
    };
    // Resolve the target against the link's real (canonicalized) parent directory.
    let resolved = if target.is_absolute() {
        target
    } else {
        let parent = link.parent().unwrap_or(root);
        parent
            .canonicalize()
            .unwrap_or_else(|_| parent.to_path_buf())
            .join(&target)
    };
    match resolved.canonicalize() {
        Ok(r) => !r.starts_with(&base),
        // Dangling target (absent on this host): decide lexically. Compare against
        // both the canonical base and the root as given, so an internal target spelled
        // through a symlinked prefix (e.g. macOS `/tmp -> /private/tmp`) is recognized
        // as internal rather than over-removed, while a true `..`/out-of-tree escape is
        // still caught.
        Err(_) => {
            let norm = lexical_normalize(&resolved);
            !(norm.starts_with(&base) || norm.starts_with(lexical_normalize(root)))
        }
    }
}

/// Resolve `.` and `..` components purely lexically, without touching the
/// filesystem, so an escaping path can be judged even when its target does not exist
/// on the scanning host.
fn lexical_normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Walk `root` depth-first WITHOUT following symlinks (so the walk itself cannot be
/// lured out of the tree — the security-sensitive invariant), invoking `on_escape` for
/// each symlink that escapes `root`. Returns the count for which `on_escape` returned
/// true. One source for both the detector and the sweep.
fn for_each_escaping_symlink(root: &Path, mut on_escape: impl FnMut(&Path) -> bool) -> usize {
    let mut count = 0;
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                if symlink_escapes_root(root, &path) && on_escape(&path) {
                    count += 1;
                }
            } else if meta.is_dir() {
                stack.push(path);
            }
        }
    }
    count
}

/// Whether any symlink under `root` escapes it — a read-only check that removes
/// nothing. Used to refuse a host-mode scan, which (unlike the Docker sandbox) runs
/// scanners directly on the host with no container to contain a symlink pointing
/// outside the scanned tree. Never deletes: a local target is the user's own directory.
///
/// Best-effort against single-hop escapes: the walk never follows symlinks, so an
/// escaper reachable ONLY through an internal directory-symlink is not seen. The Docker
/// sandbox (the default and the real isolation floor) contains the escape regardless.
pub fn has_escaping_symlink(root: &Path) -> bool {
    for_each_escaping_symlink(root, |_| true) > 0
}

/// Remove every escaping symlink under `root`, returning the count removed.
pub fn sweep_symlinks(root: &Path) -> usize {
    for_each_escaping_symlink(root, |path| std::fs::remove_file(path).is_ok())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn detects_remote_targets() {
        assert!(is_remote("https://github.com/owner/repo"));
        assert!(is_remote("github.com/owner/repo"));
        assert!(is_remote("git@github.com:owner/repo.git"));
        assert!(is_remote("http://github.com/o/r"));
        assert!(!is_remote("./local/skill"));
        assert!(!is_remote("/abs/path"));
    }

    #[test]
    fn http_remote_is_refused_not_treated_as_a_local_path() {
        let err = prepare("http://github.com/o/r", false).unwrap_err();
        assert_eq!(err.exit_code(), 11);
    }

    #[test]
    fn normalize_rejects_dangerous_transports() {
        assert_eq!(
            normalize_url("github.com/o/r").unwrap(),
            "https://github.com/o/r"
        );
        assert_eq!(
            normalize_url("https://github.com/o/r").unwrap(),
            "https://github.com/o/r"
        );
        assert_eq!(
            normalize_url("https://gitlab.com/o/r").unwrap(),
            "https://gitlab.com/o/r"
        );
        assert!(normalize_url("git@github.com:o/r.git").is_err());
        assert!(normalize_url("file:///etc").is_err());
        assert!(normalize_url("http://github.com/o/r").is_err());
    }

    #[test]
    fn clone_argv_carries_every_hardening_flag() {
        let argv = clone_argv("https://github.com/o/r", Path::new("/tmp/c")).join(" ");
        for flag in [
            "core.hooksPath=/dev/null",
            "core.symlinks=false",
            "protocol.ext.allow=never",
            "--depth 1",
            "--no-recurse-submodules",
            "--no-tags",
        ] {
            assert!(argv.contains(flag), "missing {flag} in: {argv}");
        }
        assert!(
            argv.contains("-- https://github.com/o/r"),
            "url not guarded by --: {argv}"
        );
    }

    #[test]
    fn redact_url_strips_credentials_keeps_the_rest() {
        assert_eq!(
            redact_url("https://user:t0ken@github.com/o/r"),
            "https://github.com/o/r"
        );
        assert_eq!(
            redact_url("https://github.com/o/r"),
            "https://github.com/o/r"
        );
        assert_eq!(redact_url("github.com/o/r"), "github.com/o/r");
    }

    #[test]
    fn a_pasted_token_is_not_echoed_into_the_error() {
        let err = prepare("https://alice:s3cret@github.com/o/r", true).unwrap_err();
        let rendered = err.to_string();
        assert!(
            !rendered.contains("s3cret"),
            "credential leaked: {rendered}"
        );
        assert!(rendered.contains("github.com/o/r"), "host lost: {rendered}");
    }

    #[test]
    fn clone_failure_detail_scrubs_the_credential_from_git_stderr() {
        let url = "https://alice:s3cret@github.com/o/r";
        let stderr = "Cloning into 'r'...\n\
            fatal: Authentication failed for 'https://alice:s3cret@github.com/o/r'\n";
        let detail = clone_failure_detail(stderr, url);
        assert!(!detail.contains("s3cret"), "token leaked: {detail}");
        assert!(
            !detail.contains("alice:s3cret"),
            "userinfo leaked: {detail}"
        );
        assert!(
            detail.contains("github.com/o/r"),
            "host/path lost: {detail}"
        );
        assert_eq!(clone_failure_detail("", url), "git clone failed");
        let evil = clone_failure_detail("fatal: \u{1b}[31mboom\u{07}", url);
        assert!(
            !evil.contains('\u{1b}') && !evil.contains('\u{07}'),
            "{evil:?}"
        );
    }

    #[test]
    fn git_ssh_target_is_refused_via_the_clone_path() {
        let err = prepare("git@github.com:o/r.git", false).unwrap_err();
        assert_eq!(err.exit_code(), 11);
    }

    #[cfg(unix)]
    #[test]
    fn sweep_removes_escaping_symlink_not_internal_one() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let escape = root.path().join("passwd-link");
        symlink("/etc/passwd", &escape).unwrap();
        let inside_target = root.path().join("real.txt");
        std::fs::write(&inside_target, b"ok").unwrap();
        let inside_link = root.path().join("inside-link");
        symlink(&inside_target, &inside_link).unwrap();

        assert!(symlink_escapes_root(root.path(), &escape));
        assert!(!symlink_escapes_root(root.path(), &inside_link));

        let removed = sweep_symlinks(root.path());
        assert_eq!(removed, 1, "only the escaping link is removed");
        assert!(!escape.exists(), "escaping symlink must be gone");
        assert!(inside_link.exists(), "internal symlink must survive");
    }

    #[cfg(unix)]
    #[test]
    fn detects_an_escaping_symlink_without_removing_it() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        assert!(!has_escaping_symlink(root.path()), "a clean tree has none");
        let link = root.path().join("escape");
        symlink("/etc/passwd", &link).unwrap();
        assert!(
            has_escaping_symlink(root.path()),
            "an escaping link is detected"
        );
        assert!(
            std::fs::symlink_metadata(&link).is_ok(),
            "detection must not delete"
        );
    }

    #[test]
    fn offline_refuses_remote() {
        let err = prepare("https://github.com/o/r", true).unwrap_err();
        assert_eq!(err.exit_code(), 11);
        assert!(err.to_string().contains("offline"));
    }

    #[cfg(unix)]
    #[test]
    fn sweep_catches_dangling_relative_escape_keeps_dangling_internal() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let escape = root.path().join("dangling-escape");
        symlink("../../../nonexistent-xyz-123/secret", &escape).unwrap();
        assert!(
            symlink_escapes_root(root.path(), &escape),
            "a relative ../ escape to a missing target must be caught"
        );
        let inside = root.path().join("dangling-inside");
        symlink("also-missing.txt", &inside).unwrap();
        assert!(
            !symlink_escapes_root(root.path(), &inside),
            "an internal dangling link is not an escape"
        );

        use std::os::unix::fs::symlink as symlink2;
        let abs_inside = root.path().join("abs-internal-dangling");
        symlink2(root.path().join("missing.txt"), &abs_inside).unwrap();
        assert!(
            !symlink_escapes_root(root.path(), &abs_inside),
            "an internal dangling absolute link must not be flagged as an escape"
        );
        let abs_outside = root.path().join("abs-escape");
        symlink2("/definitely/not/under/this/root/x", &abs_outside).unwrap();
        assert!(symlink_escapes_root(root.path(), &abs_outside));

        let removed = sweep_symlinks(root.path());
        assert_eq!(
            removed, 2,
            "both escaping links removed, internal ones kept"
        );
        // exists() follows the link (always false when dangling), so check the link
        // file itself via symlink_metadata.
        assert!(
            std::fs::symlink_metadata(&escape).is_err(),
            "escaping link file must be gone"
        );
        assert!(
            std::fs::symlink_metadata(&inside).is_ok(),
            "internal dangling link must survive"
        );
    }
}
