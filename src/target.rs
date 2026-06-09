//! Target resolution: turn raw arguments — a skill folder, a directory of skills,
//! or a GitHub URL — into the concrete skill roots to scan. Discovery is driven by
//! `SKILL.md`: a directory holding one is a skill root and is not descended into;
//! a tree of them yields one target each.

use std::path::{Path, PathBuf};

use tempfile::TempDir;

use crate::error::SkillwardError;
use crate::remote;

/// The manifest that marks a directory as a skill root.
const SKILL_MANIFEST: &str = "SKILL.md";

/// Directories never worth descending for skill discovery. The dotfile entries
/// (`.git`, `.venv`, `.pnpm`) are also caught by the `starts_with('.')` rule in
/// `is_ignored`; they are kept explicit so the set stays correct if that broad rule is
/// ever narrowed.
const IGNORED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "target",
    "__pycache__",
    ".pnpm",
];

/// One skill to scan: a display name and the directory mounted into the sandbox.
#[derive(Debug)]
pub struct SkillTarget {
    pub display: String,
    pub root: PathBuf,
}

/// Resolved skills plus the temp-dir guards that keep cloned remotes alive for the
/// scan's lifetime. Drop the guards and the clones are removed.
#[derive(Debug)]
pub struct Prepared {
    pub skills: Vec<SkillTarget>,
    pub guards: Vec<TempDir>,
}

/// Resolve every raw target. Remote URLs are cloned (refused under `offline`); a
/// missing local path fails loud with exit 10.
pub fn prepare(raw: &[String], offline: bool) -> Result<Prepared, SkillwardError> {
    let mut skills = Vec::new();
    let mut guards = Vec::new();

    for target in raw {
        if remote::is_remote(target) {
            let guard = remote::prepare(target, offline)?;
            let base = guard.path().to_path_buf();
            for root in discover_skills(&base) {
                skills.push(SkillTarget {
                    display: remote_display(target, &base, &root),
                    root,
                });
            }
            guards.push(guard);
        } else {
            let path = PathBuf::from(target);
            if !path.exists() {
                return Err(SkillwardError::TargetNotFound { path });
            }
            for root in discover_skills(&path) {
                skills.push(SkillTarget {
                    display: root.display().to_string(),
                    root,
                });
            }
        }
    }
    Ok(Prepared { skills, guards })
}

/// A readable display for a skill discovered inside a cloned repo.
fn remote_display(url: &str, base: &Path, root: &Path) -> String {
    if root == base {
        url.to_owned()
    } else {
        let rel = root
            .strip_prefix(base)
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        format!("{url}#{rel}")
    }
}

/// Find every skill root under `base`. A directory with a `SKILL.md` is a root and
/// is not descended into; symlinked and ignored directories are skipped. When none
/// is found, `base` itself is the single target — so a folder that is a skill
/// without a manifest is still scanned rather than silently dropped.
pub fn discover_skills(base: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut stack = vec![base.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if has_manifest(&dir) {
            roots.push(dir);
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if is_traversable_dir(&path) {
                    stack.push(path);
                }
            }
        }
    }
    if roots.is_empty() {
        roots.push(base.to_path_buf());
    }
    roots.sort();
    roots
}

fn has_manifest(dir: &Path) -> bool {
    dir.join(SKILL_MANIFEST).is_file()
}

/// A real (non-symlink) directory worth descending. Symlinked dirs are never
/// followed, so discovery cannot be lured out of the tree.
fn is_traversable_dir(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => meta.is_dir() && !meta.file_type().is_symlink() && !is_ignored(path),
        Err(_) => false,
    }
}

fn is_ignored(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| IGNORED_DIRS.contains(&n) || n.starts_with('.'))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn skill_dir(parent: &Path, name: &str) -> PathBuf {
        let dir = parent.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(SKILL_MANIFEST), b"# skill\n").unwrap();
        dir
    }

    #[test]
    fn single_skill_resolves_to_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let skill = skill_dir(tmp.path(), "my-skill");
        assert_eq!(discover_skills(&skill), vec![skill]);
    }

    #[test]
    fn directory_of_skills_resolves_each() {
        let tmp = tempfile::tempdir().unwrap();
        let a = skill_dir(tmp.path(), "a");
        let b = skill_dir(tmp.path(), "b");
        let found = discover_skills(tmp.path());
        assert_eq!(found.len(), 2);
        assert!(found.contains(&a) && found.contains(&b));
    }

    #[test]
    fn discover_skills_returns_sorted_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let c = skill_dir(tmp.path(), "c");
        let a = skill_dir(tmp.path(), "a");
        let b = skill_dir(tmp.path(), "b");
        assert_eq!(discover_skills(tmp.path()), vec![a, b, c]);
    }

    #[test]
    fn skill_root_is_not_descended_into() {
        let tmp = tempfile::tempdir().unwrap();
        let skill = skill_dir(tmp.path(), "outer");
        std::fs::create_dir_all(skill.join("scripts")).unwrap();
        std::fs::write(skill.join("scripts/SKILL.md"), b"decoy").unwrap();
        let found = discover_skills(tmp.path());
        assert_eq!(found, vec![skill], "discovery stops at the first manifest");
    }

    #[test]
    fn no_manifest_falls_back_to_the_path_itself() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("README.md"), b"not a skill manifest").unwrap();
        assert_eq!(discover_skills(tmp.path()), vec![tmp.path().to_path_buf()]);
    }

    #[test]
    fn ignored_dirs_are_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let git = tmp.path().join(".git");
        std::fs::create_dir_all(&git).unwrap();
        std::fs::write(git.join(SKILL_MANIFEST), b"decoy in .git").unwrap();
        let real = skill_dir(tmp.path(), "real");
        assert_eq!(discover_skills(tmp.path()), vec![real]);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_skill_dir_is_not_followed() {
        // Else a malicious repo could symlink `/` and have discovery enumerate the host.
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join(SKILL_MANIFEST), b"# skill\n").unwrap();
        let base = tempfile::tempdir().unwrap();
        symlink(outside.path(), base.path().join("linked")).unwrap();
        assert_eq!(
            discover_skills(base.path()),
            vec![base.path().to_path_buf()],
            "a symlinked skill dir must not be discovered"
        );
    }

    #[test]
    fn missing_local_target_is_exit_10() {
        let err = prepare(&["/no/such/path/xyz".to_owned()], false).unwrap_err();
        assert_eq!(err.exit_code(), 10);
    }

    #[test]
    fn remote_display_names_the_url_then_nested_subpath() {
        let base = Path::new("/clone/base");
        assert_eq!(
            remote_display("https://github.com/o/r", base, base),
            "https://github.com/o/r"
        );
        assert_eq!(
            remote_display("https://github.com/o/r", base, &base.join("skills/a")),
            "https://github.com/o/r#skills/a"
        );
    }

    #[test]
    fn offline_does_not_block_local_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let skill = skill_dir(tmp.path(), "local-skill");
        let prepared = prepare(&[skill.display().to_string()], true).unwrap();
        assert_eq!(prepared.skills.len(), 1);
        assert_eq!(prepared.skills[0].root, skill);
    }
}
