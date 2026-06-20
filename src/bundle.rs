//! The scanner bundle image: a from-source build of the nine default scanners,
//! rebuilt on a schedule so offline data stays current with zero rule authoring here.
//! skillward orchestrates; the bundle detects.
//!
//! `install` / `update` pull the image; a scan never pulls implicitly, so an
//! offline run is never surprised by a network fetch — a missing image fails loud
//! with the exact command to fix it.

use std::process::Command;

use crate::color;
use crate::error::SkillwardError;

/// The default bundle image: built and cosign-signed from its GitLab source-of-truth
/// repo `coroboros/security/infrastructure/skillward-bundle`. The manifest-list digest is
/// pinned for byte-reproducible scanner execution.
// renovate: datasource=docker depName=registry.gitlab.com/coroboros/security/infrastructure/skillward-bundle
pub const DEFAULT_BUNDLE_IMAGE: &str = "registry.gitlab.com/coroboros/security/infrastructure/skillward-bundle:1.0.0@sha256:fc6ac013dd7f407294b0f3ca714a85cc93f1bd690b4697d7d7b37fa4b971c6aa";

/// Override the bundle image (e.g. to a digest pin or a local build).
pub const IMAGE_ENV: &str = "SKILLWARD_BUNDLE_IMAGE";

/// The bundle image reference: the env override, else the default bundle image.
pub fn image() -> String {
    resolve_image(std::env::var(IMAGE_ENV).ok())
}

/// Resolve the bundle ref from an optional override, else the pinned default. Split
/// out so it is testable without mutating process env (`set_var` is unsafe, which the
/// crate forbids).
fn resolve_image(override_ref: Option<String>) -> String {
    override_ref.unwrap_or_else(|| DEFAULT_BUNDLE_IMAGE.to_owned())
}

/// Pull the bundle image. Used by `skillward install` and `skillward update`.
pub fn pull() -> Result<i32, SkillwardError> {
    let img = image();
    anstream::eprintln!(
        "{} {}",
        color::paint(color::ACCENT, "skillward"),
        color::paint(color::DIM, &format!("pulling {img}")),
    );
    let status = Command::new("docker")
        .args(["pull", &img])
        .status()
        .map_err(|e| SkillwardError::ScanEngine {
            detail: format!("docker is not available: {e}"),
        })?;
    if !status.success() {
        return Err(SkillwardError::BundlePullFailed {
            image: img,
            detail: "docker pull failed".to_owned(),
        });
    }
    anstream::println!("{} {img}", color::paint(color::SUCCESS, "installed"));
    Ok(0)
}

/// Confirm the bundle image is present locally, without pulling. Distinguishes
/// "Docker unavailable" (exit 12) from "image not pulled" (exit 13) so the user
/// gets the right fix.
pub fn ensure_available() -> Result<String, SkillwardError> {
    let img = image();
    let output = Command::new("docker")
        .args(["image", "inspect", &img])
        .output()
        .map_err(|e| SkillwardError::ScanEngine {
            detail: format!("docker is not available: {e}"),
        })?;
    if !output.status.success() {
        return Err(SkillwardError::BundleUnavailable {
            image: img,
            detail: "image not present locally".to_owned(),
        });
    }
    Ok(img)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_uses_override_else_default() {
        assert_eq!(resolve_image(None), DEFAULT_BUNDLE_IMAGE);
        assert_eq!(
            resolve_image(Some("registry.example/custom@sha256:abc".to_owned())),
            "registry.example/custom@sha256:abc"
        );
    }
}
