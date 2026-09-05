# skillward

Rust CLI that orchestrates an offline scanner bundle and combines its findings into one skill-safety verdict.

## Project constraints

- `README.md` owns the CLI and report contracts; `src/error.rs` owns stable exit codes. Add codes without renumbering existing ones; preserve clap's argument-error behavior.
- Route malformed input and tool failures through `SkillwardError` or a visible `tool-error`. A missing, crashed or timed-out scanner degrades the result; a wholly failed engine is not a pass.
- `src/sandbox.rs` owns Docker isolation: network disabled, read-only filesystem, dropped capabilities and no new privileges. Preserve these guarantees at the sandbox boundary.
- Detection belongs to the separately maintained scanner bundle. `src/bundle.rs` pins its digest; scanner arguments in `src/scanners/mod.rs` must match the bundle's smoke-tested interface. Coordinate interface changes with that owner.
- `skills/skillward/SKILL.md` is the single skill source, embedded by `src/skills/mod.rs`. Keep public artifacts free of private paths and infrastructure references.

## Validation

The toolchain is pinned in `rust-toolchain.toml`. Rust or dependency changes require `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test`; documentation-only edits need Markdown and reference checks.

Adapter, sandbox or bundle changes also require the relevant Docker integration and bundle smoke evidence. `tests/fusion.rs` and `tests/fixtures/sarif/` protect fusion completeness. Reuse passing results while the tested inputs remain unchanged.

## Release

Target `main` through a PR and squash-merge the reviewed head. The shared Rust pipeline owns version artifacts, changelog, cargo-deny policy and publication. `.github/workflows/auto-tag.yml` tags eligible changes after green `main`; verify that outcome before considering an authorized manual tag. The initial release needs a manual tag when no baseline exists.

Renovate owns dependency and digest updates; preserve its auto-update flow and existing release-token wiring. The scanner image is released separately; its documented registry override is `SKILLWARD_BUNDLE_IMAGE`.
