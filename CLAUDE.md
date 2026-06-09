# skillward

A Rust CLI that vets an agent skill before you install it: orchestrates a Docker
bundle of nine deterministic scanners, runs them offline, and fuses their findings
into one verdict. The binary orchestrates; the bundle detects.

## Canonical rules

Follows the Coroboros engineering global rules. Repo-specific divergences are stated
inline below.

> **Public-repo hygiene:** ships into a public community repo. Never reference
> private rule paths, local machine paths, or internal tooling here — keep it
> generic.

## Tech Stack
- Rust, edition 2024, toolchain pinned in `rust-toolchain.toml`
- `clap` (derive) for the surface; `anstream` + `anstyle` for color; `rayon` for the parallel batch; `serde_json` for SARIF and the JSON report
- Detection lives in the scanner bundle image, built in the GitLab repo `coroboros/infrastructure/skillward-bundle` from pinned sources — never re-authored here
- `cargo fmt` / `cargo clippy` for format/lint; `assert_cmd` + `predicates` for CLI tests

## Commands
- `cargo build --release` — optimized binary (`strip`, thin LTO)
- `cargo test` — unit + integration (fusion corpus, CLI contract)
- `cargo clippy --all-targets -- -D warnings` — no-panic lints are deny-level
- `cargo fmt --check`
- The scanner bundle image is built and smoke-tested in `coroboros/infrastructure/skillward-bundle` (GitLab), not here.

## Important Files
- `src/main.rs` — parse, dispatch, map errors to exit codes
- `src/error.rs` — `SkillwardError` and the stable exit-code map (`10`/`11`/`12`/`13`/`14`/`20`)
- `src/scanners/mod.rs` — the nine adapters; their argv must mirror the bundle repo's `smoke-test.sh`
- `src/sandbox.rs` — the hardened `docker run` wrapper (the isolation floor)
- `src/bundle.rs` — the bundle image ref (the pinned, cosign-signed GitLab image; digest-pinnable)
- `src/fusion.rs` — dedup, cross-tool correlation, verdict
- `src/sarif.rs` — SARIF 2.1.0 in/out
- `src/skills/mod.rs` — the bundled agent-skill registry; embeds `skills/skillward/SKILL.md`
- `skills/skillward/SKILL.md` — the agent skill, installable via `npx skills add coroboros/skillward`
- `tests/fusion.rs` + `tests/fixtures/sarif/` — the fusion completeness corpus
- `renovate.json` — the single deps bot (cargo, GitHub Actions, and the bundle image via the `src/bundle.rs` annotation); auto-merges the bundle bump, `pinDigests` keeps the digest
- `.github/workflows/auto-tag.yml` — cuts the next SemVer on a green `main` so a Renovate bundle bump auto-releases skillward

## Rules
- **No panics.** Every user-facing failure and every misbehaving tool routes through `SkillwardError` or a `tool-error` note; `unwrap`/`expect`/`panic` are deny-level lints.
- **Exit codes are a contract.** The `error.rs` map is stable — never change a code, only add. Argument errors are clap's (exit `2`).
- **Determinism at the sandbox, not the tool.** Every scan runs `--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges`; never trust a tool to stay offline on its own.
- **Per-tool isolation.** A missing, crashed, or timed-out scanner is a `tool-error`, never an aborted run — and never a silent PASS (`all_engine_failed` catches a dead engine).
- **Detection rules are inherited.** Bump pins in the bundle repo's `Dockerfile`; never author detection rules here.
- **Adapters mirror the smoke test.** A change to an adapter's argv in `src/scanners/mod.rs` must land in the bundle repo's `smoke-test.sh` too.
- **One skill source.** The agent skill lives once in `skills/skillward/SKILL.md`, embedded via `include_str!` for `skills get` and published for `npx skills add`; never duplicate its content.
- Run `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test` before every commit.

## CI overrides
All other rules in `~/.agents/rules/git-conventions.md` apply. Divergences:
- **CI** — consumes `coroboros/ci/.github/workflows/rust-packages.yml@v0` (see `.github/workflows/ci.yml`). The shared pipeline pins the version, generates the CHANGELOG, cuts the release, and imposes the cargo-deny policy centrally — so this repo carries **no `release-plz.toml` and no consumer `deny.toml`** (a local one is ignored).
- **Branch model** — main-only: feature branch → PR → squash-merge → tag.
- **Auto-update loop** — Renovate is the single deps bot (no Dependabot): it bumps the bundle image pinned in `src/bundle.rs` and auto-merges it; a green `main` then auto-tags the next SemVer (`.github/workflows/auto-tag.yml`), which the shared pipeline publishes. The tag push needs the `CI_RELEASE_TOKEN` repo secret — a PAT, mirroring the GitLab release-token name, since a `GITHUB_TOKEN`-pushed tag would not trigger the release run. The first release is cut manually (no baseline tag to bump from).
- **Scanner bundle** — the image is built in a separate GitLab source-of-truth repo, `coroboros/infrastructure/skillward-bundle`, via the `coroboros/ci` container-images template: multi-arch, container-scanned, cosign-signed with a CycloneDX SBOM. It is published to `ghcr.io/coroboros/skillward-bundle` (mirrored to Docker Hub); the CLI pins that ref in `src/bundle.rs` (digest-pinnable via `SKILLWARD_BUNDLE_IMAGE`) and is versioned independently of the image.
