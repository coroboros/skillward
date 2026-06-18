<div align="center">

<img src="assets/logo.png" width="288" height="288" alt="skillward"/>

<!-- omit in toc -->
# skillward

**Take an agent skill apart before installing it — the complete deterministic scanner ensemble, fused into one offline verdict.**

skillward runs every maintained offline scanner that adds a unique detection axis over an untrusted skill, fuses their overlapping findings into one deduplicated report, and returns a `--fail-on` verdict for CI. The scanners live in a from-source Docker bundle; the Rust binary orchestrates, fuses, and gates.

[![crates.io](https://img.shields.io/crates/v/skillward?style=flat-square&color=000000)](https://crates.io/crates/skillward)
[![ci](https://img.shields.io/github/actions/workflow/status/coroboros/skillward/ci.yml?branch=main&style=flat-square&label=ci&color=000000)](https://github.com/coroboros/skillward/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache_2.0-000000?style=flat-square)](https://opensource.org/licenses/Apache-2.0)
[![stars](https://img.shields.io/github/stars/coroboros/skillward?style=flat-square&label=stars&color=000000)](https://github.com/coroboros/skillward)
[![skills](https://img.shields.io/badge/skills-000000?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDE2IDE2IiBmaWxsPSJ3aGl0ZSI+PHBvbHlnb24gcG9pbnRzPSI4LDAgMTAsNiAxNiw4IDEwLDEwIDgsMTYgNiwxMCAwLDggNiw2Ii8+PC9zdmc+)](https://github.com/coroboros/agent-skills)
[![coroboros.com](https://img.shields.io/badge/coroboros.com-000000?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjIiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+PGNpcmNsZSBjeD0iMTIiIGN5PSIxMiIgcj0iMTAiLz48cGF0aCBkPSJNMiAxMmgyME0xMiAyYTE1LjMgMTUuMyAwIDAgMSA0IDEwIDE1LjMgMTUuMyAwIDAgMS00IDEwIDE1LjMgMTUuMyAwIDAgMS00LTEwIDE1LjMgMTUuMyAwIDAgMSA0LTEweiIvPjwvc3ZnPg==)](https://coroboros.com)

</div>

<!-- omit in toc -->
## Contents

- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [Why this exists](#why-this-exists)
- [How it works](#how-it-works)
- [Scanners](#scanners)
- [Determinism and isolation](#determinism-and-isolation)
- [Targets](#targets)
- [Options](#options)
- [Output formats](#output-formats)
- [Agents](#agents)
- [Exit codes](#exit-codes)
- [Limitations](#limitations)
- [Compared to alternatives](#compared-to-alternatives)
- [Contributing](#contributing)
- [License](#license)

## Requirements

- macOS (Apple Silicon or Intel), Linux, or Windows.
- **Docker** for the default sandbox — skillward runs the scanner bundle in a hardened container. `--sandbox host` drops this requirement in exchange for a local scanner install.
- The first `skillward install` pulls the scanner bundle from the GitHub Container Registry (`ghcr.io/coroboros/skillward-bundle`), mirrored to Docker Hub (`coroboros/skillward-bundle`) — a multi-hundred-MB, multi-arch image (Python, semgrep, the trivy DB), container-scanned and cosign-signed. It is cached; subsequent scans are offline.

## Install

```sh
cargo binstall skillward            # prebuilt binary via cargo
brew install coroboros/tap/skillward
npx @coroboros/skillward            # Node toolchains
```

From source:

```sh
cargo install --path .
```

Then pull the scanner bundle once:

```sh
skillward install
```

## Usage

```sh
skillward ./my-skill                 # one skill
skillward ./skills                   # a directory of skills, scanned in parallel
skillward https://github.com/owner/skill   # a remote repo, cloned and hardened
skillward ./my-skill --fail-on critical    # only critical findings fail the gate
skillward ./my-skill --format json -o report.json
skillward ./my-skill --without cisco,semgrep   # trim the ensemble
skillward ./my-skill --sandbox host  # use locally-installed scanners, no Docker
skillward install                    # pull the bundle
skillward update                     # re-pull the pinned bundle
```

Run `skillward --help` for the full flag list.

## Why this exists

Vetting an untrusted skill by hand means running several scanners, each with its own
flags and output format, then trusting that none of them quietly reached the network and
that none was skipped. skillward runs the whole maintained set at once and collapses the
result into a single verdict.

- **Completeness over any one tool.** No single scanner catches everything, so skillward
  runs the union of nine and makes their overlap read as signal: a site flagged by four
  tools is one finding at raised confidence, not four rows of noise.
- **Offline and deterministic.** The default sandbox severs the network for every scan, so
  a tool's optional LLM or CVE-lookup call cannot reach out, and the same skill yields the
  same verdict every run.
- **Fails loud, never silent.** A scanner that crashes, times out, or is missing becomes a
  visible `tool-error`, and a fully dead engine exits non-zero — a degraded run never reads
  as a clean skill.
- **A gate, not a wall of output.** One `--fail-on` verdict per skill and a stable exit
  code, so it drops into CI without parsing.
- **Inherited detection.** Rules come from the upstream tools. The bundle owns
  package pins, reviewed rule commits, and offline data refreshes; skillward
  orchestrates, fuses, and gates — it never authors detection.

## How it works

For security, coverage completeness is the requirement: no single scanner catches
everything, so skillward runs the union and makes the overlap read as signal rather
than noise.

1. **Resolve** the target — a skill folder, a directory of skills, or a remote URL
   (cloned into a hardened, throwaway checkout).
2. **Run** the complete ensemble over each skill, every tool in its own isolated
   container, in parallel.
3. **Normalize** each tool's SARIF into one finding model with a unified severity
   scale and a rule-class taxonomy.
4. **Fuse** — dedup by (class, file, line), correlate across tools (the same site
   flagged by four tools becomes one finding citing all four, at raised confidence),
   and sort so corroborated criticals lead.
5. **Gate** — a per-skill verdict; exit `20` when any finding reaches `--fail-on`.

Detection rules are never authored here. They are inherited from the upstream tools;
package pins, reviewed rule commits, and offline data refreshes live in the
bundle source-of-truth repository,
[coroboros/security/infrastructure/skillward-bundle](https://gitlab.com/coroboros/security/infrastructure/skillward-bundle)
— multi-arch, container-scanned, and cosign-signed with a CycloneDX SBOM.

## Scanners

The default ensemble — every maintained deterministic scanner that adds a unique
axis, all offline-capable. `--without` trims it; `--with` re-adds a tool excluded by `--without`.

<details>
<summary>The nine scanners and their detection axes</summary>

<br>

| Tool | Language | License | Detection axis |
| --- | --- | --- | --- |
| [skillspector](https://github.com/NVIDIA/SkillSpector) | Python | Apache-2.0 | Deepest `SKILL.md` taint → exec |
| [cc-audit](https://github.com/ryo-ebata/cc-audit) | Rust | MIT | Claude Skills / Hooks / MCP config audit |
| [aguara](https://github.com/garagon/aguara) | Go | Apache-2.0 | Supply-chain across 9 ecosystems + agent content |
| [cisco skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) | Python | Apache-2.0 | Multi-engine static — YAML, YARA, bytecode, pipeline taint |
| [agent-audit](https://github.com/HeadyZhang/agent-audit) | Python | MIT | OWASP Agentic Top 10, tool-boundary taint |
| [ramparts](https://github.com/highflame-ai/ramparts) | Rust | Apache-2.0 | MCP servers + agent skills, static |
| [semgrep](https://github.com/semgrep/semgrep) | — | LGPL-2.1 | AST/dataflow with the OWASP-LLM ruleset |
| [trivy](https://github.com/aquasecurity/trivy) | Go | Apache-2.0 | SCA + misconfiguration + secrets |
| [gitleaks](https://github.com/gitleaks/gitleaks) | Go | MIT | Secrets — regex + entropy |

</details>

## Determinism and isolation

Determinism is enforced at the sandbox, not trusted per-tool. Every scanner runs
inside the bundle image with:

```
--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges
--pids-limit=512 --memory=2g
```

The network is severed, so a tool's optional LLM or CVE-lookup stage cannot reach
out — offline DBs (trivy's vuln DB, the semgrep ruleset) are baked into the image.
The same input produces the same report. A tool that crashes, times out, or emits
nothing becomes a `tool-error` on the report rather than aborting the run — and a
dead engine (every tool failing) fails loud with exit `12`, never a silent PASS.

Remote targets are cloned depth-1 with hooks disabled, submodules and LFS not
fetched, and symlinks written inert; an escaping-symlink sweep runs on top, and the
scan itself happens inside the `--network=none --read-only` container.

## Targets

<details>
<summary>The three target types</summary>

<br>

| Target | Behavior |
| --- | --- |
| A skill folder (`SKILL.md` present) | Scanned as one skill. |
| A directory of skills | Each `SKILL.md` root discovered and scanned in parallel. |
| A remote https Git URL | Cloned into a hardened throwaway checkout, then discovered as above. |

</details>

`--offline` refuses remote targets; the default Docker sandbox already severs the network for every scan regardless.

## Options

Every flag; `skillward --help` prints the same surface.

<details>
<summary>All flags and defaults</summary>

<br>

| Option | Default | Description |
| --- | --- | --- |
| `<targets>...` | *(required)* | Skill folders, directories of skills, or https Git URLs. See [Targets](#targets). |
| `--fail-on <SEVERITY>` | `high` | Fail (exit 20) at or above this severity: `none`, `low`, `medium`, `high`, `critical`. |
| `--format <FORMAT>` | `terminal` | Report format: `terminal`, `markdown`, `json`, `sarif`. See [Output formats](#output-formats). |
| `--output <FILE>`, `-o` | stdout | Write the report to a file instead of stdout (color stripped). |
| `--without <TOOLS>` | none | Tools to drop from the ensemble, comma-separated. See [Scanners](#scanners). |
| `--with <TOOLS>` | none | Tools to re-add (e.g. one dropped by `--without`), comma-separated. |
| `--sandbox <MODE>` | `docker` | Where scanners run: `docker` (hardened bundle) or `host` (local binaries). |
| `--jobs <N>`, `-j` | device-aware | Worker threads for the scan; skills and their tools share the pool. |
| `--offline` | `false` | Refuse remote targets; the Docker sandbox already severs the network per scan. |
| `--no-color` | `false` | Disable colored output. |

</details>

<details>
<summary>Subcommands</summary>

<br>

| Command | Description |
| --- | --- |
| `install` | Pull the scanner bundle image (one-time, needs Docker). |
| `update` | Re-pull the pinned bundle image. |
| `skills list` · `skills get [name]` | List or print the bundled agent skill. See [Agents](#agents). |

</details>

### Environment variables

<details>
<summary>Variables that override a default</summary>

<br>

| Variable | Default | Description |
| --- | --- | --- |
| `SKILLWARD_BUNDLE_IMAGE` | the default bundle ref | Override the scanner bundle image — a tag or an `@sha256:` digest, for a byte-reproducible or air-gapped scan. |

</details>

## Output formats

<details>
<summary>The four report formats</summary>

<br>

| `--format` | Contents |
| --- | --- |
| `terminal` | Colored summary — verdict, corroboration, per-finding lines (default). |
| `markdown` | A Markdown report with a findings table per skill. |
| `json` | A versioned schema for tooling — verdict, fused findings, sources, tool-errors. |
| `sarif` | SARIF 2.1.0, one run per contributing tool, for code-scanning consumers. |

</details>

`-o <file>` writes the report to a file (color is stripped); otherwise it prints to
stdout, with the plan banner and status on stderr.

## Agents

skillward ships an agent skill — its own usage-and-triage guide — for coding agents. Install it into an agent:

```sh
npx skills add coroboros/skillward
```

Or read it inline without installing:

```sh
skillward skills get skillward   # print the bundled skill to stdout
skillward skills list            # list bundled skills
```

`skillward --help` carries an `Agents:` footer with the same pointers. The skill drives the CLI to scan a skill, a directory of skills, or a remote URL, then triages the report into an install / don't-install / remediate call. The same Markdown is the single source — embedded in the binary for `skills get` and published for `npx skills add`.

## Exit codes

Stable across releases — only ever added, never renumbered.

<details>
<summary>The exit-code contract</summary>

<br>

| Code | Meaning |
| --- | --- |
| `0` | clean, or all findings below `--fail-on` |
| `1` | unexpected error (e.g. failed to write the report) |
| `2` | usage error (bad flag or value, no targets) |
| `10` | target not found |
| `11` | remote clone failed, an unsupported transport (http/ssh/git/file), or refused under `--offline` |
| `12` | scan-engine failure (Docker unavailable, or no scanner produced output) |
| `13` | scanner bundle image unavailable (not pulled, or a pull failed) |
| `14` | refused: a `--sandbox host` target has symlinks escaping the skill root |
| `20` | findings at or above `--fail-on` |

</details>

## Limitations

- **Docker by default.** The complete ensemble ships as a container image; the
  first pull is large. `--sandbox host` runs locally-installed scanners instead.
- **Static, read-only.** skillward never executes a scanned skill — it cannot catch
  a threat that only manifests at runtime.
- **Detection is inherited.** Coverage is exactly what the bundled tools detect;
  skillward adds completeness, fusion, and a stable gate, not new rules.

## Compared to alternatives

Most tools that vet an agent skill are a single scanner: one engine, one detection
philosophy, run directly on the files. A couple orchestrate several scanners, but each
drops something skillward keeps: isolation, offline operation, corroboration, or a gate.

| Tool | Approach | Multiple external tools | Sandboxed scan | Offline | Cross-tool corroboration | Stable CI gate |
| --- | --- | :---: | :---: | :---: | :---: | :---: |
| **skillward** | 9 deterministic scanners, fused | yes | yes | yes | yes | yes |
| [SkillSpector](https://github.com/NVIDIA/SkillSpector) | regex + AST + optional LLM | no | no | mostly | no | — |
| [ramparts](https://github.com/highflame-ai/ramparts) | YARA + LLM + OWASP-MCP tags | no | no | no | no | partial |
| [cc-audit](https://github.com/ryo-ebata/cc-audit) | AI-free regex rules | no | no | yes | no | yes |
| [agent-audit](https://github.com/HeadyZhang/agent-audit) | AST + taint + secrets | no | no | yes | no | — |
| [Cisco skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) | 8 internal engines + meta-analyzer | internal | no | no | yes | — |
| [shield-claude-skill](https://github.com/alissonlinneker/shield-claude-skill) | wraps Semgrep + gitleaks + Trivy | yes | no | no | dedup only | no |
| semgrep / gitleaks / trivy, alone | one engine, run by hand | no | no | yes | no | per-tool |

Cells reflect each tool's own docs and source; `—` means the property is not established
by its primary sources, not a confirmed "no". The nuances: SkillSpector's LLM stage is
optional and its deterministic core is offline; ramparts connects to live MCP endpoints
and an LLM; Cisco's LLM, VirusTotal, and AI-Defense layers need API keys and a network,
and its eight engines are internal modules, not independent tools; shield-claude-skill
deduplicates by `(file, line, tool)`, so the same issue from two tools is never merged
or confidence-raised, and it ships no isolation and no exit-code gate.

skillward's niche is the intersection none of them occupy: multiple deterministic
external scanners, each run inside a hardened `--network=none` container, fused offline
with cross-tool corroboration, behind a stable-exit `--fail-on` gate.

## Contributing

Bug reports and PRs welcome.

- Open an issue before non-trivial PRs.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/).
- Run `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` before pushing.
- A new scanner must run deterministically and offline and add an axis the ensemble
  does not already cover; add its adapter and mirror its argv in the bundle repo's
  `smoke-test.sh` (`coroboros/security/infrastructure/skillward-bundle`).
- Target the `main` branch.

## License

[Apache 2.0](LICENSE.md)
