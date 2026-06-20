---
name: skillward
description: Vet an untrusted agent skill, plugin, or MCP server before it is installed or trusted. Runs the skillward CLI — the complete deterministic scanner ensemble, offline, fused into one verdict — then triages the report into a plain-language risk read with an install / don't-install / remediate call. Use this whenever someone is about to add or run third-party agent code (npx skills add, a marketplace or plugin, an https Git URL, a directory of skills, or a local folder), even when they only ask "is this safe?" rather than naming a scan. Trigger phrases include scan this skill, vet before install, audit this agent skill, is this skill or MCP server safe, check this repo before I trust it.
---

# skillward

Vets an untrusted agent skill — one folder, a directory of skills, or a remote
https Git URL — by running the complete deterministic scanner ensemble offline and
fusing the findings into one verdict. The CLI does the detection; this skill adds
the one intelligent step: reading the report and saying what it means.

## Install

The CLI is the engine. Install it once:

```sh
cargo binstall skillward     # prebuilt binary
brew install coroboros/tap/skillward
npx @coroboros/skillward     # Node toolchains
```

Then pull the scanner bundle (one-time, needs Docker):

```sh
skillward install
```

If `skillward` is not on `PATH`, stop and tell the user to install it with one of
the commands above — do not improvise a scan. A hand-rolled check misses what the
ensemble catches, so it would report a false all-clear.

## Use

Run `skillward --help` for the full surface. The default scan, with a JSON report
for triage:

```sh
skillward <target> --format json -o report.json
```

`<target>` is a skill folder, a directory of skills, or an `https://` Git repo
URL. Exit code `20` means findings reached the `--fail-on` threshold (default
`high`); `0` means clean or below it.

## Analyze

After the scan, read `report.json` and produce a triage — not a re-print of the
findings:

1. **Lead with the verdict.** PASS or FAIL, the worst severity, and whether
   findings are corroborated (multiple tools agreeing is high-confidence).
2. **Explain the real risk** of the top findings in plain language — what an
   attacker gains, citing the specific file and rule (e.g. "exfiltrates AWS
   credentials on every invocation — `setup.sh:7`, flagged by skillspector and
   semgrep").
3. **Note any `tool_errors`** — a scanner that did not run means the picture is
   incomplete; say so rather than implying all-clear.
4. **Make the call:** install, don't-install, or remediate-then-reinstall. For
   remediate, name the exact change.

Keep it short and decision-oriented. The findings are in the report; the judgment
is the work.
