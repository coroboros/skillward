---
name: Bug report
about: A scan, verdict, or exit code that behaves wrong
title: ""
labels: bug
---

## What happened

The scan, verdict, or exit code that misbehaved, and what it should have been instead.

## Reproduce

```sh
# the exact command
skillward ...
```

- Exit code: `$?`
- Target: the skill, directory, or https URL (a small sample skill helps)

## Environment

- skillward version: `skillward --version`
- OS + arch:
- `--sandbox` mode: docker / host (and Docker version if relevant)

## Logs

The error line and any stderr output (run without `--no-color` stripping).
