# Security Policy

## Supported versions

skillward is pre-1.0. Security fixes land on the latest release only; there is no
backport window until a stable line is cut.

## Reporting a vulnerability

Report privately — do not open a public issue for a security problem.

- Open a [GitHub security advisory](https://github.com/coroboros/skillward/security/advisories/new), or
- email `ob@coroboros.com`.

Include the version (`skillward --version`), platform, the target, and a
reproduction — ideally the skill or a minimal sample that triggers it. Expect an
acknowledgement within a few days and a fix or mitigation plan once confirmed.

## Scope

skillward exists to scan untrusted content, so its own handling of that content is
the attack surface:

- **The scan sandbox** — every scanner runs in a container with the network severed
  (`--network=none`), a read-only root, all capabilities dropped, no privilege
  escalation, and pid/memory caps. A skill that escapes this isolation, reaches the
  network, or reads the host is in scope.
- **Remote-clone hardening** — a clone runs with hooks disabled, submodules and LFS
  not fetched, and symlinks written inert (`core.symlinks=false`), with an escaping-
  symlink sweep on top. A repo that runs code or reads a host path through the clone
  path is in scope.
- **Panic-safety** — `unsafe` is forbidden and `unwrap`/`expect`/`panic` are
  deny-level lints; a crash on a crafted skill or SARIF document is in scope.

Detection quality (a scanner missing a real threat, or a false positive) is a
detection-rule matter upstream, not a vulnerability in skillward — the rules are
inherited from the bundled tools and refreshed by rebuild, never authored here.
