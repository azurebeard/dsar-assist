# WS10 Security Review — B-08, distroless runtime

**Date:** 2026-08-14 · **Scope:** the base image change and its guards
**Verdict:** **APPROVED**, conditional on CI's multi-arch job passing. One
finding raised and closed during the review; one condition, stated below.

Measurement and trade-offs: `B-08-distroless-2026-08-14.md`. This assesses the
security consequences only.

---

## The change

`python:3.13-slim` → `gcr.io/distroless/cc-debian12`, with a
python-build-standalone interpreter installed in the builder at
`ARG PYTHON_VERSION` and copied into the runtime.

---

## Attack surface

**Removed.** No shell (`/bin/sh`, `/bin/bash` and the `/usr/bin` equivalents all
verified absent), no coreutils, no package manager, no perl. An attacker who
achieves code execution in this container inherits an environment with no
interpreter but Python, nothing to spawn, and nothing to install with.

Quantified: **179 findings → 19. Four Critical and nineteen High → zero.**
Nothing that remains is fixable, and everything that remains — `libc6`,
`libssl3`, the gcc runtime — is something the process genuinely links against.

**Added.** A python-build-standalone interpreter under `/opt/python`, carrying
its own OpenSSL rather than Debian's. That is a real change in who patches the
TLS stack: previously Debian's security team via `python:3.13-slim` rebuilds,
now the python-build-standalone project via `uv python install`, on a version
this repository pins. Both are tracked by Dependabot's docker ecosystem through
the builder digest. Neither is obviously better; the change is recorded rather
than presented as a pure gain.

**Unchanged.** uid 10001, `USER` set explicitly, read-only root filesystem,
`no-new-privileges`, all capabilities dropped, both stages digest-pinned. The
serving path was run under the full launcher hardening flag set and the CSP,
`X-Frame-Options` and `X-Content-Type-Options` headers were confirmed present
on a live response.

---

## Finding — raised and closed

**SEC-DL-01 · pip returned to the runtime image, and the guard did not notice.**

`python:3.13-slim` shipped pip and it was deliberately removed. A
python-build-standalone interpreter also ships pip, so the first distroless
build reintroduced `pip 26.0` under `/opt/python` — three Trivy findings, and
the loss of a stated property: *a runtime image with no package installer means
an exploited process cannot fetch and install code*.

**The CI guard passed throughout.** It asked
`importlib.util.find_spec("pip")`, and pip was never in the venv — it was in
the interpreter's own site-packages. The check had been asking a question that
could not fail since it was written, which is worse than no check: it was cited
as evidence.

Closed two ways. pip is removed in the builder, with the `RUN` asserting
`! python -c "import pip"` so a future interpreter that resists removal breaks
the build. And the CI guard now enumerates the filesystem under `/opt/python`,
`/app` and `/usr/local` as well as querying the import system. **Run against
the pip-carrying image to confirm it discriminates**, which is the step the
original guard never had.

This is the same defect as SEC-H-02 and as the `innerHTML` comment: a stated
guarantee with a check that could not detect its violation. Third instance in
this project. The pattern to distrust is a check that has never been observed
to fail.

---

## Condition

**arm64 is unproven.** This workstation has no arm64 binfmt registration, so
neither the old nor the new Dockerfile builds arm64 locally — a host
limitation, not a property of the change. CI's multi-arch job is where this has
always been settled.

Apple Silicon is where the predecessor's demo died, and the launcher's primary
target is a laptop. **If the multi-arch build fails, this approval does not
hold** and the change is reverted rather than patched under time pressure.

---

## Not weakened

- **No data plane.** No permitted operation, scope or requested resource
  changed. The structural tests asserting all three still pass.
- **No secrets.** No credential enters the image; nothing about how tokens are
  obtained or held is touched.
- **Audit trail.** `/var/lib/dsar/audit` is created in the builder at uid
  10001 and copied. `doctor` confirms mode `0700` in the built image.
- **Diagnosis.** `doctor`, `--version` and `python -m dsar` all verified inside
  the distroless image. What is gone is `docker exec` and the Container Apps
  console — a real loss of a fallback, an explicit trade, recorded in B-08.

---

## Verdict

**APPROVED**, conditional on the multi-arch CI job. 239 tests pass,
`mypy --strict` clean, the image builds, runs, serves under full hardening and
scans clean of High and Critical. One finding raised and closed, and the guard
that missed it was proven against the broken image rather than assumed.
