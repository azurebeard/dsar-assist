# B-08 — distroless: the measurement and the decision

**Date:** 2026-08-14 · **Decision: adopt.** Shipped in the same change.

The backlog entry asked whether distroless was worth the cost to diagnosis.
The answer turned on numbers nobody had taken, so they were taken first.

---

## Measured

Both images built from this repository on the same host, scanned with the same
Trivy version and database, `--scanners vuln`, no severity filter.

| | `python:3.13-slim` | `distroless/cc-debian12` |
|---|---|---|
| **Critical** | **4** | **0** |
| **High** | **19** | **0** |
| Medium | 60 | 6 |
| Low | 66 | 13 |
| **Total** | **179** | **19** |
| Fixable | 0 | 0 |
| Size | 215 MB | 226 MB |

The 23 High and Critical findings were entirely in `perl-base` (8),
`util-linux` and its libraries (9), `ncurses` (5), `gzip`, `libacl1` — packages
this application never calls, with no patch available in Debian. What remains
is `libc6` (13), `libssl3` (2) and the gcc runtime, all Medium or Low, none
fixable, all of them things a Python process genuinely needs.

**Size went up, not down.** Distroless is usually pitched as smaller; here it
is 11 MB larger, because a python-build-standalone interpreter is heavier than
Debian's `python3.13-minimal`. Worth stating, because the opposite is widely
assumed.

## What it cost

**The shell, and with it `docker exec` and the Container Apps console.** That
was the objection recorded in the original entry, and it is real. What survives
is the diagnostic path this tool was actually designed around, verified against
the built image:

```
docker run --rm <image> --version                      → dsar 0.1.0
docker run --rm <image> doctor --offline               → All checks passed.
docker run --rm --entrypoint python <image> -m dsar    → dsar 0.1.0
```

`doctor` was always the answer to "why will it not start". It is intact. The
loss is the fallback, not the plan.

**Directories must be seeded from the builder.** No shell means no `RUN mkdir`
in the runtime stage, so `/var/lib/dsar/audit` is created and chowned in the
builder and copied. A fair sample of the friction: small, but it is everywhere.

**uid 10001 was kept.** `distroless/cc:nonroot` is uid 65532, and the
launchers, the Bicep and the CI assertion all name 10001. Using the `:latest`
tag with an explicit `USER 10001:10001` keeps five correct things correct
rather than changing them to suit a base image.

## What it fixed that was not the point

**The interpreter version is now decided once.** `python:3.13-slim` in the
runtime and `uv:python3.13-bookworm-slim` in the builder had to agree on a
minor version, and nothing checked that they did. Dependabot's PR #1 changed
one and not the other; the venv landed in `lib/python3.13/site-packages`, a
3.14 interpreter did not look there, and the whole failure was one line:
`No module named 'dsar'`.

The runtime interpreter is now copied from the builder, so there is one
version, named once in `ARG PYTHON_VERSION`. `test_the_interpreter_version_is_
decided_in_one_place` asserts no base image tag reintroduces a second.

3.14 was tested through the new `ARG` — it builds and `doctor` passes — but
**3.13 ships**. The suite has not been exercised under 3.14 and the week of a
customer demo is not when to find out. PR #1 is closed in favour of a one-line
bump made deliberately.

## What it broke, and how that was caught

**pip came back.** A python-build-standalone interpreter ships one, so
`/opt/python/.../site-packages/pip` (26.0, three findings) existed in the first
distroless build — silently undoing a property the previous image had.

The CI check that was supposed to prevent this said nothing, because it asked
`importlib.util.find_spec("pip")`. The venv never had pip; the interpreter did.
The check had been asking the wrong question and passing for the wrong reason
since it was written.

Both are fixed: pip is removed from `/opt/python` in the builder, with the
`RUN` asserting it is gone, and the CI check now looks at the filesystem under
`/opt/python`, `/app` and `/usr/local` as well as at the import system. The
filesystem check was run against the pip-carrying image to confirm it
discriminates rather than merely passing.

**Trivy found this, not review.** The scan was the only thing in the pipeline
that noticed.

## Still open

**arm64 is unproven.** This workstation has no arm64 binfmt registration, so
neither the old Dockerfile nor the new one builds for arm64 here — it is a host
limitation and not a distroless one. CI's multi-arch build is where that has
always been settled, and it is the check to watch on this change. Apple Silicon
is where the predecessor's demo died, so if that job fails, this decision gets
revisited rather than patched.

## Guards added

| Guard | Where | Proven by |
|---|---|---|
| Runtime base is distroless; no `RUN`, `SHELL` or busybox in the runtime stage | `test_the_runtime_image_has_no_shell` | Swapped the base to `python:3.13-slim` and to a stage with a `RUN`; both failed |
| One interpreter version, named once | `test_the_interpreter_version_is_decided_in_one_place` | Same tamper test |
| No shell in the built image | CI, four paths | Ran it against the built image |
| No package installer, on disk and importable | CI | Ran it against the image that still had pip |
| uid 10001 | CI, asked of the interpreter rather than `id` | `id` no longer exists, which is the point |
