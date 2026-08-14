# Software Bill of Materials

**Generated:** 2026-08-14 from `uv.lock` · **Application version:** 0.1.0

A machine-readable SBOM is attached to every published image by
`.github/workflows/publish.yml` (`sbom: true`), so it cannot drift from the
artefact it describes. This document is the human-readable companion: what is
here, why, and what each thing is trusted with.

---

## Runtime — declared

Four. The dependency budget is asserted by a structural test that reads
`[project.dependencies]`, so a fifth is a visible diff.

| Package | Version | Why | Trusted with |
|---|---|---|---|
| `msal` | 1.37.0 | Microsoft's own auth library. Custom token handling is the thing not to write | Tokens in memory, ID-token validation, PKCE, claims challenges |
| `httpx` | 0.28.1 | ASGI-native HTTP. A sync client in an async handler blocks the loop | Every outbound call to Microsoft Graph |
| `starlette` | 1.6.0 | ASGI without FastAPI's Pydantic surface — validation here is hand-written and stricter than a schema | Routing, request parsing, the test client |
| `uvicorn` | 0.52.3 | ASGI server | Binding the socket, TLS termination is the ingress's job |

**Deliberately absent:** `msal-extensions`. Its libsecret backend needs
PyGObject, a system package pip cannot install, so inside a virtualenv the
encrypted backend silently disappears and the tool degrades to interactive
sign-in on every launch. It caused 100% of the predecessor's observed
portability failures. A structural test bans it.

---

## Runtime — transitive

| Package | Version | Arrives via |
|---|---|---|
| `anyio` | 4.14.2 | starlette, httpx |
| `certifi` | 2026.7.22 | httpx, requests — the CA bundle |
| `cffi` | 2.1.1 | cryptography |
| `charset-normalizer` | 3.5.0 | requests |
| `click` | 8.4.2 | uvicorn |
| `colorama` | 0.4.6 | click, on Windows |
| `cryptography` | 50.0.0 | msal — JWT signature verification |
| `h11` | 0.16.0 | httpcore, uvicorn — HTTP/1.1 |
| `httpcore` | 1.0.9 | httpx |
| `idna` | 3.18 | httpx, requests |
| `pycparser` | 3.0 | cffi |
| `pyjwt` | 2.13.0 | msal — token decoding |
| `requests` | 2.34.2 | **msal**, transitively |
| `typing-extensions` | 4.16.0 | several |
| `urllib3` | 2.7.0 | requests |

**On `requests`.** It is here because `msal` uses it internally, not because
this codebase does — a structural test permits `httpx` in exactly three modules
and bans `requests` everywhere. It is stated rather than hidden: the dependency
budget is asserted over what we *declare*, because the predecessor maintained a
hand-written allowlist of resolved transitives and it did not survive
dependency churn.

---

## Development only

Not in the image. `uv sync --no-dev` in the builder stage.

`pytest` 9.1.1 · `mypy` 1.20.2 · `mypy-extensions` 1.1.0 · `iniconfig` 2.3.0 ·
`packaging` 26.3 · `pathspec` 1.1.1 · `pluggy` 1.6.0 · `pygments` 2.20.0 ·
`librt` 0.15.0

---

## Base images

Both pinned by digest, not tag. A tag can be repointed upstream with no change
here, and reproducibility is this project's reason for existing.

| Stage | Image | Digest |
|---|---|---|
| Builder | `ghcr.io/astral-sh/uv:bookworm-slim` | `sha256:22334efe…e0a3` |
| Runtime | `gcr.io/distroless/cc-debian12` | `sha256:6e1871c3…e1d0` |

The runtime carries **no shell, no package manager and no coreutils**. The
interpreter is a python-build-standalone CPython copied from the builder, so
`ARG PYTHON_VERSION` is the single place that decides which interpreter runs —
previously two base image tags had to agree, and nothing checked that they did
(see `B-08-distroless-2026-08-14.md`).

**pip is removed from the runtime image.** It is not needed — the venv is
populated at build time — and a runtime image with no package installer means
an exploited process cannot fetch and install code.

It has been removed twice. On `python:3.13-slim` it was Debian's, whose
*vendored* tree carried the only two fixable High findings Trivy reported
(`msgpack` 1.1.2, `setuptools` 70.3.0), unfixable by any change to
`pyproject.toml`. On distroless it came back, because a python-build-standalone
interpreter ships its own — and the CI check missed it, because it asked
`importlib.util.find_spec("pip")` and the venv never had pip. Trivy caught it.
The check now looks at the filesystem as well, and was run against the
pip-carrying image to confirm it discriminates.

---

## Front end

**No npm, no bundler, no transpiler, no lockfile.** Three files —
`index.html`, `app.js`, `style.css` — served from an explicit allowlist rather
than a directory mount. Zero third-party JavaScript, so the front end has no
supply chain of its own.

---

## Scanning

| Check | Where | Blocking |
|---|---|---|
| Trivy — vulnerabilities and secrets, fixable | CI, on the built image | Yes, High + Critical |
| Trivy — unfixed | CI | No, reported so they are known rather than suppressed |
| Gitleaks | CI, full history | Yes |
| `uv lock --check` | CI | Yes |
| Dependabot | pip, docker, actions | Opens PRs |

**Current residual: 19 findings, 6 Medium and 13 Low, none Critical, none
High, none fixable** — `libc6` (13), `libssl3` (2) and the gcc runtime. All are
libraries a Python process genuinely needs.

Before B-08 it was **179 findings, 4 Critical and 19 High**, in `perl-base`,
`util-linux`, `ncurses` and `gzip` — packages this application never calls,
with no patch available. Measured either side of the change on 2026-08-14; the
numbers and the trade are in `B-08-distroless-2026-08-14.md`.

---

## Provenance

Every published image carries an SBOM, SLSA provenance (`mode=max`), a
build-provenance attestation, and a keyless cosign signature over the
**digest**. Verify with:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/azurebeard/dsar-assist/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/azurebeard/dsar-assist@sha256:<digest>
```
