# syntax=docker/dockerfile:1
#
# B-08 EVALUATION ARTEFACT. Measurement and decision:
# docs/B-08-distroless-2026-08-14.md
#
# `python:3.13-slim` carries 23 HIGH and CRITICAL findings, 4 of them Critical
# and none of them fixable, all in packages this application never calls: perl,
# util-linux, ncurses, gzip. Measured 2026-08-14.
#
# The interpreter is the interesting part. `gcr.io/distroless/python3-debian12`
# ships Debian's python3.11, so the runtime would choose the interpreter
# version and a venv built against anything else silently fails to import —
# which is exactly how the python 3.14 bump (PR #1) broke. This installs a
# python-build-standalone interpreter in the builder, at a version chosen here,
# and copies it. One place decides the version instead of two that must agree.

# ---------------------------------------------------------------- builder
FROM ghcr.io/astral-sh/uv:bookworm-slim@sha256:22334efe746f1b69217d455049b484d7b8cacfb2d5f42555580b62415a98e0a3 AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_INSTALL_DIR=/opt/python

ARG PYTHON_VERSION=3.13

# The interpreter that lands in the runtime image is the one the venv is built
# against, because it is the same files. python-build-standalone carries its
# own OpenSSL and libffi, so it does not need Debian's.
RUN uv python install "${PYTHON_VERSION}"

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project --python "${PYTHON_VERSION}"

COPY src/ ./src/
COPY README.md ./

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable --python "${PYTHON_VERSION}"

# Proves the interpreter works before it is copied somewhere with no shell to
# diagnose it in. ssl and hashlib are the two that fail when a standalone build
# is missing its bundled libraries, and they fail at import of `msal`.
RUN /app/.venv/bin/python -c "import ssl, hashlib; print(ssl.OPENSSL_VERSION)" \
 && /app/.venv/bin/dsar --version

# Remove the package installer. A python-build-standalone interpreter ships
# pip, so the property the previous image had — no installer in the runtime —
# was silently lost in the move to distroless, and the check that was supposed
# to catch it looked only inside the venv, where pip never was. Trivy found
# three findings against `pip 26.0` under /opt/python and that is what said so.
#
# Two reasons it goes, unchanged from before: nothing installs anything at
# runtime, and an exploited process that cannot fetch and install code is a
# materially smaller problem.
RUN find /opt/python -maxdepth 5 \( -name 'pip' -o -name 'pip-*.dist-info' \
        -o -name 'pip3' -o -name 'pip3.*' -o -name 'ensurepip' \) \
        -exec rm -rf {} + \
 && ! /app/.venv/bin/python -c "import pip" 2>/dev/null

# There is no shell in the runtime stage, so there is no `RUN mkdir` and no
# `RUN chown`. Every directory and every ownership has to be prepared here and
# copied. A small thing on its own, and a fair sample of the migration.
RUN mkdir -p /seed/var/lib/dsar/audit \
 && chown -R 10001:10001 /seed/var/lib/dsar /app

# ---------------------------------------------------------------- runtime
#
# `:latest` rather than `:nonroot`, so the uid stays 10001. The nonroot variant
# is 65532, and the launchers, the Bicep and three tests all assert 10001 —
# changing the uid to satisfy the base image would mean changing five things
# that are correct for a reason that is cosmetic.
FROM gcr.io/distroless/cc-debian12:latest@sha256:6e1871c34683dc9ee996d13084497783fd98ac0200213d0826625f4e9d4be1d0

COPY --from=builder /opt/python /opt/python
COPY --from=builder /app /app
COPY --from=builder /seed/var /var

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DSAR_IN_CONTAINER=1 \
    DSAR_AUDIT_DIR=/var/lib/dsar/audit

USER 10001:10001
WORKDIR /app

EXPOSE 8765

VOLUME ["/var/lib/dsar/audit"]

# Exec form, so it needs no shell — which is just as well, because there is
# none. The absolute path rather than `python`, for the same reason.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/.venv/bin/python", "-c", "import urllib.request,os,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('DSAR_PORT','8765')+'/healthz',timeout=2).status==200 else 1)"]

ENTRYPOINT ["/app/.venv/bin/dsar"]
CMD ["up"]
