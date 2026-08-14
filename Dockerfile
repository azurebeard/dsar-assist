# syntax=docker/dockerfile:1
#
# One image, two modes. An operator runs it on their laptop; the same digest
# runs on Azure Container Apps.
#
# Build multi-arch. linux/arm64 is not optional — Apple Silicon is where the
# predecessor's demo failed:
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     --sbom=true --provenance=true -t <ref> --push .

# Both stages are pinned by digest, not by tag. A tag can be repointed at a
# different image without any change to this repository, so a tag-only pin
# means the build is not reproducible and an altered upstream enters the supply
# chain silently. That matters more than usual here, because reproducibility is
# this project's reason for existing. Dependabot's docker ecosystem updates
# digest pins, so this does not freeze the images (WS10 SEC-M-04).

# ---------------------------------------------------------------- builder
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim@sha256:531f855bda2c73cd6ef67d56b733b357cea384185b3022bd09f05e002cd144ca AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Dependencies resolve from the lockfile alone, so this layer is cached until
# the lockfile changes. `--frozen` fails loudly if the lock is stale rather
# than silently re-resolving — a resolution that differs per build machine is
# the class of failure this project exists to eliminate.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

COPY src/ ./src/
COPY README.md ./

# `--no-editable` genuinely installs the package, so /app/.venv/bin/dsar is a
# real console script. An editable install would leave a .pth shim pointing at
# a source tree the runtime image does not carry, which is exactly how the
# predecessor shipped documentation for a command nobody could run.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

# ---------------------------------------------------------------- runtime
#
# python:3.13-slim rather than distroless, deliberately. The whole diagnostic
# story of this tool is `docker run --entrypoint dsar <image> doctor`, and the
# hosted operational story includes console exec. Distroless has no shell and
# pins the interpreter to the image. With non-root, no build tools and a Trivy
# gate in CI the security delta is small; revisit in hardening.
FROM python:3.13-slim@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a

RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin dsar \
 && mkdir -p /var/lib/dsar/audit \
 && chown 10001:10001 /var/lib/dsar/audit

COPY --from=builder --chown=10001:10001 /app /app

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DSAR_IN_CONTAINER=1 \
    DSAR_AUDIT_DIR=/var/lib/dsar/audit

USER 10001:10001
WORKDIR /app

EXPOSE 8765

# The audit trail dies with the container unless this is a mount. The launcher
# mounts it; Container Apps uses the append-blob sink instead.
VOLUME ["/var/lib/dsar/audit"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request,os,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('DSAR_PORT','8765')+'/healthz',timeout=2).status==200 else 1)"]

# The ENTRYPOINT *is* the console script, so every run of the product exercises
# it. It cannot rot unnoticed.
ENTRYPOINT ["dsar"]
CMD ["up"]
