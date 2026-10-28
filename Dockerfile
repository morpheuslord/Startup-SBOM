# syntax=docker/dockerfile:1
#
# Startup-SBOM container image.
#
#   docker run --rm --network none \
#     -v /path/to/rootfs:/target:ro -v "$PWD/out:/out" --user "$(id -u):$(id -g)" \
#     ghcr.io/morpheuslord/startup-sbom scan dir:/target --offline -f cyclonedx -o /out
#
# Scanning an exported image / docker save archive:
#
#   docker run --rm -v "$PWD:/in:ro" -v "$PWD/out:/out" --user "$(id -u):$(id -g)" \
#     ghcr.io/morpheuslord/startup-sbom scan docker-archive:/in/image.tar -o /out
#
# The image runs as an unprivileged user (uid 65532). If the mounted rootfs
# contains root-only files (e.g. /var/lib/rpm, /etc/sudoers.d), add `--user 0`;
# the scanner never executes, mounts or writes anything inside the target, and
# the target should still be mounted read-only. The Docker socket is NOT needed
# for dir:/tar:/docker-archive:/oci-* targets; do not mount it unless you
# deliberately want docker:NAME acquisition.
#
# Persist the vulnerability cache across runs with `-v startup-sbom-cache:/cache`.

# ---------------------------------------------------------------------------
# Builder: resolve the locked dependency set into a self-contained venv.
# Both stages are pinned by digest; Dependabot (docker ecosystem) bumps them.
# ---------------------------------------------------------------------------
FROM ghcr.io/astral-sh/uv:0.13.5-python3.14-trixie-slim@sha256:d8e732839dfc4225a1ff698803b478b2223c05636c055d3add41ab9dbec0f315 AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_DEV=1 \
    UV_PYTHON_DOWNLOADS=0 \
    UV_PYTHON=/usr/local/bin/python3.14 \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /src

# Dependencies first (cached layer; only invalidated by lockfile changes).
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-editable

# Then the project itself, installed as a regular (non-editable) wheel.
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-editable \
 && /app/.venv/bin/startup-sbom version

# ---------------------------------------------------------------------------
# Runtime: same Python as the builder (identical interpreter path), no uv,
# no compilers, no package-manager caches, non-root by default.
# ---------------------------------------------------------------------------
FROM python:3.14-slim-trixie@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170 AS runtime

LABEL org.opencontainers.image.title="startup-sbom" \
      org.opencontainers.image.description="Root-confined static analysis of Linux root filesystems and container images" \
      org.opencontainers.image.source="https://github.com/morpheuslord/Startup-SBOM" \
      org.opencontainers.image.url="https://github.com/morpheuslord/Startup-SBOM" \
      org.opencontainers.image.documentation="https://github.com/morpheuslord/Startup-SBOM#readme" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="morpheuslord"

RUN groupadd --system --gid 65532 nonroot \
 && useradd --system --gid 65532 --uid 65532 --home-dir /home/nonroot --create-home \
      --shell /usr/sbin/nologin nonroot \
 && install -d -m 1777 /cache /work

COPY --from=builder --chown=root:root /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    STARTUP_SBOM_CACHE_DIR=/cache \
    HOME=/home/nonroot

USER 65532:65532
WORKDIR /work

# A one-shot CLI with no long-running service: there is nothing to probe.
HEALTHCHECK NONE

ENTRYPOINT ["startup-sbom"]
CMD ["--help"]
