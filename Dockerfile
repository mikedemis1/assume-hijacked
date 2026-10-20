# syntax=docker/dockerfile:1
# Optional local wheels: a directory of .whl files. Empty by default, so a plain
# `docker build .` works; scripts/kind-deploy.sh replaces this stage with LOCAL_WHEELS_DIR
# (--build-context wheels=...).
FROM scratch AS wheels

# Base image pinned by digest (multi-arch index). Tag python:3.12-slim, resolved 2026-10-15
# (3.12.15, Debian trixie). To update: `docker buildx imagetools inspect python:3.12-slim`,
# copy the top-level Digest here, and rebuild.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY pyproject.toml requirements.lock ./
COPY scripts/install-deps.sh /usr/local/bin/install-deps.sh
COPY app ./app
# The reviewed capability manifests: the tool gateway reads the arguments and the description
# fingerprint of each tool from them (app/gateway/manifest.py).
COPY permissions ./permissions
# Optional build secret "pip_cert": a CA bundle for networks that intercept TLS
# (antivirus HTTPS scanning, corporate proxy). Empty or absent on a normal machine.
# The wheels are bind-mounted for this step only, so they never end up in the image.
# install-deps.sh installs requirements.lock with --require-hashes (every package must match
# a sha256 in the lock), then the app itself with --no-deps.
RUN --mount=type=secret,id=pip_cert,required=false \
    --mount=type=bind,from=wheels,target=/wheels \
    sh /usr/local/bin/install-deps.sh \
 && useradd --create-home --uid 10001 app
USER 10001
EXPOSE 8000
# No HEALTHCHECK here: this one image runs the tool servers, the gateway, the executor's poll loop
# (no port) and the one-shot agent, and no single check fits all of them.
#checkov:skip=CKV_DOCKER_2: one image, three kinds of process (tool servers, executor loop, one-shot agent); no single image-level check fits
