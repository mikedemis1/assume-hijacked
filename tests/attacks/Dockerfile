# syntax=docker/dockerfile:1
# The attack-suite image: the probe pods of tests/k8s/test_walls.py and the chart's attack-suite
# test pods run `python -m attacks.run` (the folder tests/attacks is copied in as
# the package `attacks`). Standard library only, no app code, so it builds without
# a package index and before the app is deployed.
# Build from the repository root: docker build -f tests/attacks/Dockerfile .  (scripts/kind-attack-image.sh)

# Same base as the app image (Dockerfile), pinned by digest.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY tests/attacks ./attacks
# The app's non-root user (Pod Security "restricted", the chart's securityContext).
USER 10001
# Short-lived probe processes, not a service: nothing to health-check.
ENTRYPOINT ["python", "-m", "attacks.run"]
