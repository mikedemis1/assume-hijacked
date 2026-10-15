# Supply chain

- `requirements.lock` lists all 30 packages the images need, each with its sha256 hashes. The image build runs `pip install --only-binary :all: --require-hashes -r requirements.lock` and then `pip install --no-deps .`, so pip refuses a package whose file does not match a hash, and installs wheels only: no dependency's `setup.py` runs in the build (every locked package had a cp312 manylinux wheel with a locked hash on 2026-10-15). Two builds install the same files.
- Both base images are pinned by digest (`python:3.12-slim@sha256:...` in the `Dockerfile`, `postgres:17-alpine@sha256:...` in `compose.yaml`), with a comment naming the tag and the date the digest was resolved. A tag can move; a digest cannot. Updating is manual: `docker buildx imagetools inspect <tag>`, copy the top `Digest`, rebuild.
- `pyproject.toml` pins the runtime dependencies, `setuptools` (build) and the dev tools (`pytest`, `bandit`, `pip-audit`, `mutmut`, `pip-tools`) with `==`. `tests/test_supply_chain.py` fails if a locked package loses its hash, a dependency is no longer pinned, or an image goes back to a tag.
- A local wheel from `LOCAL_WHEELS_DIR` is installed only if its name and version are in the lock, and with the lock's hashes. A wheel with one changed byte fails the build.

To regenerate the lock after changing a dependency, run `pip-compile` in the same Python version as the image, not on the host:

```powershell
docker run --rm -v "${PWD}:/work" -w /work python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 sh -c "pip install pip-tools==7.6.2 && pip-compile --generate-hashes --strip-extras --output-file=requirements.lock pyproject.toml"
```

Not covered: the build backend (`setuptools==84.0.0`) is pinned but downloaded without a hash check.

`requirements-dev.lock` is the same idea for the tests and the pipeline's tools (pytest, bandit, pip-audit, mutmut, pip-tools): every package hashed, and every runtime package at the same version and hashes as `requirements.lock` (`test_dev_lock_hashes_every_tool_and_ships_the_same_runtime_packages`). Regenerate it after `requirements.lock`, so the runtime packages stay the same:

```powershell
docker run --rm -v "${PWD}:/work" -w /work python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 sh -c "pip install pip-tools==7.6.2 && pip-compile --generate-hashes --strip-extras --allow-unsafe --extra=dev --output-file=requirements-dev.lock pyproject.toml"
```
