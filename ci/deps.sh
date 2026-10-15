#!/bin/sh
# Known vulnerabilities in every locked package, with pip-audit.
# https://github.com/pypa/pip-audit
#   --require-hashes --disable-pip: audit the lock as written (every package pinned and hashed),
#   without resolving or installing anything. --strict: a package that cannot be checked fails
#   the job instead of being skipped.
# requirements.lock is what ships in the image; requirements-dev.lock adds the tools the
# pipeline itself runs, which see the code and the CI variables.
# On a network that intercepts HTTPS, point REQUESTS_CA_BUNDLE at the CA bundle first.
. ci/lib.sh

if in_ci; then
    install_python_tools
fi
for lock in requirements.lock requirements-dev.lock; do
    echo "== $lock"
    "$(python_bin)" -m pip_audit --require-hashes --disable-pip --strict \
        --progress-spinner off -r "$lock"
done
