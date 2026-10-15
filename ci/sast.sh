#!/bin/sh
# Static analysis of the application code with bandit.
# https://bandit.readthedocs.io/en/latest/config.html (settings in pyproject.toml [tool.bandit])
# https://bandit.readthedocs.io/en/latest/man/bandit.html (severity and confidence filters)
# Fails on any finding of medium or high severity that bandit is at least medium sure about.
# A finding that is accepted carries `# nosec <id>` and the reason on the same line.
. ci/lib.sh

if in_ci; then
    install_python_tools
fi
"$(python_bin)" -m bandit -c pyproject.toml -r app \
    --severity-level medium --confidence-level medium
