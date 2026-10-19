# Read-only Azure checks and local input preparation. No resource is created.
& python -m secops.activation preflight @args
exit $LASTEXITCODE
