# Requires --approved-plan SHA256 and --confirm for each saved-plan apply.
& python -m secops.activation install @args
exit $LASTEXITCODE
