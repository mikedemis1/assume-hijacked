# Session teardown removes lab, then net, using separately reviewed saved destroy plans.
& python -m secops.activation teardown @args
exit $LASTEXITCODE
