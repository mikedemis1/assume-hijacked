# Reads Terraform state or checks application rollouts. No model inference request.
& python -m secops.activation verify @args
exit $LASTEXITCODE
