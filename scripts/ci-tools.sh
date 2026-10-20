# Pinned tools for the CI jobs. Sourced, not run: `. scripts/ci-tools.sh`, then
# `install_tools ruff gitleaks terraform helm trivy`.
#
# A job has one image (python:3.12-slim, the one the app ships on) and that image has none of these
# tools. Each is downloaded from its publisher's release page, compared with the sha256 below, and
# unpacked only if the two match. Nothing is run from a file that failed the check.
#
# The hashes are the ones in each publisher's own checksum file (SHA256SUMS, *.sha256sum,
# checksums.txt, *.sha256), taken on 2026-10-20 and equal to the sha256 of the downloaded file.
# Every release was at least 14 days old when pinned. To update a tool: change VERSION, URL and
# SHA256 together, from the publisher's checksum file for the new release.
# terraform and gitleaks are the versions of the images the v1 pipeline ran; terraform 1.15 is
# inside the "~> 1.15.0" that every infra/*/versions.tf asks for. trivy is the version of the image
# the build job pins (TRIVY_IMAGE in .gitlab-ci.yml); its misconfiguration checks are built in.

RUFF_VERSION=0.16.10
RUFF_URL=https://github.com/astral-sh/ruff/releases/download/0.16.10/ruff-x86_64-unknown-linux-gnu.tar.gz
RUFF_SHA256=9567ff1201e2fb3da31ff04c35587d768c66d6cb42dfa84de474e2bfe360b608

GITLEAKS_VERSION=8.30.1
GITLEAKS_URL=https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz
GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb

TERRAFORM_VERSION=1.15.9
TERRAFORM_URL=https://releases.hashicorp.com/terraform/1.15.9/terraform_1.15.9_linux_amd64.zip
TERRAFORM_SHA256=76edd0b22d2f27d3d2e097cd793209646f719cf60f02ff3af626b07361137da1

HELM_VERSION=4.3.0
HELM_URL=https://get.helm.sh/helm-v4.3.0-linux-amd64.tar.gz
HELM_SHA256=86584a54def73570558f66f5111cc53dfed56689637ae32c1201205d494f54fb

TRIVY_VERSION=0.74.0
TRIVY_URL=https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz
TRIVY_SHA256=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a

# download_checked <url> <sha256> <file>: download, then keep the file only if its sha256 matches.
download_checked() {
    curl --fail --silent --show-error --location --retry 3 --output "$3" "$1" || return 1
    actual=$(sha256sum "$3" | cut -d' ' -f1)
    if [ "$actual" != "$2" ]; then
        echo "ci-tools: sha256 of $1 is $actual, expected $2" >&2
        rm -f "$3"
        return 1
    fi
}

# What the pinned downloads need and the slim image lacks: curl, unzip (terraform comes as a zip)
# and git (gitleaks reads the history; some tests ask git which files are ignored).
prepare_tools() {
    missing=""
    for command in curl unzip git; do
        command -v "$command" >/dev/null 2>&1 || missing="$missing $command"
    done
    if [ -n "$missing" ]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq || return 1
        # shellcheck disable=SC2086  # $missing is a list of package names
        apt-get install -y -qq --no-install-recommends ca-certificates $missing >/dev/null || return 1
    fi
    # The checkout belongs to another user than the one the job runs as.
    git config --global --add safe.directory "${CI_PROJECT_DIR:-$PWD}"
}

# install_tools <ruff|gitleaks|terraform|helm|trivy>...: put each tool in /usr/local/bin (or $CI_TOOLS_BIN).
install_tools() {
    prepare_tools || return 1
    bin="${CI_TOOLS_BIN:-/usr/local/bin}"
    work=$(mktemp -d)
    for tool in "$@"; do
        case "$tool" in
            ruff)
                download_checked "$RUFF_URL" "$RUFF_SHA256" "$work/ruff.tar.gz" &&
                    tar -xzf "$work/ruff.tar.gz" -C "$work" --strip-components=1 ruff-x86_64-unknown-linux-gnu/ruff &&
                    install -m 0755 "$work/ruff" "$bin/ruff"
                ;;
            gitleaks)
                download_checked "$GITLEAKS_URL" "$GITLEAKS_SHA256" "$work/gitleaks.tar.gz" &&
                    tar -xzf "$work/gitleaks.tar.gz" -C "$work" gitleaks &&
                    install -m 0755 "$work/gitleaks" "$bin/gitleaks"
                ;;
            terraform)
                download_checked "$TERRAFORM_URL" "$TERRAFORM_SHA256" "$work/terraform.zip" &&
                    unzip -q -o "$work/terraform.zip" terraform -d "$work" &&
                    install -m 0755 "$work/terraform" "$bin/terraform"
                ;;
            helm)
                download_checked "$HELM_URL" "$HELM_SHA256" "$work/helm.tar.gz" &&
                    tar -xzf "$work/helm.tar.gz" -C "$work" --strip-components=1 linux-amd64/helm &&
                    install -m 0755 "$work/helm" "$bin/helm"
                ;;
            trivy)
                download_checked "$TRIVY_URL" "$TRIVY_SHA256" "$work/trivy.tar.gz" &&
                    tar -xzf "$work/trivy.tar.gz" -C "$work" trivy &&
                    install -m 0755 "$work/trivy" "$bin/trivy"
                ;;
            *)
                echo "ci-tools: unknown tool '$tool'" >&2
                false
                ;;
        esac || { rm -rf "$work"; return 1; }
    done
    rm -rf "$work"
}
