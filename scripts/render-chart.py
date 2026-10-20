"""Render the Helm chart for kind and for Azure into <outdir>/chart-<env>.yaml.

Same inputs as the chart tests: values-<env>.yaml plus the install values the tests use
(install_values in tests/k8s/test_chart.py), so the scan sees what a deploy would install.
Used by scripts/trivy-config.sh. Needs the helm binary; the test module needs pytest and PyYAML.

    python scripts/render-chart.py <outdir>
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.k8s.test_chart import CHART, install_values  # noqa: E402


def main(outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    for env in ("kind", "azure"):
        with tempfile.TemporaryDirectory() as tmp:
            install = Path(tmp) / f"install-values-{env}.json"
            install.write_text(json.dumps(install_values(env)), encoding="utf-8")  # JSON is YAML
            done = subprocess.run(
                ["helm", "template", "ah", str(CHART), "-f", str(CHART / f"values-{env}.yaml"),
                 "-f", str(install)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8", check=False)
        if done.returncode != 0:
            sys.exit(f"helm template ({env}) failed:\n{done.stderr}")
        (outdir / f"chart-{env}.yaml").write_text(done.stdout, encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(Path(sys.argv[1]))
