"""Contract: every hosted setup-uv install must pin the pyproject required-version.

The repository pins uv through ``[tool.uv] required-version`` in pyproject.toml, but
that value only constrains a uv that was already installed. Hosted jobs that install
uv through ``astral-sh/setup-uv`` without an explicit version fall back to ``latest``
whenever the workspace has no readable pyproject.toml, which is how
``Required uv version ... does not match the running version`` broke the download bump.
"""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

from tests.workflow_contract_test_support import load_workflow

WORKFLOW_DIRECTORY = Path(".github/workflows")
SETUP_UV_ACTION = "astral-sh/setup-uv"
UV_VERSION_EXPRESSION = "${{ env.UV_VERSION }}"


def required_uv_version() -> str:
    document = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    return document["tool"]["uv"]["required-version"]


def setup_uv_steps(workflow: dict) -> list[dict]:
    steps = []
    for job in (workflow.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            if str(step.get("uses", "")).startswith(SETUP_UV_ACTION):
                steps.append(step)
    return steps


class UvVersionPinTests(unittest.TestCase):
    def test_hosted_install_steps_use_shared_version_variable(self):
        for path in sorted(WORKFLOW_DIRECTORY.glob("*.yml")):
            workflow = load_workflow(path.name)
            for step in setup_uv_steps(workflow):
                with self.subTest(workflow=path.name, step=step.get("name") or step.get("uses")):
                    version = (step.get("with") or {}).get("version")
                    self.assertEqual(
                        UV_VERSION_EXPRESSION,
                        version,
                        f"{path.name} must install uv through {UV_VERSION_EXPRESSION}, not {version!r}",
                    )

    def test_shared_version_variable_matches_pyproject_required_version(self):
        expected = required_uv_version()
        pinned = 0
        for path in sorted(WORKFLOW_DIRECTORY.glob("*.yml")):
            workflow = load_workflow(path.name)
            if not setup_uv_steps(workflow):
                continue
            pinned += 1
            with self.subTest(workflow=path.name):
                self.assertEqual(
                    expected,
                    (workflow.get("env") or {}).get("UV_VERSION"),
                    f"{path.name} env.UV_VERSION must match pyproject.toml required-version",
                )
        self.assertGreater(pinned, 0, "no workflow installs uv; the pin contract would be vacuous")


if __name__ == "__main__":
    unittest.main()
