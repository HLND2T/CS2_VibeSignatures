"""Execute the bootstrap publisher head-verification step against a simulated GitHub API."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.workflow_contract_test_support import load_workflow

POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")

EXPECTED_SHA = "a" * 40
OBSERVED_SHA = "b" * 40
BUMP_REF = "bump-download/14184"
REPOSITORY = "owner/repo"

HARNESS = r"""
$global:pollCalls = 0
$global:sleptMs = @()
$global:nowMs = 0
$responses = @($env:STUB_RESPONSES | ConvertFrom-Json)
function Get-Date {
    [datetime]::new(2026, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc).AddMilliseconds($global:nowMs)
}
function Start-Sleep {
    param([int]$Milliseconds)
    $global:sleptMs += $Milliseconds
    $global:nowMs += $Milliseconds
}
function gh {
    $global:pollCalls += 1
    $response = $responses[[Math]::Min($global:pollCalls, $responses.Count) - 1]
    if ($response.exit -ne 0) {
        [Console]::Error.WriteLine("gh: HTTP 503")
        $global:LASTEXITCODE = $response.exit
        return
    }
    [pscustomobject]@{
        state = $response.state
        head = [pscustomobject]@{
            sha = $response.sha
            ref = $response.ref
            repo = [pscustomobject]@{ full_name = $response.repo }
        }
    } | ConvertTo-Json -Depth 5 -Compress
    $global:LASTEXITCODE = 0
}
$ok = $false
$message = ""
try {
"""

EPILOGUE = r"""
    $ok = $true
} catch {
    $message = $_.Exception.Message
}
[pscustomobject]@{
    ok = $ok
    calls = $global:pollCalls
    slept = $global:sleptMs
    now = $global:nowMs
    error = $message
} | ConvertTo-Json -Compress
"""


def verify_step():
    steps = load_workflow("bootstrap-new-gamever-artifacts.yml")["jobs"]["publish-new-gamever-artifacts"]["steps"]
    return next(step for step in steps if step["name"] == "Verify published bootstrap PR head")


class BootstrapPublishedHeadTests(unittest.TestCase):
    @unittest.skipUnless(POWERSHELL, "PowerShell required")
    def test_published_head_convergence(self):
        script = verify_step()["run"]
        synced = {"state": "open", "ref": BUMP_REF, "repo": REPOSITORY, "exit": 0}
        scenarios = {
            "immediate": [{**synced, "sha": EXPECTED_SHA}],
            "delayed": [
                {**synced, "sha": OBSERVED_SHA},
                {**synced, "sha": OBSERVED_SHA},
                {**synced, "sha": EXPECTED_SHA},
            ],
            "timeout": [{**synced, "sha": OBSERVED_SHA}],
            "api-error": [{"exit": 1}],
            "closed": [{**synced, "state": "closed", "sha": OBSERVED_SHA}],
            "wrong-ref": [{**synced, "ref": "other", "sha": OBSERVED_SHA}],
            "wrong-repo": [{**synced, "repo": "other/repo", "sha": OBSERVED_SHA}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(
                os.environ,
                EXPECTED_HEAD_SHA=EXPECTED_SHA,
                EXPECTED_HEAD_REF=BUMP_REF,
                REPOSITORY=REPOSITORY,
                PR_NUMBER="941",
                GH_TOKEN="stub",
            )
            for scenario, responses in scenarios.items():
                with self.subTest(scenario=scenario):
                    source = Path(tmp) / "verify.ps1"
                    source.write_text(HARNESS + script + EPILOGUE, encoding="utf-8")
                    result = subprocess.run(
                        [POWERSHELL, "-NoProfile", "-File", str(source)],
                        env=dict(env, STUB_RESPONSES=json.dumps(responses)),
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    self.assertEqual(0, result.returncode, result.stderr)
                    observed = json.loads(result.stdout)
                    if scenario == "immediate":
                        self.assertTrue(observed["ok"], observed)
                        self.assertEqual(1, observed["calls"])
                        self.assertEqual([], observed["slept"])
                    elif scenario == "delayed":
                        self.assertTrue(observed["ok"], observed)
                        self.assertEqual(3, observed["calls"])
                        self.assertEqual([2000, 2000], observed["slept"])
                        self.assertEqual(4000, observed["now"])
                    elif scenario == "timeout":
                        self.assertFalse(observed["ok"], observed)
                        self.assertEqual(60000, observed["now"])
                        self.assertIn(EXPECTED_SHA, observed["error"])
                        self.assertIn(OBSERVED_SHA, observed["error"])
                    elif scenario == "api-error":
                        self.assertFalse(observed["ok"], observed)
                        self.assertEqual(1, observed["calls"])
                        self.assertEqual("Published artifact pull request could not be read back.", observed["error"])
                    else:
                        self.assertFalse(observed["ok"], observed)
                        self.assertEqual(1, observed["calls"])
                        self.assertEqual(
                            "Published artifact pull request identity or state changed.", observed["error"]
                        )


if __name__ == "__main__":
    unittest.main()
