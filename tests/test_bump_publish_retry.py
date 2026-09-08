"""Execute the publisher scripts against retry inputs and a simulated GitHub API."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.workflow_contract_test_support import load_workflow

POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")


def publisher_step(name):
    steps = load_workflow("bump-download.yml")["jobs"]["publish-bump-branch"]["steps"]
    return next(step for step in steps if step["name"] == name)


class BumpPublisherRetryTests(unittest.TestCase):
    @unittest.skipUnless(POWERSHELL, "PowerShell required")
    def test_producer_attempt_validation(self):
        script = publisher_step("Validate untrusted bump job outputs")["run"]
        for producer, current, artifact_attempt, accepted in [
            ("1", "2", "1", True),
            ("2", "2", "2", True),
            ("3", "2", "3", False),
            ("0", "2", "0", False),
            ("-1", "2", "-1", False),
            ("01", "2", "01", False),
            ("1\n", "2", "1\n", False),
            ("", "2", "", False),
            ("abc", "2", "abc", False),
            ("999999999999999999999999", "2", "999999999999999999999999", False),
            ("1", "2", "2", False),
        ]:
            with (
                self.subTest(producer=producer, artifact_attempt=artifact_attempt),
                tempfile.TemporaryDirectory() as tmp,
            ):
                output = Path(tmp) / "output"
                source = Path(tmp) / "validate.ps1"
                source.write_text(script, encoding="utf-8")
                env = dict(
                    os.environ,
                    GITHUB_RUN_ID="123",
                    GITHUB_RUN_ATTEMPT=current,
                    GITHUB_OUTPUT=str(output),
                    UNTRUSTED_GAMEVER="14180",
                    UNTRUSTED_SOURCE_GAMEVER="14178b",
                    UNTRUSTED_CONFIG_PATH="configs/14180.yaml",
                    UNTRUSTED_ARTIFACT_NAME=f"bump-download-candidate-14180-123-{artifact_attempt}",
                    UNTRUSTED_ARTIFACT_DIGEST="a" * 64,
                    UNTRUSTED_RUN_ATTEMPT=producer,
                )
                result = subprocess.run(
                    [POWERSHELL, "-NoProfile", "-File", str(source)],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                self.assertEqual(accepted, result.returncode == 0, result.stderr)
                if accepted:
                    values = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8-sig").splitlines())
                    self.assertEqual(producer, values["run_attempt"])
                    self.assertEqual(env["UNTRUSTED_ARTIFACT_NAME"], values["artifact_name"])

    @unittest.skipUnless(POWERSHELL, "PowerShell required")
    def test_prepare_receives_producer_attempt(self):
        step = publisher_step("Revalidate candidate and create direct-child bump commit")
        # Resolve the step's output bindings, then capture the real command arguments.
        outputs = {
            "gamever": "14180",
            "source_gamever": "14178b",
            "run_attempt": "1",
            "artifact_name": "bump-download-candidate-14180-123-1",
            "artifact_digest": "sha256:" + "a" * 64,
        }
        env = dict(os.environ, GITHUB_RUN_ATTEMPT="2", GITHUB_RUN_ID="123")
        for key, expression in step["env"].items():
            output_key = expression.removeprefix("${{ steps.validate-inputs.outputs.").removesuffix(" }}")
            env[key] = outputs[output_key]
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "publication").mkdir()
            env.update(GITHUB_WORKSPACE=tmp, GITHUB_OUTPUT=str(Path(tmp) / "output"))
            source = Path(tmp) / "prepare.ps1"
            source.write_text(
                r"""
function git { $global:LASTEXITCODE = 0 }
function uv {
    $args | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $env:GITHUB_WORKSPACE 'arguments.json')
    '{"commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' |
        Set-Content -LiteralPath (Join-Path $env:GITHUB_WORKSPACE 'bump-publication-receipt.json')
    $global:LASTEXITCODE = 0
}
"""
                + step["run"],
                encoding="utf-8",
            )
            subprocess.run(
                [POWERSHELL, "-NoProfile", "-File", str(source)],
                env=env,
                capture_output=True,
                text=True,
                check=True,
                timeout=20,
            )
            arguments = json.loads((Path(tmp) / "arguments.json").read_text(encoding="utf-8-sig"))
            self.assertEqual("1", arguments[arguments.index("--workflow-run-attempt") + 1])
            self.assertEqual(outputs["artifact_name"], arguments[arguments.index("--actions-artifact-name") + 1])

    @unittest.skipUnless(shutil.which("node"), "Node.js required")
    def test_pr_head_convergence(self):
        script = publisher_step("Verify synchronized PR head")["with"]["script"]
        harness = r"""
const script = SCRIPT;
const scenario = process.argv[2];
let now = 0, calls = 0, sleeps = [];
Date.now = () => now;
const wait = (callback, delay) => { sleeps.push(delay); now += delay; callback(); };
const expected = 'a'.repeat(40), old = 'b'.repeat(40);
process.env.TRIGGER_SHA = expected;
process.env.PR_NUMBER = '941';
process.env.BUMP_BRANCH = 'bump-download/14180';
const get = async ({pull_number}) => {
  if (pull_number !== 941) throw new Error('Wrong PR number');
  calls++;
  if (scenario === 'api-error') throw new Error('API denied');
  return {data: {state: scenario === 'closed' ? 'closed' : 'open', html_url: 'https://example.test/941',
    head: {sha: scenario === 'immediate' || (scenario === 'delayed' && calls >= 3) ? expected : old,
           ref: scenario === 'wrong-branch' ? 'other' : process.env.BUMP_BRANCH,
           repo: {full_name: scenario === 'wrong-repo' ? 'other/repo' : 'owner/repo'}}}};
};
const github = {rest: {pulls: {get, list() {}}},
  paginate: async () => [(await get({pull_number: 941})).data]};
const core = {notice() {}, info() {}};
const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
(async () => {
  try {
    await new AsyncFunction('github', 'context', 'core', 'setTimeout', script)(
      github, {repo: {owner: 'owner', repo: 'repo'}}, core, wait);
    console.log(JSON.stringify({ok: true, calls, now, sleeps}));
  } catch (error) {
    console.log(JSON.stringify({ok: false, error: error.message, calls, now, sleeps}));
  }
})();
""".replace("SCRIPT", json.dumps(script))
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "poll.cjs"
            source.write_text(harness, encoding="utf-8")
            for scenario in ("immediate", "delayed", "timeout", "api-error", "closed", "wrong-branch", "wrong-repo"):
                with self.subTest(scenario=scenario):
                    result = subprocess.run(
                        ["node", str(source), scenario], capture_output=True, text=True, check=True, timeout=10
                    )
                    observed = json.loads(result.stdout)
                    self.assertEqual(scenario in ("immediate", "delayed"), observed["ok"], observed)
                    if scenario == "immediate":
                        self.assertEqual(1, observed["calls"])
                        self.assertEqual([], observed["sleeps"])
                    elif scenario == "delayed":
                        self.assertEqual(3, observed["calls"])
                        self.assertEqual(4000, observed["now"])
                    elif scenario == "timeout":
                        self.assertEqual(60000, observed["now"])
                        self.assertIn("a" * 40, observed["error"])
                        self.assertIn("b" * 40, observed["error"])
                    elif scenario == "api-error":
                        self.assertEqual("API denied", observed["error"])
                        self.assertEqual(1, observed["calls"])
                    else:
                        self.assertIn("identity or state changed", observed["error"])
                        self.assertEqual(1, observed["calls"])


if __name__ == "__main__":
    unittest.main()
