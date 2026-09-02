"""Repository-contract tests for reference YAML assets.

Every ``ida_preprocessor_scripts/references/**/*.yaml`` file is an input to the
IDA preprocess pipeline and must carry at least ``func_name``, a resolvable
``func_va``, and a non-empty ``disasm_code``. These tests fail with the exact
file path and the specific anomaly so a stray stub (e.g. a file containing only
``func_name``) is caught at PR time instead of during analysis.
"""

import unittest
from pathlib import Path

import generate_reference_yaml
from trusted_yaml import load_yaml_file


def _normalize_address_text(value) -> str | None:
    return generate_reference_yaml._normalize_address_text(value)


def _normalize_non_empty_text(value) -> str | None:
    return generate_reference_yaml._normalize_non_empty_text(value)


def _payload_problems(path: Path) -> list[str]:
    """Return a human-readable list of contract violations for one YAML file."""
    try:
        payload = load_yaml_file(path, cache=True, copy_result=False)
    except Exception as exc:  # noqa: BLE001 - surface any parse failure as a contract violation
        return [f"YAML load error: {exc!r}"]

    if not isinstance(payload, dict):
        return [f"top-level YAML is not a mapping: {type(payload).__name__}"]

    problems: list[str] = []
    func_name = _normalize_non_empty_text(payload.get("func_name"))
    func_va = _normalize_address_text(payload.get("func_va"))
    disasm_code = _normalize_non_empty_text(payload.get("disasm_code"))

    if func_name is None:
        problems.append("func_name is missing or empty")
    if func_va is None:
        problems.append(f"func_va is missing or invalid: {payload.get('func_va')!r}")
    if disasm_code is None:
        problems.append("disasm_code is missing or empty/whitespace")
    return problems


class TestRepositoryReferenceYamlContract(unittest.TestCase):
    def test_reference_yamls_have_required_properties(self) -> None:
        references_root = Path("ida_preprocessor_scripts/references")
        files = sorted(references_root.glob("**/*.yaml"))
        self.assertGreater(len(files), 0, f"no reference YAML files found under {references_root}")

        for path in files:
            with self.subTest(reference=path.as_posix()):
                problems = _payload_problems(path)
                self.assertEqual(
                    [],
                    problems,
                    f"{path.as_posix()} reference YAML anomaly: " + "; ".join(problems),
                )


if __name__ == "__main__":
    unittest.main()
