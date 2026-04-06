import unittest
from pathlib import Path
from unittest.mock import call, patch

import ida_analyze_bin


class TestResolveArtifactPath(unittest.TestCase):
    def test_resolve_artifact_path_keeps_current_module_artifacts_local(self) -> None:
        binary_dir = str(Path('/tmp/bin/14141/networksystem'))

        resolved = ida_analyze_bin.resolve_artifact_path(
            binary_dir,
            'CNetChan_vtable.{platform}.yaml',
            'linux',
        )

        self.assertEqual(
            str(Path('/tmp/bin/14141/networksystem/CNetChan_vtable.linux.yaml').resolve()),
            resolved,
        )

    def test_resolve_artifact_path_supports_sibling_module_reference(self) -> None:
        binary_dir = str(Path('/tmp/bin/14141/networksystem'))

        resolved = ida_analyze_bin.resolve_artifact_path(
            binary_dir,
            '../server/CFlattenedSerializers_CreateFieldChangedEventQueue.{platform}.yaml',
            'windows',
        )

        self.assertEqual(
            str(
                Path(
                    '/tmp/bin/14141/server/'
                    'CFlattenedSerializers_CreateFieldChangedEventQueue.windows.yaml'
                ).resolve()
            ),
            resolved,
        )

    def test_resolve_artifact_path_rejects_escape_outside_gamever_root(self) -> None:
        binary_dir = str(Path('/tmp/bin/14141/networksystem'))

        with self.assertRaises(ValueError):
            ida_analyze_bin.resolve_artifact_path(
                binary_dir,
                '../../outside/secret.{platform}.yaml',
                'windows',
            )


class TestResolveArtifactPathIntegration(unittest.TestCase):
    def test_expand_expected_paths_delegates_to_resolver(self) -> None:
        binary_dir = str(Path('/tmp/bin/14141/networksystem'))
        expected_paths = [
            'CNetChan_vtable.{platform}.yaml',
            '../server/CFlattenedSerializers_CreateFieldChangedEventQueue.{platform}.yaml',
        ]

        with patch.object(
            ida_analyze_bin,
            'resolve_artifact_path',
            side_effect=['/tmp/resolved-a.yaml', '/tmp/resolved-b.yaml'],
        ) as mock_resolver:
            resolved = ida_analyze_bin.expand_expected_paths(binary_dir, expected_paths, 'linux')

        self.assertEqual(['/tmp/resolved-a.yaml', '/tmp/resolved-b.yaml'], resolved)
        mock_resolver.assert_has_calls(
            [
                call(binary_dir, expected_paths[0], 'linux'),
                call(binary_dir, expected_paths[1], 'linux'),
            ]
        )

    def test_process_binary_rejects_illegal_expected_input_without_crash(self) -> None:
        binary_path = str(Path('/tmp/bin/14141/networksystem/networksystem.dll'))
        skills = [
            {
                'name': 'skill_illegal_expected_input',
                'expected_output': ['CNetChan_vtable.{platform}.yaml'],
                'expected_input': ['../../outside/secret.{platform}.yaml'],
            }
        ]
        fake_process = object()

        with (
            patch.object(ida_analyze_bin, 'start_idalib_mcp', return_value=fake_process),
            patch.object(ida_analyze_bin, 'ensure_mcp_available', return_value=(fake_process, True)),
            patch.object(ida_analyze_bin, 'quit_ida_gracefully') as mock_quit_ida,
            patch.object(ida_analyze_bin, 'run_skill') as mock_run_skill,
        ):
            success, fail, skip = ida_analyze_bin.process_binary(
                binary_path=binary_path,
                skills=skills,
                agent='codex',
                host='127.0.0.1',
                port=13337,
                ida_args='',
                platform='windows',
                debug=False,
                max_retries=1,
            )

        self.assertEqual((0, 1, 0), (success, fail, skip))
        mock_run_skill.assert_not_called()
        mock_quit_ida.assert_called_once_with(fake_process, '127.0.0.1', 13337, debug=False)

    def test_process_binary_preserves_prefilter_failures_when_mcp_startup_fails(self) -> None:
        binary_path = str(Path('/tmp/bin/14141/networksystem/networksystem.dll'))
        skills = [
            {
                'name': 'a_illegal_output',
                'expected_output': ['../../outside/secret.{platform}.yaml'],
                'expected_input': [],
            },
            {
                'name': 'b_valid_output',
                'expected_output': ['CNetChan_vtable.{platform}.yaml'],
                'expected_input': [],
            },
        ]

        with patch.object(ida_analyze_bin, 'start_idalib_mcp', return_value=None):
            success, fail, skip = ida_analyze_bin.process_binary(
                binary_path=binary_path,
                skills=skills,
                agent='codex',
                host='127.0.0.1',
                port=13337,
                ida_args='',
                platform='windows',
                debug=False,
                max_retries=1,
            )

        self.assertEqual((0, 2, 0), (success, fail, skip))


if __name__ == '__main__':
    unittest.main()
