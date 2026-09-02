import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.errors import SnapshotConfigError
from tests.gamesymbol_snapshot_test_support import module, skill, write_config


class TestSnapshotContract(unittest.TestCase):
    def test_collects_platform_outputs_optional_cross_module_and_owners(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config.yaml"
            modules = [
                module(
                    "engine",
                    [
                        skill(
                            "find-common",
                            ["Common.{platform}.yaml", "notes.txt", "../server/Cross.{platform}.yaml"],
                            expected_output_windows=["WinOnly.{platform}.yaml"],
                            optional_output=["Maybe.{platform}.yaml"],
                        ),
                        skill("find-linux", ["LinuxOnly.{platform}.yaml"], platform="linux"),
                    ],
                ),
                module("engine", [skill("find-common-again", ["Common.{platform}.yaml"])]),
            ]
            write_config(config, modules)

            contract = load_contract(config, "14168", root / "bin")

        self.assertEqual(
            {
                "engine/Common.windows.yaml",
                "engine/Common.linux.yaml",
                "engine/WinOnly.windows.yaml",
                "engine/LinuxOnly.linux.yaml",
                "server/Cross.windows.yaml",
                "server/Cross.linux.yaml",
            },
            contract.required_paths,
        )
        self.assertEqual(
            {"engine/Maybe.windows.yaml", "engine/Maybe.linux.yaml"},
            contract.optional_paths,
        )
        self.assertEqual(2, len(contract.owners_by_path["engine/Common.windows.yaml"]))

    def test_explicit_producer_group_preserves_config_order_and_fingerprint(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first = root / "first.yaml"
            second = root / "second.yaml"
            alternatives = [
                skill("find-noinline", ["Shared.{platform}.yaml"], alternative_output=["Shared.{platform}.yaml"]),
                skill("find-inlined", ["Shared.{platform}.yaml"], alternative_output=["Shared.{platform}.yaml"]),
            ]
            write_config(first, [module("server", alternatives, linux=False)])
            write_config(second, [module("server", list(reversed(alternatives)), linux=False)])

            first_contract = load_contract(
                first,
                "1",
                root / "bin",
                require_explicit_producer_groups=True,
            )
            second_contract = load_contract(
                second,
                "1",
                root / "bin",
                require_explicit_producer_groups=True,
            )

        first_group = first_contract.producer_group_for_path("server/Shared.windows.yaml")
        second_group = second_contract.producer_group_for_path("server/Shared.windows.yaml")
        self.assertEqual(
            ["find-noinline", "find-inlined"],
            [first_contract.nodes[node_id].skill_name for node_id in first_group.alternative_node_ids],
        )
        self.assertNotEqual(first_group.fingerprint, second_group.fingerprint)

    def test_duplicate_producers_require_explicit_group_in_source_owned_mode(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config.yaml"
            write_config(
                config,
                [
                    module(
                        "server",
                        [
                            skill("find-a", ["Shared.{platform}.yaml"]),
                            skill("find-b", ["Shared.{platform}.yaml"]),
                        ],
                        linux=False,
                    )
                ],
            )

            with self.assertRaisesRegex(SnapshotConfigError, "explicit alternative output group"):
                load_contract(
                    config,
                    "1",
                    root / "bin",
                    require_explicit_producer_groups=True,
                )

    def test_partial_or_single_producer_group_markers_are_rejected(self) -> None:
        cases = [
            [
                skill("find-a", ["Shared.{platform}.yaml"], alternative_output=["Shared.{platform}.yaml"]),
                skill("find-b", ["Shared.{platform}.yaml"]),
            ],
            [skill("find-a", ["Shared.{platform}.yaml"], alternative_output=["Shared.{platform}.yaml"])],
        ]
        for skills in cases:
            with self.subTest(skills=skills), TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                config = root / "config.yaml"
                write_config(config, [module("server", skills, linux=False)])
                with self.assertRaises(SnapshotConfigError):
                    load_contract(config, "1", root / "bin")

    def test_formal_inputs_resolve_to_output_groups_and_downstream_closure(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config.yaml"
            write_config(
                config,
                [
                    module(
                        "server",
                        [
                            skill("find-a", ["A.{platform}.yaml"]),
                            skill(
                                "find-b",
                                ["B.{platform}.yaml"],
                                expected_input=["A.{platform}.yaml"],
                            ),
                            skill(
                                "find-c",
                                ["C.{platform}.yaml"],
                                expected_input=["B.{platform}.yaml"],
                            ),
                        ],
                        linux=False,
                    )
                ],
            )

            contract = load_contract(config, "1", root / "bin")

        a_group = contract.producer_group_for_path("server/A.windows.yaml")
        b_group = contract.producer_group_for_path("server/B.windows.yaml")
        c_group = contract.producer_group_for_path("server/C.windows.yaml")
        self.assertEqual((a_group.group_id,), b_group.upstream_group_ids)
        self.assertEqual((b_group.group_id,), c_group.upstream_group_ids)
        self.assertEqual(
            {a_group.group_id, b_group.group_id, c_group.group_id},
            contract.downstream_group_ids({a_group.group_id}),
        )

    def test_optional_input_without_formal_output_is_rejected(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config.yaml"
            write_config(
                config,
                [
                    module(
                        "server",
                        [
                            skill(
                                "find-a",
                                ["A.{platform}.yaml"],
                                optional_input=["Missing.{platform}.yaml"],
                            )
                        ],
                        linux=False,
                    )
                ],
            )

            with self.assertRaisesRegex(SnapshotConfigError, "formal output"):
                load_contract(config, "1", root / "bin")

    def test_module_without_platform_binary_does_not_emit_that_platform(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config.yaml"
            write_config(config, [module("server", [skill("find-a", ["A.{platform}.yaml"])], linux=False)])

            contract = load_contract(config, "1", root / "bin")

        self.assertEqual({"server/A.windows.yaml"}, contract.required_paths)
        self.assertEqual({("server", "windows")}, set(contract.binary_targets))

    def test_contract_separates_binary_and_artifact_roots(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config.yaml"
            write_config(config, [module("server", [skill("find-a", ["A.{platform}.yaml"])])])

            contract = load_contract(
                config,
                "1",
                root / "bin",
                artifactdir=root / "bin_artifacts",
            )

        self.assertEqual(root / "bin/1", contract.binary_game_root)
        self.assertEqual(root / "bin_artifacts/1", contract.artifact_game_root)
        self.assertEqual(contract.artifact_game_root, contract.game_root)

    def test_binary_targets_include_skillless_modules_and_deduplicate_stages(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config.yaml"
            repeated = module("server", [])
            write_config(config, [repeated, repeated])

            contract = load_contract(config, "1", root / "bin")

        self.assertEqual({("server", "windows"), ("server", "linux")}, set(contract.binary_targets))
        self.assertEqual(
            "game/bin/linuxsteamrt64/server.so",
            contract.binary_targets[("server", "linux")].source_path,
        )

    def test_binary_target_rejects_conflicting_stage_paths(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config.yaml"
            first = module("server", [])
            second = module("server", [])
            second["path_windows"] = "game/bin/win64/other.dll"
            write_config(config, [first, second])

            with self.assertRaisesRegex(SnapshotConfigError, "conflicting binary path"):
                load_contract(config, "1", root / "bin")

    def test_digest_ignores_descriptions_but_tracks_analysis_fields(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first = root / "first.yaml"
            second = root / "second.yaml"
            third = root / "third.yaml"
            fourth = root / "fourth.yaml"
            base = module(
                "server",
                [
                    skill("find-optional", ["Optional.{platform}.yaml"]),
                    skill("find-a", ["A.{platform}.yaml"], description="old"),
                ],
            )
            changed_description = module(
                "server",
                [
                    skill("find-optional", ["Optional.{platform}.yaml"]),
                    skill("find-a", ["A.{platform}.yaml"], description="new"),
                ],
            )
            changed_output = module(
                "server",
                [
                    skill("find-optional", ["Optional.{platform}.yaml"]),
                    skill("find-a", ["B.{platform}.yaml"]),
                ],
            )
            changed_optional_input = module(
                "server",
                [
                    skill("find-optional", ["Optional.{platform}.yaml"]),
                    skill("find-a", ["A.{platform}.yaml"], optional_input=["Optional.{platform}.yaml"]),
                ],
            )
            write_config(first, [base])
            write_config(second, [changed_description])
            write_config(third, [changed_output])
            write_config(fourth, [changed_optional_input])

            first_digest = load_contract(first, "1", root / "bin").config_sha256
            second_digest = load_contract(second, "1", root / "bin").config_sha256
            third_digest = load_contract(third, "1", root / "bin").config_sha256
            fourth_digest = load_contract(fourth, "1", root / "bin").config_sha256

        self.assertEqual(first_digest, second_digest)
        self.assertNotEqual(first_digest, third_digest)
        self.assertNotEqual(first_digest, fourth_digest)

    def test_rejects_escape_and_case_insensitive_collision(self) -> None:
        cases = [
            [module("server", [skill("find-a", ["../../outside.yaml"])])],
            [
                module(
                    "server",
                    [
                        skill("find-a", ["Same.windows.yaml"], platform="windows"),
                        skill("find-b", ["same.windows.yaml"], platform="windows"),
                    ],
                    linux=False,
                )
            ],
        ]
        for modules in cases:
            with self.subTest(modules=modules), TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                config = root / "config.yaml"
                write_config(config, modules)
                with self.assertRaises(SnapshotConfigError):
                    load_contract(config, "1", root / "bin")


if __name__ == "__main__":
    unittest.main()
